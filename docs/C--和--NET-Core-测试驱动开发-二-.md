# C# 和 .NET Core 测试驱动开发（二）

> 原文：[`zh.annas-archive.org/md5/32CD200F397A73ED943D220E0FB2E744`](https://zh.annas-archive.org/md5/32CD200F397A73ED943D220E0FB2E744)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：.NET Core 单元测试

**单元测试**是软件开发领域最近几年讨论最多的概念之一。单元测试并不是软件开发中的新概念；它已经存在了相当长的时间，自 Smalltalk 编程语言的早期。基于对质量和健壮软件应用程序的增加倡导，软件开发人员和测试人员已经意识到单元测试在软件产品质量改进方面所能提供的巨大好处。

通过单元测试，开发人员能够快速识别代码中的错误，从而增加开发团队对正在发布的软件产品质量的信心。单元测试主要由程序员和测试人员进行，这项活动涉及将应用程序的要求和功能分解为可以单独测试的单元。

单元测试旨在保持小型并经常运行，特别是在对代码进行更改时，以确保代码库中的工作功能不会出现故障。在进行 TDD 时，必须在编写要测试的代码之前编写单元测试。测试通常用作设计和编写代码的辅助工具，并且有效地是代码设计和规范的文档。

在本章中，我们将解释如何创建基本单元测试，并使用 xUnit 断言证明我们的单元测试结果。本章将涵盖以下主题：

+   良好单元测试的属性

+   .NET Core 和 C#的当前单元测试框架生态系统

+   ASP.NET MVC Core 的单元测试考虑因素

+   使用 xUnit 构建单元测试

+   使用 xUnit 断言证明单元测试结果

+   .NET Core 和 Windows 上可用的测试运行器

# 良好单元测试的属性

单元测试是编写用于测试另一段代码的代码。有时它被称为最低级别的测试，因为它用于测试应用程序的最低级别的代码。单元测试调用要测试的方法或类来验证和断言有关被测试代码的逻辑、功能和行为的假设。

单元测试的主要目的是验证被测试代码单元，以确保代码片段执行其设计用途而不是其他用途。通过单元测试，可以证明代码单元的正确性，只有当单元测试编写得好时才能实现。虽然单元测试将证明正确性并有助于发现代码中的错误，但如果被测试的代码设计和编写不佳，代码质量可能不会得到改善。

当您正确编写单元测试时，您可以在一定程度上确信您的应用程序在发布时会正确运行。通过测试套件获得的测试覆盖率，您可以获得有关代码库中方法、类和其他对象的测试写入频率的指标，并且您将获得有关测试运行频率以及测试通过或失败次数的有意义信息。

通过可用的测试指标，参与软件开发的每个利益相关者都可以获得客观信息，这些信息可用于改进软件开发过程。迭代进行单元测试可以通过测试代码中的错误来增加代码的价值，从而提高代码的可靠性和质量。这是通过对代码进行错误测试来实现的——测试会多次重复运行，这是一个被称为**回归测试**的概念，以便在软件应用程序成熟并且之前工作的组件出现故障时找到可能发生的错误。

# 可读性

单元测试的这一特性不容忽视。与被测试的代码类似，单元测试应该易于阅读和理解。编码标准和原则也适用于测试。应该避免使用魔术数字或常量等反模式，因为它们会使测试混乱并且难以阅读。在下面的测试中，整数`10`是一个魔术数字，因为它直接使用。这影响了测试的可读性和清晰度：

```cs
[Fact]
 public void Test_CheckPasswordLength_ShouldReturnTrue() { 

    string password = "civic";

    bool isValid=false;
    if(password.Length >=10)
        isValid=true;

    Assert.True(isValid);
 }
```

有一个良好的测试结构模式可以采用，它被广泛称为**三 A 模式**或**3A 模式**——`安排`，`行动`和`断言`——它将测试设置与验证分开。您需要确保测试所需的数据被安排好，然后是对被测试方法进行操作的代码行，最后断言被测试方法的结果是否符合预期：

```cs
 [Fact]
 public void Test_CompareTwoStrings_ShouldReturnTrue() { 
    string input = "civic";

    string reversed =  new string(input.Reverse().ToArray());

    Assert.Equal(reversed, input);
 }
```

虽然测试没有严格的命名约定，但您应确保测试的名称代表特定的业务需求。测试名称应包含预期的输入以及预期的输出，`Test_CheckPasswordLength_ShouldReturnTrue`，这是因为除了用于测试特定应用功能之外，单元测试还是源代码的丰富文档来源。

# 单元独立性

单元测试基本上应该是一个单元，它应该被设计和编写成可以独立运行的形式。在这种情况下，被测试的单元，即一个方法，应该已经被编写成微妙地依赖于其他方法。如果可能的话，方法所需的数据应该通过方法参数传递，或者应该在单元内提供，它不应该需要外部请求或设置数据来进行功能。

单元测试不应该依赖于或受到任何其他测试的影响。当单元测试相互依赖时，如果其中一个测试在运行时失败，所有其他依赖测试也会失败。代码所需的所有数据应该由单元测试提供。

与第二章中讨论的*单一职责原则*类似，*开始使用.NET Core*，一个单元应该只有一个职责，任何时候只有一个关注点。单元在任何时候应该只有一个任务，以便作为一个单元进行测试。当您有一个方法实际上执行多个任务时，它只是单元的包装器，应该分解为基本单元以便进行简单的测试：

```cs
[Fact]
 public void Test_DeleteLoan_ShouldReturnNull() {

    loanRepository.ArchiveLoan(12);    
    loanRepository.DeleteLoan(12);    
    var loan=loanRepository.GetById(12); 

    Assert.Null(loan);
 }
```

此片段中测试的问题在于同时发生了很多事情。如果测试失败，没有特定的方法来检查哪个方法调用导致了失败。为了清晰和易于维护，这个测试可以分解成不同的测试。

# 可重复

单元测试应该易于运行，而无需每次运行时都进行修改。实质上，测试应该准备好重复运行而无需修改。在下面的测试中，`Test_DeleteLoan_ShouldReturnNull`测试方法是不可重复的，因为每次运行测试都必须进行修改。为了避免这种情况，最好模拟`loanRepository`对象：

```cs
[Fact]
 public void Test_DeleteLoan_ShouldReturnNull() { 
    loanRepository.DeleteLoan(12);

    var loan=loanRepository.GetLoanById(12); 

    Assert.Null(loan);
 }
```

# 易维护且运行速度快

单元测试应该以一种允许它们快速运行的方式编写。测试应该易于实现，任何开发团队的成员都应该能够运行它。因为软件应用是动态的，不断发展的，所以代码库的测试应该易于维护，因为被测试的底层代码发生变化。为了使测试运行更快，尽量减少依赖关系。

很多时候，大多数程序员在单元测试方面做错了，他们编写具有固有依赖关系的单元测试，这反过来使得测试运行变得更慢。一个快速的经验法则可以给你一个线索，表明你在单元测试中做错了什么，那就是测试运行得非常慢。此外，当你的单元测试调用后端服务器或执行一些繁琐的 I/O 操作时，这表明存在测试问题。

# 易于设置，非琐碎，并具有良好的覆盖率

单元测试应该易于设置，并且与任何直接或外部依赖项解耦。应使用适当的模拟框架对外部依赖项进行模拟。适当的对象设置应在设置方法或测试类构造函数中完成。

避免冗余代码，这可能会使测试变得混乱，并确保测试只包含与被测试方法相关的代码。此外，应该为单元或方法编写测试。例如，为类的 getter 和 setter 编写测试可能被认为太琐碎。

最后，良好的单元测试应该具有良好的代码覆盖率。测试方法中的所有执行路径都应该被覆盖，所有测试都应该有定义的可测试标准。

# .NET Core 和 C#的单元测试框架生态系统

.NET Core 开发平台已经被设计为完全支持测试。这可以归因于采用的架构。这使得在.NET Core 平台上进行 TDD 相对容易且值得。

在.NET 和.NET Core 中有几个可用的单元测试框架。这些框架基本上提供了从您喜欢的 IDE、代码编辑器、专用测试运行器，或者有时通过命令行直接编写和执行单元测试的简单和灵活的方式。

.NET 平台上存在着蓬勃发展的测试框架和套件生态系统。这些框架包含各种适配器，可用于创建单元测试项目以及用于持续集成和部署。

这个框架生态系统已经被.NET Core 平台继承。这使得在.NET Core 上实践 TDD 非常容易。Visual Studio IDE 是开放且广泛的，可以更快、更容易地从 NuGet 安装测试插件和适配器，用于测试项目。

有许多免费和开源的测试框架，用于各种类型的测试。最流行的框架是 MSTest、NUnit 和 xUnit.net。

# .NET Core 测试与 MSTest

Microsoft MSTest 是随 Visual Studio 一起提供的默认测试框架，由微软开发，最初是.NET 框架的一部分，但也包含在.NET Core 中。MSTest 框架用于编写负载、功能、UI 和单元测试。

MSTest 可以作为统一的应用程序平台支持，也可以用于测试各种应用程序——桌面、商店、通用 Windows 平台（UWP）和 ASP.NET Core。MSTest 作为 NuGet 软件包提供。

基于 MSTest 的单元测试项目可以添加到包含要测试的项目的现有解决方案中，按照在 Visual Studio 2017 中向解决方案添加新项目的步骤进行操作：

1.  在解决方案资源管理器中右键单击现有解决方案，选择添加，然后选择新项目。或者，要从头开始创建一个新的测试项目，点击“文件”菜单，选择“新建”，然后选择“项目”。

1.  在显示的对话框中，选择 Visual C#，点击.NET Core 选项。

1.  选择 MSTest 测试项目（.NET Core）并为项目指定一个名称。然后点击确定：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/d5683380-b9e2-453a-a8e8-cfa978ed3e2a.png)

或者，在创建新项目或向现有解决方案添加新项目时，选择“类库（.NET Core）”选项，并从 NuGet 添加对 MSTest 的引用。从 NuGet 安装以下软件包到类库项目中，使用 NuGet 软件包管理器控制台或 GUI 选项。您可以从 NuGet 软件包管理器控制台运行以下命令：

```cs
Install-Package MSTest.TestFramework
Install-Package dotnet-test-mstest
```

无论使用哪种方法创建 MSTest 测试项目，Visual Studio 都会自动创建一个`UnitTest1`或`Class1.cs`文件。您可以重命名类或删除它以创建一个新的测试类，该类将使用 MSTest 的`TestClass`属性进行修饰，表示该类将包含测试方法。

实际的测试方法将使用`TestMethod`属性进行修饰，将它们标记为测试，这将使得 MSTest 测试运行器可以运行这些测试。MSTest 有丰富的`Assert`辅助类集合，可用于验证单元测试的期望结果：

```cs
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LoanApplication.Core.Repository;
namespace MsTest
{
    [TestClass]
    public class LoanRepositoryTest
    {
        private LoanRepository loanRepository;
        public LoanRepositoryTest()
        {
            loanRepository = new LoanRepository();
        }

        [TestMethod]
        public void Test_GetLoanById_ShouldReturnLoan()
        {            
            var loan = loanRepository.GetLoanById(12);
            Assert.IsNotNull(loan);
        }
    }
}
```

您可以从 Visual Studio 2017 的测试资源管理器窗口中运行`Test_GetLoanById_ShouldReturnLoan`测试方法。可以从`测试`菜单中打开此窗口，选择`窗口`，然后选择`测试资源管理器`。右键单击测试并选择运行选定的测试：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/a243401d-f9c6-4f6d-a09f-e70a5cbcfda9.png)

您还可以从控制台运行测试。打开命令提示窗口并将目录更改为包含测试项目的文件夹，或者如果要运行解决方案中的所有测试项目，则更改为解决方案文件夹。运行`dotnet test`命令。项目将被构建，同时可用的测试将被发现和执行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/d43da412-1305-4b9b-a03a-09e0d22ea6cf.png)

# 使用 NUnit 进行.NET Core 测试

**NUnit**是一个最初从 Java 的 JUnit 移植的测试框架，可用于测试.NET 平台上所有编程语言编写的项目。目前是第 3 版，其开源测试框架是在 MIT 许可下发布的。

NUnit 测试框架包括引擎和控制台运行器。此外，它还有用于测试在移动设备上运行的应用程序的测试运行器—**Xamarin Runners**。NUnit 测试适配器和生成器基本上可以使使用 Visual Studio IDE 进行测试变得无缝和相对容易。

使用 NUnit 测试.NET Core 或.NET 标准应用程序需要使用 Visual Studio 测试适配器的 NUnit 3 版本。需要安装 NUnit 测试项目模板，以便能够创建 NUnit 测试项目，通常只需要进行一次。

NUnit 适配器可以通过以下步骤安装到 Visual Studio 2017 中：

1.  单击`工具`菜单，然后选择`扩展和更新`

1.  单击在线选项，并在搜索文本框中键入`nunit`以过滤可用的 NUnit 适配器

1.  选择 NUnit 3 测试适配器并单击下载

这将下载适配器并将其安装为 Visual Studio 2017 的模板，您必须重新启动 Visual Studio 才能生效：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/9c1256ab-f478-4a5d-8a8c-8b11f2352d06.png)

或者，您可以每次要创建测试项目时直接从 NuGet 安装 NUnit 3 测试适配器。

要将 NUnit 测试项目添加到现有解决方案中，请按照以下步骤操作：

1.  在解决方案资源管理器中右键单击解决方案，选择添加，新建项目。

1.  在对话框中，选择 Visual C#，然后选择.NET Core 选项。

1.  选择类库(.NET Core)，然后为项目指定所需的名称。

1.  从 NuGet 向项目添加`NUnit3TestAdapter`和`NUnit.ConsoleRunner`包：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/22d45be3-58b5-45d9-91bc-90fdc32e8332.png)

项目设置完成后，可以编写和运行单元测试。与 MSTest 类似，NUnit 也有用于设置测试方法和测试类的属性。

`TestFixture`属性用于标记一个类作为测试方法的容器。`Test`属性用于修饰测试方法，并使这些方法可以从 NUnit 测试运行器中调用。

NUnit 还有其他用于一些设置和测试目的的属性。`OneTimeSetup`属性用于修饰一个方法，该方法仅在运行所有子测试之前调用一次。类似的属性是`SetUp`，用于修饰在运行每个测试之前调用的方法：

```cs
using LoanApplication.Core.Repository;
using NUnit;
using NUnit.Framework;
namespace MsTest
{
    [TestFixture]
    public class LoanRepositoryTest
    {
        private LoanRepository loanRepository;

        [OneTimeSetUp]
        public void SetupTest()
        {
            loanRepository = new LoanRepository();
        }

        [Test]
        public void Test_GetLoanById_ShouldReturnLoan()
        {            
            var loan = loanRepository.GetLoanById(12);
            Assert.IsNotNull(loan);
        }
    }
}
```

测试可以从“测试资源管理器”窗口运行，类似于在 MSTest 测试项目中运行的方式。此外，可以使用`dotnet test`从命令行运行测试。但是，您必须将**Microsoft.NET.Test.Sdk Version 15.5.0**添加为 NUnit 测试项目的引用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/8082dc4c-2b2e-4fbb-91c8-3194d14ad38e.png)

# xUnit.net

**xUnit.net**是用于测试使用 F＃，VB.NET，C＃和其他符合.NET 的编程语言编写的项目的.NET 平台的开源单元测试框架。xUnit.net 是由 NUnit 的第 2 版的发明者编写的，并根据 Apache 2 许可证获得许可。

xUnit.net 可用于测试传统的.NET 平台应用程序，包括控制台和 ASP.NET 应用程序，UWP 应用程序，移动设备应用程序以及包括 ASP.NET Core 的.NET Core 应用程序。

与 NUnit 或 MSTest 不同，测试类分别使用`TestFixture`和`TestClass`属性进行装饰，xUnit.net 测试类不需要属性装饰。该框架会自动检测测试项目或程序集中所有公共类中的所有测试方法。

此外，在 xUnit.net 中不提供测试设置和拆卸属性，可以使用无参数构造函数来设置测试对象或模拟依赖项。测试类可以实现`IDisposable`接口，并在`Dispose`方法中清理对象或依赖项：

```cs
public class TestClass : IDisposable
{
    public TestClass()
    {
        // do test class dependencies and object setup
    }
    public void Dispose()
    {
        //do cleanup here
    }
}
```

xUnit.net 支持两种主要类型的测试-事实和理论。**事实**是始终为真的测试；它们是没有参数的测试。**理论**是只有在传递特定数据集时才为真的测试；它们本质上是参数化测试。分别使用`[Fact]`和`[Theory]`属性来装饰事实和理论测试：

```cs
[Fact]
public void TestMethod1()
{
    Assert.Equal(8, (4 * 2));
}

[Theory]
[InlineData("name")]
[InlineData("word")]
public void TestMethod2(string value)
{
    Assert.Equal(4, value.Length);
}
```

`[InlineData]`属性用于在`TestMethod2`中装饰理论测试，以向测试方法提供测试数据，以在测试执行期间使用。

# 如何配置 xUnit.net

xUnit.net 的配置有两种类型。xUnit.net 允许配置文件为基于 JSON 或 XML。必须为要测试的每个程序集进行 xUnit.net 配置。用于 xUnit.net 的配置文件取决于被测试应用程序的开发平台，尽管 JSON 配置文件可用于所有平台。

要使用 JSON 配置文件，在 Visual Studio 2017 中创建测试项目后，应向测试项目的根文件夹添加一个新的 JSON 文件，并将其命名为`xunit.runner.json`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/79a25dcb-05de-4af9-8986-68d0114476bd.png)

将文件添加到项目后，必须指示 Visual Studio 将`.json`文件复制到项目的输出文件夹中，以便 xUnit 测试运行程序找到它。为此，应按照以下步骤操作：

1.  从“解决方案资源管理器”中右键单击 JSON 配置文件。从菜单选项中选择“属性”，这将显示一个名为 xunit.runner.json 属性页的对话框。

1.  在“属性”窗口页面上，将“复制到输出目录”选项从“从不”更改为“如果较新则复制”，然后单击“确定”按钮：

**![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/ab8daaf8-0d7b-4cc1-94be-e036ec31aa6c.png)**

这将确保在更改时配置文件始终被复制到输出文件夹。 xUnit 中支持的配置元素放置在配置文件中的顶级 JSON 对象中，如此处所见：

```cs
{
  "appDomain": "ifAvailable",
  "methodDisplay": "classAndMethod",
  "diagnosticMessages": false,
  "internalDiagnosticMessages": false,
  "maxParallelThreads": 8
}
```

使用支持 JSON 的 Visual Studio 版本时，它将根据配置文件名称自动检测模式。此外，在编辑`xunit.runner.json`文件时，Visual Studio IntelliSense 中将提供上下文帮助。此表中解释了各种配置元素及其可接受的值：

| **键** | **值** |
| --- | --- |
| `appDomain` | `appDomain`配置元素是`enum` JSON 模式类型，可以采用三个值来确定是否使用应用程序域——`ifAvailable`、`required`和`denied`。应用程序域仅由桌面运行器使用，并且将被非桌面运行器忽略。默认值应始终为`ifAvailable`，表示如果可用应该使用应用程序域。当设置为`required`时，将需要使用应用程序域，如果设置为`denied`，将不使用应用程序域。 |
| `diagnosticMessages` | `diagnosticMessages`配置元素是`boolean` JSON 模式类型，如果要在测试发现和执行期间启用诊断消息，应将其设置为`true`。 |
| `internalDiagnosticMessages` | `internalDiagnosticMessages`配置元素是`boolean` JSON 模式类型，如果要在测试发现和执行期间启用内部诊断消息，应将其设置为`true`。 |
| `longRunningTestSeconds` | `longRunningTestSeconds`配置元素是`integer` JSON 模式类型。如果要启用长时间运行的测试，应将此值设置为正整数；将值设置为`0`会禁用该配置。您应该启用`diagnosticMessages`以获取长时间运行测试的通知。 |
| `maxParallelThreads` | `maxParallelThreads`配置元素是`integer` JSON 模式类型。将值设置为要在并行化时使用的最大线程数。将值设置为`0`将保持默认行为，即计算机上的逻辑处理器数量。设置为`-1`意味着您不希望限制用于测试并行化的线程数。 |
| `methodDisplay` | `methodDisplay`配置元素是`enum` JSON 模式类型。当设置为`method`时，显示名称将是方法，不包括类名。将值设置为`classAndMethod`，这是默认值，表示将使用默认显示名称，即类名和方法名。 |
| `parallelizeAssembly` | `parallelizeAssembly`配置元素是`boolean` JSON 模式类型。将值设置为`true`将使测试程序集与其他程序集并行化。 |
| `parallelizeTestCollections` | `parallelizeTestCollections`配置元素是`boolean` JSON 模式类型。将值设置为 true 将使测试在程序集中并行运行，这允许不同测试集中的测试并行运行。同一测试集中的测试仍将按顺序运行。将其设置为`false`将禁用测试程序集中的并行化。 |
| `preEnumerateTheories` | `preEnumerateTheories`配置元素是`boolean` JSON 模式类型，如果要预先枚举理论以确保每个理论数据行都有一个单独的测试用例，应将其设置为`true`。当设置为`false`时，将返回每个理论的单个测试用例，而不会提前枚举数据。 |
| `shadowCopy` | `shadowCopy`配置元素是`boolean` JSON 模式类型，如果要在不同应用程序域中运行测试时启用影子复制，应将其设置为`true`。如果测试在没有应用程序域的情况下运行，则将忽略此配置元素。 |

xUnit.net 用于桌面和 PCL 测试项目的另一个配置文件选项是 XML 配置。如果测试项目尚未具有`App.Config`文件，则应将其添加到测试项目中。

在`App.Config`文件的`appSettings`部分下，您可以添加配置元素及其值。在使用 XML 配置文件时，必须在前面表中解释的配置元素后面添加 xUnit。例如，JSON 配置文件中的`appDomain`元素将写为`xunit.appDomain`：

```cs
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="xunit.appDomain" value="ifAvailable"/>
    <add key="xunit.diagnosticMessages" value="false"/>
  </appSettings>
</configuration>
```

# xUnit.net 测试运行器

在 xUnit.net 中，有两个负责运行使用该框架编写的单元测试的角色——xUnit.net 运行器和测试框架。**测试运行器**是一个程序，也可以是搜索程序集中的测试并激活发现的测试的第三方插件。xUnit.net 测试运行器依赖于`xunit.runner.utility`库来发现和执行测试。

测试框架是实现测试发现和执行的代码。测试框架将发现的测试链接到`xunit.core.dll`和`xunit.execution.dll`库。这些库与单元测试一起存在。`xunit.abstractions.dll`是 xUnit.net 的另一个有用的库，其中包含测试运行器和测试框架在通信中使用的抽象。

# 测试并行

**测试并行化**是在 xUnit.net 的 2.0 版本中引入的。这个功能允许开发人员并行运行多个测试。测试并行化是必要的，因为大型代码库通常有数千个测试运行，需要多次运行。

这些代码库有大量的测试，因为需要确保功能代码的工作正常且没有问题。它们还利用了现在可用的超快计算资源来运行并行测试，这要归功于计算机硬件技术的进步。

您可以编写使用并行化的测试，并利用计算机上可用的核心，从而使测试运行更快，或者让 xUnit.net 并行运行多个测试。通常情况下，后者更受欢迎，这可以确保测试以计算机运行它们的速度运行。在 xUnit.net 中，测试并行可以在框架级别进行，其中框架支持在同一程序集中并行运行多个测试，或者在测试运行器中进行并行化，其中运行器可以并行运行多个测试程序集。

测试是使用测试集合并行运行的。每个测试类都是一个测试集合，测试集合内的测试不会相互并行运行。例如，如果运行`LoanCalculatorTest`中的测试，测试运行器将按顺序运行类中的两个测试，因为它们属于同一个测试集合：

```cs
public class LoanCalculatorTest
{
        [Fact]
        public void TestCalculateLoan()
        {
            Assert.Equal(16, (4*4));
        }

        [Fact]
        public void TestCalculateRate()
        {
            Assert.Equal(12, (4*3));
        }
}
```

不同的测试类中的测试可以并行运行，因为它们属于不同的测试集合。让我们修改`LoanCalculatorTest`，将`TestCalculateRate`测试方法放入一个单独的测试类`RateCalculatorTest`中：

```cs
public class LoanCalculatorTest
{
        [Fact]
        public void TestCalculateLoan()
        {
            Assert.Equal(16, (4*4));
        }
}

public class RateCalculatorTest
{
        [Fact]
        public void TestCalculateRate()
        {
            Assert.Equal(12, (4*3));
        }
}
```

如果我们运行测试，运行`TestCalculateLoan`和`TestCalculateRate`的总时间将会减少，因为它们位于不同的测试类中，这将使它们位于不同的测试集合中。此外，从测试资源管理器窗口，您可以观察到用于标记两个测试正在运行的图标：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/2b7a8086-5a87-443e-8d60-bb4c47a776ed.png)

不同的测试类中的测试可以配置为不并行运行。这可以通过使用相同名称的`Collection`属性对类进行装饰来实现。如果将`Collection`属性添加到`LoanCalculatorTest`和`RateCalculatorTest`中：

```cs
[Collection("Do not run in parallel")]
public class LoanCalculatorTest
{
        [Fact]
        public void TestCalculateLoan()
        {
            Assert.Equal(16, (4*4));
        }
}

[Collection("Do not run in parallel")]
public class RateCalculatorTest
{
        [Fact]
        public void TestCalculateRate()
        {
            Assert.Equal(12, (4*3));
        }
}
```

`LoanCalculatorTest`和`RateCalculatorTest`类中的测试不会并行运行，因为这些类基于属性装饰属于同一个测试集合。

# ASP.NET MVC Core 的单元测试考虑

ASP.NET Core MVC 开发范式将 Web 应用程序分解为三个不同的部分——`Model`、`View`和`Controller`，符合 MVC 架构模式的原则。**Model-View-Controller**（MVC）模式有助于创建易于测试和维护的 Web 应用程序，并且具有明确的关注点和边界分离。

MVC 模式提供了清晰的演示逻辑和业务逻辑之间的分离，易于扩展和维护。它最初是为桌面应用程序设计的，但后来在 Web 应用程序中得到了广泛的使用和流行。

ASP.NET Core MVC 项目可以以与测试其他类型的 .NET Core 项目相同的方式进行测试。ASP.NET Core 支持对控制器类、razor 页面、页面模型、业务逻辑和应用程序数据访问层进行单元测试。为了构建健壮的 MVC 应用程序，各种应用程序组件必须在隔离环境中进行测试，并在集成后进行测试。

# 控制器单元测试

ASP.NET Core MVC 控制器类处理用户交互，这转化为浏览器上的请求。控制器获取适当的模型并选择要呈现的视图，以显示用户界面。控制器从视图中读取用户的输入数据、事件和交互，并将其传递给模型。控制器验证来自视图的输入，然后执行修改数据模型状态的业务操作。

`Controller` 类应该轻量级，并包含渲染视图所需的最小逻辑，以便进行简单的测试和维护。控制器应该验证模型的状态并确定有效性，调用执行业务逻辑验证和管理数据持久性的适当代码，然后向用户显示适当的视图。

在对 `Controller` 类进行单元测试时，主要目的是在隔离环境中测试控制器动作方法的行为，这应该在不混淆测试与其他重要的 MVC 构造（如模型绑定、路由、过滤器和其他自定义控制器实用对象）的情况下进行。这些其他构造（如果是自定义编写的）应该以不同的方式进行单元测试，并在集成测试中与控制器一起进行整体测试。

审查 `LoanApplication` 项目的 `HomeController` 类，`Controller` 类包含在 Visual Studio 中创建项目时添加的四个动作方法：

```cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using LoanApplication.Models;

namespace LoanApplication.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }
    }
}
```

`HomeController` 类当前包含具有返回视图的基本逻辑的动作方法。为了对 MVC 项目进行单元测试，应向解决方案添加一个新的 xUnit.net 测试项目，以便将测试与实际项目代码分开。将 `HomeControllerTest` 测试类添加到新创建的测试项目中。

将要编写的测试方法将验证 `HomeController` 类的 `Index` 和 `About` 动作方法返回的 `viewResult` 对象：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using LoanApplication.Controllers;
using Xunit;

namespace LoanApplication.Tests.Unit.Controller
{
    public class HomeControllerTest
    {
        [Fact]
        public void TestIndex()
        {
            var homeController = new HomeController();
            var result = homeController.Index();
            var viewResult = Assert.IsType<ViewResult>(result);
        }

        [Fact]
        public void TestAbout()
        {
            var homeController = new HomeController();
            var result = homeController.About();
            var viewResult = Assert.IsType<ViewResult>(result);
        }
    }
}
```

在前面的控制器测试中编写的测试是基本的和非常简单的。为了进一步演示控制器单元测试，可以更新 `Controller` 类代码以支持依赖注入，这将允许通过对象模拟来测试方法。此外，通过使用 `AddModelError` 来添加错误，可以测试无效的模型状态：

```cs
public class HomeController : Controller
{        
        private ILoanRepository loanRepository;

        public HomeController(ILoanRepository loanRepository)
        {
            this.loanRepository = loanRepository;
        }

        public IActionResult Index()
        {
            var loanTypes=loanRepository.GetLoanTypes();
            ViewData["LoanTypes"]=loanTypes;
            return View();
        }             
 }
```

`ILoanRepository` 通过类构造函数注入到 `HomeController` 中，在测试类中，`ILoanRepository` 将使用 Moq 框架进行模拟。在 `TestIndex` 测试方法中，使用 `LoanType` 列表设置了 `HomeController` 类中 `Index` 方法所需的模拟对象：

```cs
public class HomeControllerTest
{
    private Mock<ILoanRepository> loanRepository;
    private HomeController homeController;

    public HomeControllerTest()
    {
        loanRepository = new Mock<ILoanRepository>();
        loanRepository.Setup(x => x.GetLoanTypes()).Returns(GetLoanTypes());
        homeController = new HomeController(loanRepository.Object);
    }
    [Fact]
    public void TestIndex()
    {
       var result = homeController.Index();
       var viewResult = Assert.IsType<ViewResult>(result);
       var loanTypes = Assert.IsAssignableFrom<IEnumerable<LoanType>>(viewResult.ViewData["LoanTypes"]);
       Assert.Equal(2, loanTypes.Count());
    }

    private List<LoanType> GetLoanTypes()
    {
            var loanTypes = new List<LoanType>();
            loanTypes.Add(new LoanType()
            {
                Id = 1,
                Name = "Car Loan"
            });
            loanTypes.Add(new LoanType()
            {
                Id = 2,
                Name = "House Loan"
            });
            return loanTypes;
    }
 }
```

# razor 页面单元测试

在 ASP.NET MVC 中，视图是用于呈现 Web 应用程序用户界面的组件。视图以适当且易于理解的输出格式（如 HTML、XML、XHTML 或 JSON）呈现模型中包含的信息。视图根据对模型执行的更新向用户生成输出。

**Razor 页面**使得在页面上编写功能相对容易。Razor 页面类似于 Razor 视图，但增加了`@page`指令。`@page`指令必须是页面中的第一个指令，它会自动将文件转换为 MVC 操作，处理请求而无需经过控制器。

在 ASP.NET Core 中，可以测试 Razor 页面，以确保它们在隔离和集成应用程序中正常工作。Razor 页面测试可以涉及测试数据访问层代码、页面组件和页面模型。

以下代码片段显示了一个单元测试，用于验证页面模型是否正确重定向：

```cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;
using Xunit;

public class ViewTest
{
    [Fact]
    public void TestResultView()
    {
        var httpContext = new DefaultHttpContext();
        var modelState = new ModelStateDictionary();
        var actionContext = new ActionContext(httpContext, new RouteData(), new PageActionDescriptor(), modelState);
        var modelMetadataProvider = new EmptyModelMetadataProvider();
        var viewData = new ViewDataDictionary(modelMetadataProvider, modelState);
        var pageContext = new PageContext(actionContext);
        pageContext.ViewData = viewData;
        var pageModel = new ResultModel();
        pageModel.PageContext = pageContext;
        pageModel.Url = new UrlHelper(actionContext);
        var result = pageModel.RedirectToPage();
        Assert.IsType<RedirectToPageResult>(result);
    }
}

public class ResultModel : PageModel
{
    public string Message { get; set; }
}
```

# 使用 xUnit 构建单元测试

与应用程序代码库结构化方式类似，以便易于阅读和有效地维护源代码，单元测试也应该被结构化。这是为了便于维护和使用 Visual Studio IDE 中的测试运行器快速运行测试。

**测试用例**是包含测试方法的测试类。通常，每个被测试类都有一个测试类。开发人员在测试中构建测试的另一种常见做法是为每个被测试的方法创建一个嵌套类，或者为被测试的类创建一个基类测试类，为每个被测试的方法创建一个子类。此外，还有每个功能一个测试类的方法，其中所有共同验证应用程序功能的测试方法都分组在一个测试用例中。

这些测试结构方法促进了 DRY 原则，并在编写测试时实现了代码的可重用性。没有一种方法适用于所有目的，选择特定的方法应该基于应用程序开发周围的情况，并在与团队成员进行有效沟通后进行。

选择每个测试一个类或每个方法一个类的路线取决于个人偏好，有时也取决于团队合作时的惯例或协议，每种方法都有其利弊。当您使用每个测试一个类的方法时，您会在测试类中为被测试的类中的方法编写测试，而不是每个方法一个类的方法，其中您只在类中编写一个与被测试方法相关的测试，尽管有时可能会在类中编写多个测试，只要它们与方法相关即可：

```cs
public class HomeControllerTest
    {
        private Mock<ILoanRepository> loanRepository;
        private HomeController homeController;
        public HomeControllerTest()
        {
            loanRepository = new Mock<ILoanRepository>();
            loanRepository.Setup(x => x.GetLoanTypes()).Returns(GetLoanTypes());
            homeController = new HomeController(loanRepository.Object);
        }

        private List<LoanType> GetLoanTypes()
        {
            var loanTypes = new List<LoanType>();
            loanTypes.Add(new LoanType()
            {
                Id = 1,
                Name = "Car Loan"
            });
            loanTypes.Add(new LoanType()
            {
                Id = 2,
                Name = "House Loan"
            });
            return loanTypes;
        }       
    }
```

将创建两个测试类`IndexMethod`和`AboutMethod`。这两个类都将扩展`HomeControllerTest`类，并将分别拥有一个方法，遵循每个测试类一个方法的单元测试方法：

```cs
 public class IndexMethod :HomeControllerTest
        {
            [Fact]
            public void TestIndex()
            {               
                var result = homeController.Index();
                var viewResult = Assert.IsType<ViewResult>(result);
                var loanTypes = Assert.IsAssignableFrom<IEnumerable<LoanType>>(viewResult.ViewData["LoanTypes"]);
                Assert.Equal(3, loanTypes.Count());
            }            
        }

        public class AboutMethod : HomeControllerTest
        {
            [Fact]
            public void TestAbout()
            {
                var result = homeController.About();
                var viewResult = Assert.IsType<ViewResult>(result);
            }
        }
```

重要的是要注意，给测试用例和测试方法赋予有意义和描述性的名称可以在使它们有意义和易于理解方面起到很大作用。测试方法的名称应包含被测试的方法或功能的名称。可选地，可以在测试方法的名称中进一步描述性地添加预期结果，以`Should`为前缀：

```cs
[Fact]
public void TestAbout_ShouldReturnViewResult()
{
      var result = homeController.About();
      var viewResult = Assert.IsType<ViewResult>(result);
}
```

# xUnit.net 共享测试上下文

测试上下文设置是在测试类构造函数中完成的，因为测试设置在 xUnit 中不适用。对于每个测试，xUnit 会创建测试类的新实例，这意味着类构造函数中的代码将为每个测试运行。

往往，单元测试类希望共享测试上下文，因为创建和清理测试上下文可能很昂贵。xUnit 提供了三种方法来实现这一点：

+   **构造函数和 dispose**：共享设置或清理代码，而无需共享对象实例

+   **类装置**：在单个类中跨测试共享对象实例

+   **集合装置**：在多个测试类之间共享对象实例

当您希望每个测试类中的每个测试都有一个新的测试上下文时，您应该使用构造函数和 dispose。在下面的代码中，上下文对象将为`LoanModuleTest`类中的每个测试方法构造和处理：

```cs
public class LoanModuleTest : IDisposable
{
    public LoanAppContext Context { get; private set; }

    public LoanModuleTest()
    {
        Context = new LoanAppContext();
    }

    public void Dispose()
    {
        Context=null;
    }

    [Fact]
    public void TestSaveLoan_ShouldReturnTrue()
    {
        Loan loan= new Loan{Description = "Car Loan"};
        Context.Loan.Add(loan);
        var isSaved=Context.Save();
        Assert.True(isSaved);
    }
}
```

当您打算创建将在类中的所有测试之间共享的测试上下文，并在所有测试运行完成后进行清理时，可以使用类装置方法。要使用类装置，您必须创建一个具有包含要共享的对象代码的构造函数的装置类。测试类应该实现`IClassFixture<>`，并且您应该将装置类作为测试类的构造函数参数添加：

```cs
public class EFCoreFixture : IDisposable
{
    public LoanAppContext Context { get; private set; }

    public EFCoreFixture()
    {
        Context = new LoanAppContext();
    }

    public void Dispose()
    {
        Context=null;
    }
}

```

以下片段中的`LoanModuleTest`类实现了`IClassFixture`，并将`EFCoreFixture`作为参数传递。`EFCoreFixture`被注入到测试类构造函数中：

```cs
public class LoanModuleTest : IClassFixture<EFCoreFixture>
{
    EFCoreFixture efCoreFixture;

    public LoanModuleTest(EFCoreFixture efCoreFixture)
    {
        this.efCoreFixture = efCoreFixture;
    }

    [Fact]
    public void TestSaveLoan_ShouldReturnTrue()
    {
        // test to persist using EF Core context
    }
}
```

与类装置类似，集合装置用于创建在多个类中共享的测试上下文。测试上下文的创建将一次性完成所有测试类，并且如果实现了清理，则将在测试类中的所有测试运行完成后执行。

使用集合装置：

1.  创建一个与类装置类似的构造函数的装置类。

1.  如果应该进行代码清理，则可以在装置类上实现`IDisposable`，这将放在`Dispose`方法中：

```cs
public class EFCoreFixture : IDisposable
{
    public LoanAppContext Context { get; private set; }

    public EFCoreFixture()
    {
        Context = new LoanAppContext();
    }

    public void Dispose()
    {
        Context=null;
    }
}
```

1.  将创建一个定义类，该类将没有代码，并添加`ICollectionFixture<>`，因为其目的是定义集合定义。使用`[CollectionDefinition]`属性装饰类，并为测试集合指定名称：

```cs
[CollectionDefinition("Context collection")]
public class ContextCollection : ICollectionFixture<EFCoreFixture>
{

}
```

1.  向测试类添加`[Collection]`属性，并使用先前用于集合定义类属性的名称。

1.  如果测试类需要实例化的装置，则添加一个以装置为参数的构造函数：

```cs
[Collection("Context collection")]
public class LoanModuleTest 
{
    EFCoreFixture efCoreFixture;

    public LoanModuleTest(EFCoreFixture efCoreFixture)
    {
        this.efCoreFixture = efCoreFixture;
    }

    [Fact]
    public void TestSaveLoan_ShouldReturnTrue()
    {
        // test to persist using EF Core context
    }
}

[Collection("Context collection")]
public class RateModuleTest 
{
    EFCoreFixture efCoreFixture;

    public RateModuleTest(EFCoreFixture efCoreFixture)
    {
        this.efCoreFixture = efCoreFixture;
    }

    [Fact]
    public void TestUpdateRate_ShouldReturnTrue()
    {
        // test to persist using EF Core context
    }
}
```

# 使用 Visual Studio 2017 企业版进行实时单元测试

Visual Studio 2017 企业版具有实时单元测试功能，可以自动运行受您对代码库所做更改影响的测试。测试在后台运行，并且结果在 Visual Studio 中呈现。这是一个很酷的 IDE 功能，可以为您对项目源代码所做的更改提供即时反馈。

Visual Studio 2017 企业版目前支持 NUnit、MSTest 和 xUnit 的实时单元测试。可以从工具菜单配置实时单元测试——从顶级菜单选择选项，并在选项对话框的左窗格中选择实时单元测试。可以从选项对话框调整可用的实时单元测试配置选项：

**![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/3326490e-3774-439d-a37a-544084bbfe44.png)**

可以通过选择实时单元测试并选择开始来从测试菜单启用实时单元测试：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/7eae808b-dd25-42d2-93e2-13286fdbdbf1.png)

启用实时单元测试后，实时单元测试菜单上的其他可用选项将显示。除了开始，还将有暂停、停止和重置清理。菜单功能在此处描述：

+   暂停：这暂时暂停实时单元测试，保留单元测试数据，但隐藏测试覆盖`visualization.rk`以赶上在暂停时所做的所有编辑，并相应地更新图标

+   停止：停止实时单元测试并删除所有收集的单元测试数据

+   重置清理：通过停止并重新启动来重新启动实时单元测试

+   选项：打开选项对话框以配置实时单元测试

在下面的屏幕截图中，可以在启用实时单元测试时看到覆盖可视化。每行代码都会更新并用绿色、红色和蓝色装饰，以指示该行代码是由通过的测试、失败的测试覆盖还是未被任何测试覆盖的：

**![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/8b8669dc-1d2d-43d3-9227-2662e2819334.png)**

# 使用 xUnit.net 断言证明单元测试结果

xUnit.net 断言验证测试方法的行为。断言验证了预期结果应为真的条件。当断言失败时，当前测试的执行将终止，并抛出异常。以下表格解释了 xUnit.net 中可用的断言：

| **断言** | **描述** |
| --- | --- |
| `相等` | 验证对象是否等于另一个对象 |
| `NotEqual` | 验证对象不等于另一个对象 |
| `相同` | 验证两个对象是否是相同类型的 |
| `NotSame` | 验证两个对象不是相同类型的 |
| `包含` | 是一个重载的断言/方法，验证字符串包含给定的子字符串或集合包含对象 |
| `DoesNotContain` | 是一个重载的断言/方法，验证字符串不包含给定的子字符串或集合不包含对象 |
| `DoesNotThrow` | 验证代码不会抛出异常 |
| `InRange` | 验证值在给定的包容范围内 |
| `IsAssignableFrom` | 验证对象是否是给定类型或派生类型的 |
| `空` | 验证集合为空 |
| `NotEmpty` | 验证集合不为空 |
| `假` | 验证表达式是否为假 |
| `真` | 验证表达式是否为真 |
| `IsType<T>` | 验证对象是否是给定类型的 |
| `IsNotType<T>` | 验证对象不是给定类型的 |
| `空` | 验证对象引用是否为空 |
| `NotNull` | 验证对象引用不为空 |
| `NotInRange` | 验证值不在给定的包容范围内 |
| `Throws<T>` | 验证代码是否抛出精确异常 |

以下代码片段使用了前面表格中描述的一些 xUnit.net 断言方法。`Assertions`单元测试方法展示了在 xUnit.net 中进行单元测试时如何使用断言方法来验证方法的行为：

```cs
        [Fact]
        public void Assertions()
        {
            Assert.Equal(8 , (4*2));
            Assert.NotEqual(6, (4 * 2));

            List<string> list = new List<String> { "Rick", "John" };
            Assert.Contains("John", list);
            Assert.DoesNotContain("Dani", list);

            Assert.Empty(new List<String>());
            Assert.NotEmpty(list);

            Assert.False(false);
            Assert.True(true);

            Assert.NotNull(list);
            Assert.Null(null); 
        }
```

# 在.NET Core 和 Windows 上可用的测试运行器

.NET 平台有一个庞大的测试运行器生态系统，可以与流行的测试平台 NUnit、MSTest 和 xUnit 一起使用。测试框架都有随附的测试运行器，可以促进测试的顺利运行。此外，还有几个开源和商业测试运行器可以与可用的测试平台一起使用，其中之一就是 ReSharper。

# ReSharper

**ReSharper**是 JetBrains 开发的.NET 开发人员的 Visual Studio 扩展。它的测试运行器是.NET 平台上可用的测试运行器中最受欢迎的，ReSharper 生产工具提供了增强程序员生产力的其他功能。它有一个单元测试运行器，可以帮助您基于 xUnit.net、NUnit、MSTest 和其他几个测试框架运行和调试单元测试。

ReShaper 可以检测到.NET 和.NET Core 平台上使用的测试框架编写的测试。ReSharper 在编辑器中添加图标，可以单击以调试或运行测试：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/1a7fe848-c074-4287-b547-2afc8e084063.png)

ReSharper 使用*Unit Test Sessions*窗口运行单元测试。**ReSharper 的单元测试会话**窗口允许您并行运行任意数量的单元测试会话，彼此独立。但是在调试模式下只能运行一个会话。

您可以使用单元测试树来过滤测试，这样可以获得测试的结构。它显示了哪些测试失败、通过或尚未运行。此外，通过双击测试，您可以直接导航到源代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/c1435338-2fa0-4ef3-8cd4-7d648e60e84a.png)

# 摘要

单元测试可以提高代码的质量和应用程序的整体质量。这些测试也可以作为源代码的丰富评论和文档。创建高质量的单元测试是一个应该有意识学习的技能，遵循本章讨论的准则。

在本章中，讨论了良好单元测试的属性。我们还广泛讨论了使用 xUnit.net 框架中可用的测试功能的单元测试程序。解释了 Visual Studio 2017 中的实时单元测试功能，并使用 xUnit.net 的`Fact`属性，使用断言来创建基本的单元测试。

在下一章中，我们将探讨数据驱动的单元测试，这是单元测试的另一个重要方面，它可以方便地使用来自不同来源的数据，比如来自数据库或 CSV 文件，来执行单元测试。这是通过 xUnit.net 的`Theory`属性实现的。


# 第五章：数据驱动单元测试

在上一章中，我们讨论了良好单元测试的属性，以及 xUnit.net 支持的两种测试类型**Fact**和**Theory**。此外，我们还通过 xUnit.net 单元测试框架中可用的丰富测试断言集合创建了单元测试。

为软件项目编写的单元测试应该从开发阶段开始反复运行，在部署期间，维护期间，以及在项目的整个生命周期中都应该有效地运行。通常情况下，这些测试应该在不同的数据输入上运行相同的执行步骤，而测试和被测试的代码都应该在不同的数据输入下表现出一致的行为。

通过使用不同的数据集运行测试可以通过创建或复制具有相似步骤的现有测试来实现。这种方法的问题在于维护，因为必须在各种复制的测试中影响测试逻辑的更改。xUnit.net 通过其数据驱动单元测试功能解决了这一挑战，称为**theories**，它允许在不同的测试数据集上运行测试。

数据驱动单元测试，也可以称为 xUnit.net 中的数据驱动测试自动化，是用`Theory`属性装饰的测试，并将数据作为参数传递给这些测试。传递给数据驱动单元测试的数据可以来自各种来源，可以通过使用`InlineData`属性进行内联。数据也可以来自特定的数据源，例如从平面文件、Web 服务或数据库中获取数据。

在第四章中解释的示例数据驱动单元测试使用了内联方法。还有其他属性可以用于向测试提供数据，如`MemberData`和`ClassData`。

在本章中，我们将通过使用 xUnit.net 框架创建数据驱动单元测试，并涵盖以下主题：

+   数据驱动单元测试的好处

+   用于创建数据驱动测试的 xUnit.net `Theory`属性

+   内联数据驱动单元测试

+   属性数据驱动单元测试

+   整合来自其他来源的数据

# 数据驱动单元测试的好处

**数据驱动单元测试**是一个概念，因为它能够使用不同的数据集执行测试，所以它能够对代码行为提供深入的见解。通过数据驱动单元测试获得的见解可以帮助我们对应用程序开发方法做出明智的决策，并且可以识别出需要改进的潜在领域。可以从数据单元测试的报告和代码覆盖率中制定策略，这些策略可以后来用于重构具有潜在性能问题和应用程序逻辑中的错误的代码。

数据驱动单元测试的一些好处在以下部分进行了解释。

# 测试简洁性

通过数据驱动测试，可以更容易地减少冗余，同时保持全面的测试覆盖。这是因为可以避免测试代码的重复。传统上需要为不同数据集重复测试的测试现在可以用于不同的数据集。当存在具有相似结构但具有不同数据的测试时，这表明可以将这些测试重构为数据驱动测试。

让我们在以下片段中回顾`CarLoanCalculator`类和相应的`LoanCalculatorTest`测试类。与传统的编写测试方法相比，这将为我们提供宝贵的见解，说明为什么数据驱动测试可以简化测试，同时在编写代码时提供简洁性。

`CarLoanCalculator`扩展了`LoanCalculator`类，覆盖了`CalculateLoan`方法，执行与汽车贷款相关的计算，并返回一个`Loan`对象，该对象将使用 xUnit.net 断言进行验证：

```cs
public class CarLoanCalculator : LoanCalculator
{    
    public CarLoanCalculator(RateParser rateParser)
    {
        base.rateParser=rateParser;
    }

    public override Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan();
        loan.LoanType=loanDTO.LoanType;
        loan.InterestRate=rateParser.GetRateByLoanType(loanDTO.LoanType, loanDTO.LocationType, loanDTO.JobType);
        // do other processing
        return loan    
    }   
}
```

为了验证`CarLoanCalculator`类的一致行为，将使用以下测试场景验证`CalculateLoan`方法返回的`Loan`对象，当方法参数`LoanDTO`具有不同的`LoanType`、`LocationType`和`JobType`组合时。`CarLoanCalculatorTest`类中的`Test_CalculateLoan_ShouldReturnLoan`测试方法验证了描述的每个场景：

```cs
public class CarLoanCalculatorTest
{    
    private CarLoanCalculator carLoanCalculator;

    public CarLoanCalculatorTest()
    {
        RateParser rateParser= new RateParser();
        this.carLoanCalculator=new CarLoanCalculator(rateParser);
    }

    [Fact]
    public void Test_CalculateLoan_ShouldReturnLoan()
    {
        // first scenario
        LoanDTO loanDTO1 = new LoanDTO();
        loanDTO1.LoanType=LoanType.CarLoan;
        loanDTO1.LocationType=LocationType.Location1;
        loanDTO1.JobType=JobType.Professional
        Loan loan1=carLoanCalculator.CalculateLoan(loanDTO1);

        Assert.NotNull(loan1);
        Assert.Equal(8,loan1.InterestRate);        

        // second scenario
        LoanDTO loanDTO2 = new LoanDTO();
        loanDTO2.LoanType=LoanType.CarLoan;
        loanDTO2.LocationType=LocationType.Location2;
        loanDTO2.JobType=JobType.Professional;
        Loan loan2=carLoanCalculator.CalculateLoan(loanDTO2);

        Assert.NotNull(loan2);
        Assert.Equal(10,loan2.InterestRate);
    }   
}
```

在上述片段中的`Test_CalculateLoan_ShouldReturnLoan`方法包含了用于测试`CalculateLoan`方法两次的代码行。这个测试明显包含了重复的代码，测试与测试数据紧密耦合。此外，测试代码不够清晰，因为当添加更多的测试场景时，测试方法将不得不通过添加更多的代码行来进行修改，从而使测试变得庞大而笨拙。通过数据驱动测试，可以避免这种情况，并且可以消除测试中的重复代码。

# 包容性测试

当业务人员和质量保证测试人员参与自动化测试过程时，可以改善软件应用程序的质量。他们可以使用数据文件作为数据源，无需太多的技术知识，就可以向数据源中填充执行测试所需的数据。可以使用不同的数据集多次运行测试，以彻底测试代码，以确保其健壮性。

使用数据驱动测试，您可以清晰地分离测试和数据。原本可能会与数据混在一起的测试现在将使用适当的逻辑进行分离。这确保了数据源可以在不更改使用它们的测试的情况下进行修改。

通过数据驱动单元测试，应用程序的整体质量得到改善，因为您可以使用各种数据集获得良好的覆盖率，并具有用于微调和优化正在开发的应用程序以获得改进性能的指标。

# xUnit.net 理论属性用于创建数据驱动测试

在 xUnit.net 中，数据驱动测试被称为理论。它们是使用`Theory`属性装饰的测试。当测试方法使用`Theory`属性装饰时，必须另外使用数据属性装饰，测试运行器将使用该属性确定要在执行测试时使用的数据源：

```cs
[Theory]
public void Test_CalculateRates_ShouldReturnRate()
{
   // test not implemented yet
}
```

当测试标记为数据理论时，从数据源中提供的数据直接映射到测试方法的参数。与使用`Fact`属性装饰的常规测试不同，数据理论的执行次数基于从数据源获取的可用数据行数。

至少需要传递一个数据属性作为测试方法参数，以便 xUnit.net 将测试视为数据驱动并成功执行。要传递给测试的数据属性可以是`InlineData`、`MemberData`和`ClassData`中的任何一个。这些数据属性源自`Xunit.sdk.DataAttribute`。

# 内联数据驱动单元测试

**内联数据驱动测试**是使用*xUnit.net 框架*编写数据驱动测试的最基本或最简单的方式。内联数据驱动测试使用`InlineData`属性编写，该属性用于装饰测试方法，除了`Theory`属性之外：

```cs
[Theory, InlineData("arguments")]
```

当测试方法需要简单的参数并且不接受类实例化作为`InlineData`参数时，可以使用内联数据驱动测试。使用内联数据驱动测试的主要缺点是缺乏灵活性。不能将内联数据与另一个测试重复使用。

当在数据理论中使用`InlineData`属性时，数据行是硬编码的，并内联传递到测试方法中。要用于测试的所需数据可以是任何数据类型，并作为参数传递到`InlineData`属性中：

```cs
public class TheoryTest
{
    [Theory,
    InlineData("name")]
    public void TestCheckWordLength_ShouldReturnBoolean(string word)
    {
        Assert.Equal(4, word.Length);
    }
}
```

内联数据驱动测试可以有多个`InlineData`属性，指定测试方法的参数。多个`InlineData`数据理论的语法在以下代码中指定：

```cs
[Theory, InlineData("argument1"), InlineData("argument2"), InlineData("argumentn")]
```

`TestCheckWordLength_ShouldReturnBoolean`方法可以更改为具有三个内联数据行，并且可以根据需要添加更多数据行到测试中。为了保持测试的清晰，建议每个测试不要超过必要或所需的内联数据：

```cs
public class TheoryTest
{
    [Theory,
    InlineData("name"),
    InlineData("word"),
    InlineData("city")
    ]
    public void TestCheckWordLength_ShouldReturnBoolean(string word)
    {
        Assert.Equal(4, word.Length);
    }
}
```

在编写内联数据驱动单元测试时，必须确保测试方法中的参数数量与传递给`InlineData`属性的数据行中的参数数量匹配；否则，xUnit 测试运行器将抛出`System.InvalidOperationException`。以下代码片段中`TestCheckWordLength_ShouldReturnBoolean`方法中的`InlineData`属性已被修改为接受两个参数：

```cs
public class TheoryTest
{
    [Theory,
    InlineData("word","name")]
    public void TestCheckWordLength_ShouldReturnBoolean(string word)
    {
        Assert.Equal(4, word.Length);
    }
}
```

当您在前面的代码片段中运行数据理论测试时，xUnit 测试运行器会因为传递了两个参数`"word"`和`"name"`给 InlineData 属性，而不是预期的一个参数，导致测试失败并显示`InvalidOperationException`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/23ebb8d6-1117-4d33-ab01-019ba6d8ba69.png)

当运行内联数据驱动测试时，xUnit.net 将根据添加到测试方法的`InlineData`属性或数据行的数量创建测试的数量。在以下代码片段中，xUnit.net 将创建两个测试，一个用于`InlineData`属性的参数`"name"`，另一个用于参数`"city"`：

```cs
 [Theory,
    InlineData("name"),
    InlineData("city")]
    public void TestCheckWordLength_ShouldReturnBoolean(string word)
    {
        Assert.Equal(4, word.Length);
    }
```

如果您在 Visual Studio 中使用测试运行器运行`TestCheckWordLength_ShouldReturnBoolean`测试方法，测试应该成功运行并通过。基于属性创建的两个测试可以通过从`InlineData`属性传递给它们的参数来区分：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/134d525d-7134-4729-85a3-735ad3552326.png)

现在，让我们修改*数据驱动单元测试的好处*部分中的`Test_CalculateLoan_ShouldReturnCorrectRate`测试方法，使用`InlineData`来加载测试数据，而不是直接在测试方法的代码中硬编码测试数据：

```cs
[Theory,InlineData(new LoanDTO{ LoanType =LoanType.CarLoan, JobType =JobType.Professional, LocationType=LocationType.Location1 })]
 public void Test_CalculateLoan_ShouldReturnCorrectRate(LoanDTO loanDTO)
 {
     Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
     Assert.NotNull(loan);
     Assert.Equal(8, loan.InterestRate);
 }
```

在 Visual Studio 中，上述代码片段将导致语法错误，IntelliSense 上下文菜单显示错误——属性参数必须是常量表达式、表达式类型或属性参数类型的数组创建表达式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/cbdb20bd-06a9-498b-be91-9f33f13b6bbc.png)

在`InlineData`属性中使用属性或自定义类型作为参数类型是不允许的，这表明`LoanDTO`类的新实例不能作为`InlineData`属性的参数。这是`InlineData`属性的限制，因为它不能用于从属性、类、方法或自定义类型加载数据。

# 属性数据驱动单元测试

在编写内联数据驱动测试时遇到的灵活性不足可以通过使用属性数据驱动测试来克服。属性数据驱动单元测试是通过使用`MemberData`和`ClassData`属性在 xUnit.net 中编写的。使用这两个属性，可以创建从不同数据源（如文件或数据库）加载数据的数据理论。

# MemberData 属性

当要创建并加载来自以下数据源的数据行的数据理论时，使用`MemberData`属性：

+   静态属性

+   静态字段

+   静态方法

在使用`MemberData`时，数据源必须返回与`IEnumerable<object[]>`兼容的独立对象集。这是因为在执行测试方法之前，`return`属性会被`.ToList()`方法枚举。

`Test_CalculateLoan_ShouldReturnCorrectRate`测试方法在*数据驱动单元测试的好处*部分中，可以重构以使用`MemberData`属性来加载测试的数据。创建一个静态的`IEnumerable`方法`GetLoanDTOs`，使用`yield`语句返回一个`LoanDTO`对象给测试方法：

```cs
public static IEnumerable<object[]> GetLoanDTOs()
{
       yield return new object[]
       {
           new LoanDTO
            {
                LoanType = LoanType.CarLoan,
                JobType = JobType.Professional,
                 LocationType = LocationType.Location1
             }
        };

       yield return new object[]
       {
            new LoanDTO
            {
                LoanType = LoanType.CarLoan,
                JobType = JobType.Professional,
                LocationType = LocationType.Location2
            }
        };
  }
```

`MemberData`属性要求将数据源的名称作为参数传递给它，以便在后续调用中加载测试执行所需的数据行。静态方法、属性或字段的名称可以作为字符串传递到`MemberData`属性中，形式为`MemberData("methodName")`：

```cs
 [Theory, MemberData("GetLoanDTOs")]
 public void Test_CalculateLoan_ShouldReturnCorrectRate(LoanDTO loanDTO)
 {
     Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
     Assert.NotNull(loan);
     Assert.InRange(loan.InterestRate, 8, 12);
 }
```

另外，数据源名称可以通过`nameof`表达式传递给`MemeberData`属性，`nameof`是 C#关键字，用于获取变量、类型或成员的字符串名称。语法是`MemberData(nameof(methodName))`：

```cs
 [Theory, MemberData(nameof(GetLoanDTOs))]
 public void Test_CalculateLoan_ShouldReturnCorrectRate(LoanDTO loanDTO)
 {
     Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
     Assert.NotNull(loan);
     Assert.InRange(loan.InterestRate, 8, 12);
 }
```

与`MemberData`属性一起使用静态方法类似，静态字段和属性可以用于提供数据理论的数据集。

`Test_CalculateLoan_ShouldReturnCorrectRate`可以重构以使用静态属性代替方法：

```cs
[Theory, MemberData("LoanDTOs")]
        public void Test_CalculateLoan_ShouldReturnCorrectRate(LoanDTO loanDTO)
        {
            Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
            Assert.NotNull(loan);
            Assert.InRange(loan.InterestRate, 8, 12);
        }
```

创建一个静态属性`LoanDTOs`，返回`IEnumerable<object[]>`，这是作为`MemberData`属性参数的资格要求。`LoanDTOs`随后用作属性的参数：

```cs
public static IEnumerable<object[]> LoanDTOs
{
            get
            {
                yield return new object[]
                {
                    new LoanDTO
                    {
                        LoanType = LoanType.CarLoan,
                        JobType = JobType.Professional,
                        LocationType = LocationType.Location1
                    }
                };

                yield return new object[]
                {
                    new LoanDTO
                    {
                        LoanType = LoanType.CarLoan,
                        JobType = JobType.Professional,
                        LocationType = LocationType.Location2
                    }
                };
 }
```

每当运行`Test_CalculateLoan_ShouldReturnCorrectRate`时，将创建两个测试，对应于作为数据源返回的两个数据集。

遵循上述方法要求静态方法、字段或属性用于加载测试数据的位置与数据理论相同。为了使测试组织良好，有时需要将测试方法与用于加载数据的静态方法或属性分开放在不同的类中：

```cs
public class DataClass
{
    public static IEnumerable<object[]> LoanDTOs
    {
            get
             {
                    yield return new object[]
                    {
                        new LoanDTO
                        {
                            LoanType = LoanType.CarLoan,
                            JobType = JobType.Professional,
                            LocationType = LocationType.Location1
                        }
                    };

                yield return new object[]
                 {
                        new LoanDTO
                        {
                            LoanType = LoanType.CarLoan,
                            JobType = JobType.Professional,
                            LocationType = LocationType.Location2
                        }
                };
           }
     }
}
```

当测试方法写在与静态方法不同的单独类中时，必须在`MemberData`属性中指定包含方法的类，使用`MemberType`，并分配包含类，使用类名，如下面的代码片段所示：

```cs
[Theory, MemberData(nameof(LoanDTOs), MemberType = typeof(DataClass))]
public void Test_CalculateLoan_ShouldReturnCorrectRate(LoanDTO loanDTO)
{
       Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
       Assert.NotNull(loan);
       Assert.InRange(loan.InterestRate, 8, 12);
}        
```

在使用静态方法时，该方法也可以有一个参数，当处理数据时可能需要使用该参数。例如，可以将整数值传递给方法，以指定要返回的记录数。该参数可以直接从`MemberData`属性传递给静态方法：

```cs
[Theory, MemberData(nameof(GetLoanDTOs),  parameters: 1, MemberType = typeof(DataClass))]
public void Test_CalculateLoan_ShouldReturnCorrectRate3(LoanDTO loanDTO)
{
     Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
     Assert.NotNull(loan);
     Assert.InRange(loan.InterestRate, 8, 12);
}        
```

`DataClass`中的`GetLoanDTOs`方法可以重构为接受一个整数参数，用于限制要返回的记录数，以填充执行`Test_CalculateLoan_ShouldReturnCorrectRate`所需的数据行：

```cs
public class DataClass
{
    public static IEnumerable<object[]> GetLoanDTOs(int records)
    {
        var loanDTOs = new List<object[]>
        {
               new object[]
               {
                   new LoanDTO
                   {
                       LoanType = LoanType.CarLoan,
                       JobType = JobType.Professional,
                         LocationType = LocationType.Location1
                    }
               },
               new object[]
               {
                    new LoanDTO
                    {
                        LoanType = LoanType.CarLoan,
                        JobType = JobType.Professional,
                        LocationType = LocationType.Location2
                     }
                 }
         };
        return loanDTOs.TakeLast(records);
    }
}
```

# ClassData 属性

`ClassData`是另一个属性，可以使用它来通过来自类的数据创建数据驱动测试。`ClassData`属性接受一个可以实例化以获取将用于执行数据理论的数据的类。具有数据的类必须实现`IEnumerable<object[]>`，每个数据项都作为`object`数组返回。还必须实现`GetEnumerator`方法。

让我们创建一个`LoanDTOData`类，用于提供数据以测试`Test_CalculateLoan_ShouldReturnCorrectRate`方法。`LoanDTOData`将返回`LoanDTO`的`IEnumerable`对象：

```cs
public class LoanDTOData : IEnumerable<object[]>
{
     private IEnumerable<object[]> data => new[]
     {
                new object[]
                {
                    new LoanDTO
                    {
                        LoanType = LoanType.CarLoan,
                        JobType = JobType.Professional,
                        LocationType = LocationType.Location1
                    }
                },
                new object[]
                {
                    new LoanDTO
                    {
                        LoanType = LoanType.CarLoan,
                        JobType = JobType.Professional,
                        LocationType = LocationType.Location2
                    }
                }
      };

      IEnumerator IEnumerable.GetEnumerator()
      {
            return GetEnumerator();
      }

      public IEnumerator<object[]> GetEnumerator()
      {
            return data.GetEnumerator();
      }
}

```

实现了`LoanDTOData`类之后，可以使用`ClassData`属性装饰`Test_CalculateLoan_ShouldReturnCorrectRate`，并将`LoanDTOData`作为属性参数传递，以指定`LoanDTOData`将被实例化以返回测试方法执行所需的数据：

```cs
[Theory, ClassData(typeof(LoanDTOData))]
public void Test_CalculateLoan_ShouldReturnCorrectRate(LoanDTO loanDTO)
{
    Loan loan = carLoanCalculator.CalculateLoan(loanDTO);
    Assert.NotNull(loan);
    Assert.InRange(loan.InterestRate, 8, 12);
}
```

使用任何合适的方法，都可以灵活地实现枚举器，无论是使用类属性还是方法。在运行测试之前，xUnit.net 框架将在类上调用`.ToList()`。在使用`ClassData`属性将数据传递给您的测试时，您总是需要创建一个专用类来包含您的数据。

# 整合来自其他来源的数据

虽然您可以使用前面讨论过的 xUnit.net 理论属性编写基本的数据驱动测试，但有时您可能希望做更多的事情，比如连接到 SQL Server 数据库表，以获取用于执行测试的数据。xUnit.net 的早期版本具有来自`xUnit.net.extensions`的其他属性，允许您轻松地从不同来源获取数据，以用于您的测试。`xUnit.net.extensions`包在**xUnit.net v2**中不再可用。

但是，`xUnit.net.extensions`中的类在示例项目中可用：[`github.com/xUnit.net/samples.xUnit.net.`](https://github.com/xUnit.net/samples.xUnit.net)如果您希望使用此属性，可以将示例项目中的代码复制到您的项目中。

# SqlServerData 属性

在项目的`SqlDataExample`文件夹中，有一些文件可以复制到您的项目中，以便为您提供直接连接到 SQL Server 数据库或可以使用*OLEDB*访问的任何数据源的功能。该文件夹中的四个类是`DataAdapterDataAttribute`，`DataAdapterDataAttributeDiscoverer`，`OleDbDataAttribute`和`SqlServerDataAttribute`。

需要注意的是，由于.NET Core 不支持 OLEDB，因此无法在.NET Core 项目中使用前面的扩展。这是因为 OLEDB 技术是基于 COM 的，依赖于仅在 Windows 上可用的组件。但是您可以在常规.NET 项目中使用此扩展。

GitHub 上的 xUnit.net 存储库中提供了`SqlServerData`属性的代码清单，该属性可用于装饰数据理论，以直接从 Microsoft SQL Server 数据库表中获取测试执行所需的数据。

为了测试`SqlServerData`属性，您应该在您的 SQL Server 实例中创建一个名为`TheoryDb`的数据库。创建一个名为`Palindrome`的表；它应该有一个名为`varchar`的列。用样本数据填充表，以便用于测试：

```cs
CREATE TABLE [dbo].Palindrome NOT NULL
) ;

INSERT INTO [dbo].[Palindrome] ([word]) VALUES ('civic')
GO
INSERT INTO [dbo].[Palindrome] ([word]) VALUES ('dad')
GO
INSERT INTO [dbo].[Palindrome] ([word]) VALUES ('omo')
GO
```

`PalindronmeChecker`类运行一个`IsWordPalindrome`方法来验证一个单词是否是回文，如下面的代码片段所示。回文是一个可以在两个方向上阅读的单词，例如`dad`或`civic`。在不使用算法实现的情况下，快速检查这一点的方法是反转单词并使用字符串`SequenceEqual`方法来检查这两个单词是否相等：

```cs
public class PalindromeChecker
{
    public bool IsWordPalindrome(string word)
    {
        return word.SequenceEqual(word.Reverse());
    }
}
```

为了测试`IsWordPalindrome`方法，将实现一个测试方法`Test_IsWordPalindrome_ShouldReturnTrue`，并用`SqlServerData`属性进行装饰。此属性需要三个参数——数据库服务器地址、数据库名称和用于从包含要加载到测试中的数据的表或视图中检索数据的选择语句：

```cs
public class PalindromeCheckerTest
    {
        [Theory, SqlServerData(@".\sqlexpress", "TheoryDb", "select word from Palindrome")]
        public void Test_IsWordPalindrome_ShouldReturnTrue(string word)
        {
            PalindromeChecker palindromeChecker = new PalindromeChecker();
            Assert.True(palindromeChecker.IsWordPalindrome(word));
        }
    }
```

当运行`Test_IsWordPalindrome_ShouldReturnTrue`时，将执行`SqlServerData`属性，以从数据库表中获取记录，用于执行测试方法。要创建的测试数量取决于表中可用的记录。在这种情况下，将创建并执行三个测试：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/f7472981-0328-44c8-8843-367ee078defd.png)

# 自定义属性

与 xUnit.net GitHub 存储库中可用的`SqlServerData`属性类似，您可以创建一个自定义属性来从任何源加载数据。自定义属性类必须实现`DataAttribute`，这是一个表示理论要使用的数据源的抽象类。自定义属性类必须重写并实现`GetData`方法。该方法返回`IEnumerable<object[]>`，用于包装要返回的数据集的内容。

让我们创建一个`CsvData`自定义属性，可以用于从`.csv`文件中加载数据，用于数据驱动的单元测试。该类将具有一个构造函数，它接受两个参数。第一个是包含`.csv`文件的完整路径的字符串参数。第二个参数是一个布尔值，当为`true`时，指定是否应使用包含在`.csv`文件中的数据的第一行作为列标题，当为`false`时，指定忽略文件中的列标题，这意味着 CSV 数据从第一行开始。

自定义属性类是`CsvDataAttribute`，它实现了`DataAttribute`类。该类用`AttributeUsage`属性修饰，该属性具有以下参数—`AttributeTargets`用于指定应用属性的有效应用元素，`AllowMultiple`用于指定是否可以在单个应用元素上指定属性的多个实例，`Inherited`用于指定属性是否可以被派生类或覆盖成员继承：

```cs
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
    public class CsvDataAttribute : DataAttribute
    {
        private readonly string filePath;
        private readonly bool hasHeaders;
        public CsvDataAttribute(string filePath, bool hasHeaders)
        {
            this.filePath = filePath;
            this.hasHeaders = hasHeaders;
        }       
        // To be followed by GetData implementation
    }
```

下一步是实现`GetData`方法，该方法将覆盖`DataAttribute`类中可用的实现。此方法使用`System.IO`命名空间中的`StreamReader`类逐行读取`.csv`文件的内容。实现了第二个实用方法`ConverCsv`，用于将 CSV 数据转换为整数值：

```cs
public override IEnumerable<object[]> GetData(MethodInfo methodInfo)
{
    var methodParameters = methodInfo.GetParameters();
    var parameterTypes = methodParameters.Select(x => x.ParameterType).ToArray();
    using (var streamReader = new StreamReader(filePath))
    {
        if(hasHeaders)
            streamReader.ReadLine();
        string csvLine=string.Empty;
        while ((csvLine = streamReader.ReadLine()) != null)
        {
            var csvRow = csvLine.Split(',');
            yield return ConvertCsv((object[])csvRow, parameterTypes);
        }
    }
}

 private static object[] ConvertCsv(IReadOnlyList<object> csvRow, IReadOnlyList<Type> parameterTypes)
 {
    var convertedObject = new object[parameterTypes.Count];
    //convert object if integer
    for (int i = 0; i < parameterTypes.Count; i++)
      convertedObject[i] = (parameterTypes[i] == typeof(int)) ? Convert.ToInt32(csvRow[i]) : csvRow[i]; 
    return convertedObject;
 }
```

创建的自定义属性现在可以与 xUnit.net 的`Theory`属性一起使用，以从`.csv`文件中提供数据给理论。

`Test_IsWordPalindrome_ShouldReturnTrue`测试方法将被修改以使用新创建的`CsvData`属性，以从`.csv`文件中获取测试执行的数据：

```cs
 public class PalindromeCheckerTest
 {
        [Theory, CsvData(@"C:\data.csv", false)]
        public void Test_IsWordPalindrome_ShouldReturnTrue(string word)
        {
            PalindromeChecker palindromeChecker = new PalindromeChecker();
            Assert.True(palindromeChecker.IsWordPalindrome(word));
        }
 }
```

当您在 Visual Studio 中运行前面片段中的`Test_IsWordPalindrome_ShouldReturnTrue`测试方法时，测试运行器将创建三个测试。这应该对应于从`.csv`文件中检索到的记录或数据行数。测试信息可以从测试资源管理器中查看：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/7bae2c94-06b8-4b72-9505-3493b7cfb2c8.png)

`CsvData`自定义属性可以从任何`.csv`文件中检索数据，无论单行上存在多少列。记录将被提取并传递给测试方法中的`Theory`属性。

让我们创建一个具有两个整数参数`firstNumber`和`secondNumber`的方法。该方法将计算整数值`firstNumber`和`secondNumber`的最大公约数。这两个整数的最大公约数是能够整除这两个整数的最大值：

```cs

public int GetGcd(int firstNumber, int secondNumber)
{
    if (secondNumber == 0)
        return firstNumber;    
    else
        return GetGcd(secondNumber, firstNumber % secondNumber);    
}
```

现在，让我们编写一个测试方法来验证`GetGcd`方法。`Test_GetGcd_ShouldRetunTrue`将是一个数据理论，并具有三个整数参数—`firstNumber`、`secondNumber`和`gcdValue`。该方法将检查在调用时`gdcValue`参数中提供的值是否与调用时`GetGcd`方法返回的值匹配。测试的数据将从`.csv`文件中加载：

```cs
[Theory, CsvData(@"C:\gcd.csv", false)]
public void Test_GetGcd_ShouldRetunTrue(int firstNumber, int secondNumber, int gcd)
{
    int gcdValue=GetGcd(firstNumber,secondNumber);
    Assert.Equal(gcd,gcdValue);
}
```

根据`.csv`文件中提供的值，将创建测试。以下屏幕截图显示了运行时`Test_GetGcdShouldReturnTrue`的结果。创建了三个测试；一个通过，两个失败：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/53b2079c-961e-4f2b-983f-04c88278c973.png)

# 摘要

数据驱动的单元测试是 TDD 的重要概念，它带来了许多好处，可以让您使用来自多个数据源的真实数据广泛测试代码库，为您提供调整和重构代码以获得更好性能和健壮性所需的洞察力。

在本章中，我们介绍了数据驱动测试的好处，以及如何使用 xUnit.net 的内联和属性属性编写有效的数据驱动测试。此外，我们还探讨了在 xUnit.net 中使用的`Theory`属性进行数据驱动的单元测试。这使您能够针对来自不同数据源的广泛输入对代码进行适当的验证和验证。

虽然 xUnit.net 提供的默认数据源属性非常有用，但您可以进一步扩展`DataAttribute`类，并创建一个自定义属性来从另一个源加载数据。我们演示了`CsvData`自定义属性的实现，以从`.csv`文件加载测试数据。

在下一章中，我们将深入探讨另一个重要且有用的 TDD 概念，即依赖项模拟。模拟允许您在不必直接构造或执行依赖项代码的情况下，有效地对方法和类进行单元测试。


# 第六章：模拟依赖

在第五章中，我们讨论了使用 xUnit 框架进行数据驱动的单元测试，这使我们能够创建从不同来源（如平面文件、数据库或内联数据）获取数据的测试。现在，我们将解释模拟依赖的概念，并探讨如何使用 Moq 框架来隔离正在测试的类与其依赖关系，使用 Moq 创建的模拟对象。

在软件项目的代码库中通常存在对象依赖，无论是简单项目还是复杂项目。这是因为各种对象需要相互交互并在边界之间共享信息。然而，为了有效地对对象进行单元测试并隔离它们的行为，每个对象必须在隔离的环境中进行测试，而不考虑它们对其他对象的依赖。

为了实现这一点，类中的依赖对象被替换为模拟对象，以便在测试时能够有效地进行隔离测试，而无需经历构造依赖对象的痛苦，有时这些依赖对象可能并未完全实现，或者在编写被测试对象时构造它们可能是不切实际的。

**模拟对象**用于模拟真实对象以进行代码测试。模拟对象用于替换真实对象；它们是从真实接口或类创建的，并用于验证交互。模拟对象是另一个类中引用的必要实例，用于模拟这些类的行为。由于软件系统的组件需要相互交互和协作，模拟对象用于替换协作者。使用模拟对象时，可以验证使用是否正确且符合预期。模拟对象可以使用模拟框架或库创建，或者通过手工编写模拟对象的代码生成。

本章将详细探讨 Moq 框架，并将用它来创建模拟对象。Moq 是一个功能齐全的模拟框架，可以轻松设置。它可用于创建用于单元测试的模拟对象。Moq 具有模拟框架应具备的几个基本和高级特性，以创建有用的模拟对象，并基本上编写良好的单元测试。

本章将涵盖以下主题：

+   模拟对象的好处

+   模拟框架的缺点

+   手动编写模拟对象与使用模拟框架

+   使用 Moq 框架进行模拟对象

# 模拟对象的好处

在良好架构的软件系统中，通常有相互交互和协调以实现基于业务或自动化需求的设定目标的对象。这些对象往往复杂，并依赖于其他外部组件或系统，如数据库、SOAP 或 REST 服务，用于数据和内部状态更新。

大多数开发人员开始采用 TDD，因为它可以提供许多好处，并且意识到程序员有责任编写质量良好、无错误且经过充分测试的代码。然而，一些开发人员反对模拟对象，因为存在一些假设。例如，向单元测试中添加模拟对象会增加编写单元测试所需的总时间。这种假设是错误的，因为使用模拟对象提供了几个好处，如下节所述。

# 快速运行测试

单元测试的主要特征是它应该运行非常快，并且即使使用相同的数据集多次执行，也应该给出一致的结果。然而，为了有效地运行单元测试并保持具有高效和快速运行的单元测试的属性，重要的是在被测试的代码中存在依赖关系时设置模拟对象。

例如，在以下代码片段中，`LoanRepository`类依赖于 Entity Framework 的`DbContext`类，后者创建与数据库服务器的连接以进行数据库操作。要为`LoanRepository`类中的`GetCarLoans`方法编写单元测试，将需要构造`DbContext`对象。可以对`DbContext`对象进行模拟，以避免每次对该类运行单元测试时打开和关闭数据库连接的昂贵操作：

```cs
public class LoanRepository
{
    private DbContext dbContext;

    public LoanRepository(DbContext dbContext)
    {
        this.dbContext=dbContext;
    }

    public List<CarLoan> GetCarLoans()
    {
        return dbContext.CarLoan;
    }
}
```

在软件系统中，根据需求，将需要访问外部系统，如大型文件、数据库或 Web 连接。在单元测试中直接与这些外部系统交互会增加测试的运行时间。因此，最好对这些外部系统进行模拟，以便测试能够快速运行。当您有长时间运行的测试时，单元测试的好处可能会丧失，因为这显然会浪费生产时间。在这种情况下，开发人员可以停止运行测试，或者完全停止单元测试，并断言单元测试是浪费时间。

# 依赖项隔离

使用依赖项模拟，您在代码中实际上创建了依赖项的替代方案，可以进行实验。当您在适当位置有依赖项的模拟实现时，您可以进行更改并测试更改的效果，因为测试将针对模拟对象而不是真实对象运行。

当您将依赖项隔离时，您可以专注于正在运行的测试，从而将测试的范围限制在对测试真正重要的代码上。实质上，通过减少范围，您可以轻松重构被测试的代码以及测试本身，从而清晰地了解代码可以改进的地方。

为了在以下代码片段中隔离地测试`LoanRepository`类，可以对该类依赖的`DbContext`对象进行模拟。这将限制单元测试的范围仅限于`LoanRepository`类：

```cs
public class LoanRepository
{
    private DbContext dbContext;

    public LoanRepository(DbContext dbContext)
    {
        this.dbContext=dbContext;
    }
}
```

此外，通过隔离依赖项来保持测试范围较小，使得测试易于理解并促进了易于维护。通过不模拟依赖项来增加测试范围，最终会使测试维护变得困难，并减少测试的高级详细覆盖。由于必须对依赖项进行测试，这可能导致由于范围增加而导致测试的细节减少。

# 重构遗留代码

遗留源代码是由您或其他人编写的代码，通常没有测试或使用旧的框架、架构或技术。这样的代码库可能很难重写或维护。它有时可能是难以阅读和理解的混乱代码，因此很难更改。

面对维护遗留代码库的艰巨任务，特别是没有充分或适当测试的代码库，为这样的代码编写单元测试可能很困难，也可能是浪费时间，并且可能需要大量的辛苦工作。然而，使用模拟框架可以极大地简化重构过程，因为正在编写的新代码可以与现有代码隔离，并使用模拟对象进行测试。

# 更广泛的测试覆盖

通过模拟，您可以确保进行广泛的测试覆盖，因为您可以轻松使用模拟对象来模拟可能的异常、执行场景和条件，否则这些情况将很难实现。例如，如果您有一个清除或删除数据库表的方法，使用模拟对象测试这个方法比每次运行单元测试时在实时数据库上运行更安全。

# 模拟框架的缺点

虽然模拟框架在 TDD 期间非常有用，因为它们通过使用模拟对象简化了单元测试，但它们也有一些限制和缺点，可能会影响代码的设计，或者通过过度使用导致包含不相关模拟对象的混乱测试的创建。

# 接口爆炸

大多数嘲弄框架的架构要求必须创建接口来模拟对象。实质上，你不能直接模拟一个类；必须通过类实现的接口来进行。为了在单元测试期间模拟依赖关系，为每个要模拟的对象或依赖关系创建一个接口，即使在生产代码中使用该依赖关系时并不需要该接口。这导致创建了太多的接口，这种情况被称为**接口爆炸**。

# 额外的复杂性

大多数模拟框架使用反射或创建代理来调用方法并创建单元测试中所需的模拟。这个过程很慢，并给单元测试过程增加了额外的开销。特别是当希望使用模拟来模拟所有类和依赖关系之间的交互时，这一点尤其明显，这可能导致模拟返回其他模拟的情况。

# 模拟爆炸

有了几种模拟框架，更容易熟悉模拟概念并为单元测试创建模拟。然而，开发人员可能会开始过度模拟，即每个对象似乎都是模拟候选对象的情况。此外，拥有太多的模拟可能会导致编写脆弱的测试，使你的测试容易在接口更改时出现问题。当你有太多的模拟时，最终会减慢测试套件的速度，并因此增加开发时间。

# 手动编写模拟与使用模拟框架

使用模拟框架可以促进流畅的单元测试体验，特别是在单元测试具有依赖关系的代码部分时，模拟对象被创建并替代依赖关系。虽然使用模拟框架更容易，但有时你可能更喜欢手动编写模拟对象进行单元测试，而不向项目或代码库添加额外的复杂性或附加库。

手动编写的模拟是为了测试而创建的类，用于替换生产对象。这些创建的类将具有与生产类相同的方法和定义，以及返回值，以有效模拟生产类并用作单元测试中依赖关系的替代品。

# 模拟概念

创建模拟的第一步应该是识别依赖关系。单元测试的目标应该是编写清晰的代码，并尽可能快地运行具有良好覆盖率的测试。你应该识别可能减慢测试速度的依赖关系。例如，Web 服务或数据库调用就是模拟的候选对象。

创建模拟对象的方法可以根据被模拟的依赖关系的类型而变化。然而，模拟的概念可以遵循模拟对象在调用方法时应返回特定预定义值的基本概念。应该有适当的验证机制来确保模拟的方法被调用，并且如果根据测试要求进行配置，模拟对象可以抛出异常。

了解模拟对象的类型对于有效地手动编写模拟对象非常重要。可以创建两种类型的模拟对象——动态和静态模拟对象。**动态对象**可以通过反射或代理类创建。这类似于模拟框架的工作方式。**静态模拟对象**可以通过实现接口的类以及有时作为要模拟的依赖关系的实际具体类来创建。当你手动编写模拟对象时，实质上你正在创建静态模拟对象。

**反射**可以用来创建模拟对象。C#中的反射是一个有用的构造，允许你创建一个类型的实例对象，以及获取或绑定类型到现有对象，并调用类型中可用的字段和方法。此外，你可以使用反射来创建描述模块和程序集的对象。

# 手动编写模拟的好处

手动编写您的模拟有时可能是一种有效的方法，当您打算完全控制测试设置并指定测试设置的行为时。此外，当测试相对简单时，使用模拟框架不是一个选择；最好手动编写模拟并保持一切简单。

使用模拟框架时，对被模拟的真实对象进行更改将需要更改在其使用的任何地方的模拟对象。这是因为对依赖项进行的更改将破坏测试。例如，如果依赖对象上的方法名称发生更改，您必须在动态模拟中进行更改。因此，必须在代码库的几个部分进行更改。使用手动编写的模拟，您只需要在一个地方进行更改，因为您可以控制向测试呈现的方法。

# 模拟和存根

**模拟**和**存根**都很相似，因为它们用于替换类依赖项或协作者，并且大多数模拟框架都提供创建两者的功能。存根可以以与手动编写模拟相同的方式手动编写。

那么模拟和存根真正的区别是什么？模拟用于测试协作。这包括验证实际协作者的期望。模拟被编程为具有包含要接收的方法调用详细信息的期望，而存根用于模拟协作者。让我们通过一个例子进一步解释这一点。

存根可用于表示来自数据库的结果。可以创建一个 C#列表，其中包含可用于执行测试的数据，以替代数据库调用返回一组数据。如果未验证测试的依赖项交互上方的存根，则测试将仅关注数据。

以下片段中的`LoanService`类具有一个`GetBadCarLoans`方法，该方法接受要从数据库中检索的`Loan`对象列表：

```cs
public class LoanService
{    
    public List<Loan> GetBadCarLoans(List<Loan> carLoans)
    {
        List<Loan> badLoans= new List<Loan>();
        //do business logic computations on the loans
        return badLoans;
    }
}
```

以下片段中`Test_GetBadCarLoans_ShouldReturnLoans`的`GetBadCarLoans`方法的测试使用了存根，这是一个`Loan`对象列表，作为参数传递给`GetBadCarLoans`方法，而不是调用数据库以获取用于`Test`类的`Loan`对象列表：

```cs
[Fact]
 public void Test_GetBadCarLoans_ShouldReturnLoans()
 {
    List<Loan> loans= new List<Loan>();
    loans.Add(new Loan{Amount=120000, Rate=12.5, ServiceYear=5, HasDefaulted=false});
    loans.Add(new Loan{Amount=150000, Rate=12.5, ServiceYear=4, HasDefaulted=true});
    loans.Add(new Loan{Amount=200000, Rate=12.5, ServiceYear=5, HasDefaulted=false});

    LoanService loanService= new LoanService();
    List<Loan> badLoans = loanService.GetBadCarLoans(loanDTO);
    Assert.NotNull(badLoans);
 }
```

以下片段中的`LoanService`类具有连接到数据库以获取记录的`LoanRepository` DI。该类具有一个构造函数，在该构造函数中注入了`ILoanRepository`对象。`LoanService`类具有一个`GetBadCarLoans`方法，该方法调用依赖项上的`GetCarLoan`方法，后者又调用数据库获取`Loan`对象列表：

```cs
public class LoanService
{
    private ILoanRepository loanRepository;

    public LoanService(ILoanRepository loanRepository)
    {
        this.loanRepository=loanRepository;
    }

    public List<Loan> GetBadCarLoans()
    {
        List<Loan> badLoans= new List<Loan>();
        var carLoans=loanRepository.GetCarLoans();
        //do business logic computations on the loans
        return badLoans;
    }
}
```

与使用存根时不同，模拟将验证调用依赖项中的方法。这意味着模拟对象将设置依赖项中要调用的方法。在以下片段中的`LoanServiceTest`类中，从`ILoanRepository`创建了一个模拟对象：

```cs
 public class LoanServiceTest
 {
        private Mock<ILoanRepository> loanRepository;
        private LoanService loanService;
        public LoanServiceTest()
        {
            loanRepository= new Mock<ILoanRepository>();
            List<Loan> loans = new List<Loan>
            {
                new Loan{Amount = 120000, Rate = 12.5, ServiceYear = 5, HasDefaulted = false },
                new Loan {Amount = 150000, Rate = 12.5, ServiceYear = 4, HasDefaulted = true },
                new Loan { Amount = 200000, Rate = 12.5, ServiceYear = 5, HasDefaulted = false }
            };
            loanRepository.Setup(x => x.GetCarLoans()).Returns(loans);
            loanService= new LoanService(loanRepository.Object);
        }

        [Fact]
        public void Test_GetBadCarLoans_ShouldReturnLoans()
        {
            List<Loan> badLoans = loanService.GetBadCarLoans();
            Assert.NotNull(badLoans);
        }
    }
```

在`LoanServiceTest`类的构造函数中，首先创建了模拟对象要返回的数据，然后设置了依赖项中的方法，如`loanRepository.Setup(x => x.GetCarLoans()).Returns(loans);`。然后将模拟对象传递给`LoanService`构造函数，`loanService= new loanService(loanRepository.Object);`。

# 手动编写模拟

我们可以手动编写一个模拟对象来测试`LoanService`类。要创建的模拟对象将实现`ILoanRepository`接口，并且仅用于单元测试，因为在生产代码中不需要它。模拟对象将返回一个`Loan`对象列表，这将模拟对数据库的实际调用。

```cs
public class LoanRepositoryMock : ILoanRepository
{
    public List<Loan> GetCarLoans()
    {
        List<Loan> loans = new List<Loan>
        {
            new Loan{Amount = 120000, Rate = 12.5, ServiceYear = 5, HasDefaulted = false },
            new Loan {Amount = 150000, Rate = 12.5, ServiceYear = 4, HasDefaulted = true },
            new Loan { Amount = 200000, Rate = 12.5, ServiceYear = 5, HasDefaulted = false }
        };
        return loans;
    }
}
```

现在可以在`LoanService`类中使用创建的`LoanRepositoryMock`类来模拟`ILoanRepository`，而不是使用从模拟框架创建的模拟对象。在`LoanServiceTest`类的构造函数中，将实例化`LoanRepositoryMock`类并将其注入到`LoanService`类中，该类在`Test`类中使用：

```cs
public class LoanServiceTest
{
    private ILoanRepository loanRepository;
    private LoanService loanService;

    public LoanServiceTest()
    {
        loanRepository= new LoanRepositoryMock();
        loanService= new LoanService(loanRepository);
    }

    [Fact]
    public void Test_GetBadCarLoans_ShouldReturnLoans()
    {
        List<Loan> badLoans = loanService.GetBadCarLoans();
        Assert.NotNull(badLoans);
    }
}
```

因为`LoanRepositoryMock`被用作`ILoanRepository`接口的具体类，是`LoanService`类的依赖项，所以每当在`ILoanRepository`接口上调用`GetCarLoans`方法时，`LoanRepositoryMock`的`GetCarLoans`方法将被调用以返回测试运行所需的数据。

# 使用 Moq 框架模拟对象

选择用于模拟对象的模拟框架对于顺利进行单元测试是很重要的。然而，并没有必须遵循的书面规则。在选择用于测试的模拟框架时，您可以考虑一些因素和功能。

在选择模拟框架时，性能和可用功能应该是首要考虑因素。您应该检查模拟框架创建模拟的方式；使用继承、虚拟和静态方法的框架无法被模拟。要注意的其他功能可能包括方法、属性、事件，甚至是框架是否支持 LINQ。

此外，没有什么比库的简单性和易用性更好。您应该选择一个易于使用的框架，并且具有良好的可用功能文档。在本章的后续部分中，将使用 Moq 框架来解释模拟的其他概念，这是一个易于使用的强类型库。

使用 Moq 时，模拟对象是一个实际的虚拟类，它是使用反射为您创建的，其中包含了被模拟的接口中包含的方法的实现。在 Moq 设置中，您将指定要模拟的接口以及测试类需要有效运行测试的方法。

要使用 Moq，您需要通过 NuGet 包管理器或 NuGet 控制台安装该库：

```cs
Install-Package Moq
```

为了解释使用 Moq 进行模拟，让我们创建一个`ILoanRepository`接口，其中包含两种方法，`GetCarLoan`用于从数据库中检索汽车贷款列表，以及`GetLoanTypes`方法，用于返回`LoanType`对象的列表：

```cs
public interface ILoanRepository
{
   List<LoanType> GetLoanTypes();
   List<Loan> GetCarLoans();
}
```

`LoanRepository`类使用 Entity Framework 作为数据访问和检索的 ORM，并实现了`ILoanRepository`。`GetLoanTypes`和`GetCarLoans`两种方法已经被`LoanRepository`类实现：

```cs
public class LoanRepository :ILoanRepository
{
    public List<LoanType> GetLoanTypes()
    {
        List<LoanType> loanTypes= new List<LoanType>();
        using (LoanContext context = new LoanContext())
        {
            loanTypes=context.LoanType.ToList();
        }
        return loanTypes;
    }

    public List<Loan> GetCarLoans()
    {
        List<Loan> loans = new List<Loan>();
        using (LoanContext context = new LoanContext())
        {
            loans = context.Loan.ToList();
        }
        return loans;
    }
}
```

让我们为`ILoanRepository`创建一个模拟对象，以便在不依赖任何具体类实现的情况下测试这两种方法。

使用 Moq 很容易创建一个模拟对象：

```cs
Mock<ILoanRepository> loanRepository = new Mock<ILoanRepository>();
```

在上一行代码中，已经创建了一个实现`ILoanRepository`接口的模拟对象。该对象可以被用作`ILoanRepository`的常规实现，并注入到任何具有`ILoanRepository`依赖的类中。

# 模拟方法、属性和回调

在测试中使用模拟对象的方法之前，它们需要被设置。这个设置最好是在测试类的构造函数中完成，模拟对象创建后，但在将对象注入到需要依赖的类之前。

首先，需要创建要由设置的方法返回的数据；这是测试中要使用的虚拟数据：

```cs
List<Loan> loans = new List<Loan>
{
    new Loan{Amount = 120000, Rate = 12.5, ServiceYear = 5, HasDefaulted = false },
    new Loan {Amount = 150000, Rate = 12.5, ServiceYear = 4, HasDefaulted = true },
    new Loan { Amount = 200000, Rate = 12.5, ServiceYear = 5, HasDefaulted = false }
};
```

在设置方法的时候，返回数据将被传递给它，以及任何方法参数（如果适用）。在下一行代码中，`GetCarLoans`方法被设置为以`Loan`对象的列表作为返回数据。这意味着每当在单元测试中使用模拟对象调用`GetCarLoans`方法时，之前创建的列表将作为方法的返回值返回：

```cs
Mock<ILoanRepository> loanRepository = new Mock<ILoanRepository>();
loanRepository.Setup(x => x.GetCarLoans()).Returns(loans);
```

您可以对方法返回值进行延迟评估。这是使用 LINQ 提供的语法糖：

```cs
loanRepository.Setup(x => x.GetCarLoans()).Returns(() => loans);
```

Moq 有一个`It`对象，它可以用来指定方法中参数的匹配条件。`It`指的是被匹配的参数。假设`GetCarLoans`方法有一个字符串参数`loanType`，那么方法设置的语法可以改变以包括参数和返回值：

```cs
loanRepository.Setup(x => x.GetCarLoans(It.IsAny<string>())).Returns(loans);
```

可以设置一个方法，每次调用时返回不同的返回值。例如，可以设置`GetCarLoans`方法的设置，以便在每次调用该方法时返回不同大小的列表：

```cs
Random random = new Random();
loanRepository.Setup(x => x.GetCarLoans()).Returns(loans).Callback(() => loans.GetRange(0,random.Next(1, 3));
```

在上面的片段中，生成了`1`和`3`之间的随机数，以设置。这将确保由`GetCarLoans`方法返回的列表的大小随每次调用而变化。第一次调用`GetCarLoans`方法时，将调用`Returns`方法，而在随后的调用中，将执行`Callback`中的代码。

Moq 的一个特性是提供异常测试的功能。您可以设置方法以测试异常。在以下方法设置中，当调用时，`GetCarLoans`方法会抛出`InvalidOperationException`：

```cs
loanRepository.Setup(x => x.GetCarLoans()).Throws<InvalidOperationException>();
```

# 属性

如果您有一个具有要在方法调用中使用的属性的依赖项，可以使用 Moq 的`SetupProperty`方法为这些属性设置虚拟值。让我们向`ILoanRepository`接口添加两个属性，`LoanType`和`Rate`：

```cs
public interface ILoanRepository
{
   LoanType LoanType{get;set;}
   float Rate {get;set;}

   List<LoanType> GetLoanTypes();
   List<Loan> GetCarLoans();
}
```

使用 Moq 的`SetupProperty`方法，您可以指定属性应具有的行为，这实质上意味着每当请求属性时，将返回在`SetupProperty`方法中设置的值：

```cs
Mock<ILoanRepository> loanRepository = new Mock<ILoanRepository>();
loanRepository.Setup(x => x.LoanType, LoanType.CarLoan);
loanRepository.Setup(x => x.Rate, 12.5);
```

在上面的片段中的代码将`LoanType`属性设置为枚举值`CarLoan`，并将`Rate`设置为`12.5`。在测试中请求属性时，将返回设置的值到调用点。

使用`SetupProperty`方法设置属性会自动将属性设置为存根，并允许跟踪属性的值并为属性提供默认值。

此外，在设置属性时，还可以使用`SetupSet`方法，该方法接受 lambda 表达式来指定对属性设置器的调用类型，并允许您将值传递到表达式中：

```cs
loanRepository.SetupSet(x => x.Rate = 12.5F);
```

`SetupSet`类似于`SetupGet`，用于为属性的调用指定类型的设置：

```cs
loanRepository.SetupGet(x => x.Rate);
```

递归模拟允许您模拟复杂的对象类型，特别是嵌套的复杂类型。例如，您可能希望模拟`Loan`类型中`Person`复杂类型的`Age`属性。Moq 框架可以以优雅的方式遍历此图以模拟属性：

```cs
loanRepository.SetupSet(x => x.CarLoan.Person.Age= 40);
```

您可以使用`SetupAllProperties`方法存根模拟对象上的所有属性。此方法将指定模拟上的所有属性都具有属性行为设置。通过在模拟中为每个属性生成默认值，使用 Moq 框架的`Mock.DefaultProperty`属性生成默认属性：

```cs
 loanRepository.SetupAllProperties();
```

# 匹配参数

在使用 Moq 创建模拟对象时，您可以匹配参数以确保在测试期间传递了预期的参数。使用此功能，您可以确定在测试期间调用方法时传递的参数的有效性。这仅适用于具有参数的方法，并且匹配将在方法设置期间进行。

使用 Moq 的`It`关键字，您可以在设置期间为方法参数指定不同的表达式和验证。让我们向`ILoanRepository`接口添加一个`GetCarLoanDefaulters`方法定义。`LoanRepository`类中的实现接受一个整数参数，该参数是贷款的服务年限，并返回汽车贷款拖欠者的列表。以下片段显示了`GetCarLoanDefaulters`方法的代码：

```cs
public List<Person> GetCarLoanDefaulters(int year)
{
    List<Person> defaulters = new List<Person>();
    using (LoanContext context = new LoanContext())
    {
        defaulters = context.Loan.Where(c => c.HasDefaulted 
                     && c.ServiceYear == year).Select(c => c.Person).ToList();
    }
    return defaulters;
}
```

现在，让我们在`LoanServiceTest`构造函数中设置`GetCarLoanDefaulters`方法，以使用 Moq 的`It`关键字接受不同的`year`参数值：

```cs
List<Person> people = new List<Person>
{
    new Person { FirstName = "Donald", LastName = "Duke", Age =30},
    new Person { FirstName = "Ayobami", LastName = "Adewole", Age =20}
};

Mock<ILoanRepository> loanRepository = new Mock<ILoanRepository>();
loanRepository.Setup(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 5, Range.Inclusive))).Returns(people);
```

已创建了一个`Person`对象列表，将传递给模拟设置的`Returns`方法。`GetCarLoanDefaulters`方法现在将接受指定范围内的值，因为`It.IsInRange`方法已经使用了上限和下限值。

`It` 类有其他有用的方法，用于在设置期间指定方法的匹配条件，而不必指定特定的值：

+   `IsRegex` 用于指定一个正则表达式来匹配一个字符串参数

+   `Is` 用于指定与给定谓词匹配的值

+   `IsAny<>` 用于匹配指定类型的任何值

+   `Ref<>` 用于匹配在 `ref` 参数中指定的任何值

您可以创建一个自定义匹配器，并在方法设置中使用它。例如，让我们为 `GetCarLoanDefaulters` 方法创建一个自定义匹配器 `IsOutOfRange`，以确保不会提供大于 `12` 的值作为参数。通过使用 `Match.Create` 来创建自定义匹配器：

```cs
public int IsOutOfRange() 
{ 
  return Match.Create<int>(x => x > 12);
}
```

现在可以在模拟对象的方法设置中使用创建的 `IsOutOfRange` 匹配器：

```cs
loanRepository.Setup(x => x.GetCarLoanDefaulters(IsOutOfRange())).Throws<ArgumentException>();
```

# 事件

Moq 有一个功能，允许您在模拟对象上引发事件。要引发事件，您使用 `Raise` 方法。该方法有两个参数。第一个是 Lambda 表达式，用于订阅事件以在模拟上引发事件。第二个参数提供将包含在事件中的参数。要在 `loanRepository` 模拟对象上引发 `LoanDefaulterNotification` 事件，并使用空参数，您可以使用以下代码行：

```cs
Mock<ILoanRepository> loanRepository = new Mock<ILoanRepository>();
loanRepository.Raise(x => x.LoanDefaulterNotification+=null, EventArgs.Empty);
```

真实用例是当您希望模拟对象响应动作引发事件或响应方法调用引发事件时。在模拟对象上设置方法以允许引发事件时，模拟上的 `Returns` 方法将被替换为 `Raises` 方法，该方法指示在测试中调用方法时，应该引发事件：

```cs
loanRepository.Setup(x => x.GetCarLoans()).Raises(x=> x.LoanDefaulterNotification+=null, new LoanDefualterEventArgs{OK=true});
```

# 回调

使用 Moq 的 `Callback` 方法，您可以指定在调用方法之前和之后要调用的回调。有一些测试场景可能无法使用简单的模拟期望轻松测试。在这种复杂的情况下，您可以使用回调来执行特定的操作，当调用模拟对象时。`Callback` 方法接受一个动作参数，根据回调是在方法调用之前还是之后设置，将执行该动作。该动作可以是要评估的表达式或要调用的另一个方法。

例如，您可以设置一个回调，在调用特定方法之后更改数据。此功能允许您创建提供更大灵活性的测试，同时简化测试复杂性。让我们向 `loanRepository` 模拟对象添加一个回调。

回调可以是一个将被调用的方法，或者是您需要设置值的属性：

```cs
List<Person> people = new List<Person>
{
    new Person { FirstName = "Donald", LastName = "Duke", Age =30},
    new Person { FirstName = "Ayobami", LastName = "Adewole", Age =20}
};

Mock<ILoanRepository> loanRepository = new Mock<ILoanRepository>();

loanRepository.Setup(x => x.GetCarLoanDefaulters())
.Callback(() => CarLoanDefaultersCallbackAfter ())
.Returns(() => people)
.Callback(() => CarLoanDefaultersCallbackAfter());
```

上面的片段为方法设置设置了两个回调。`CarLoanDefaultersCallback` 方法在实际调用 `GetCarLoanDefaulters` 方法之前被调用，`CarLoanDefaultersCallbackAfter` 在在模拟对象上调用 `GetCarLoanDefaulters` 方法之后被调用。`CarLoanDefaultersCallback` 向 `List` 添加一个新的 `Person` 对象，`CarLoanDefaultersCallback` 删除列表中的第一个元素：

```cs
public void CarLoanDefaultersCallback()
{
    people.Add(new Person { FirstName = "John", LastName = "Doe", Age =40});
}

public void CarLoanDefaultersCallbackAfter()
{
    people.RemoveAt(0);
}
```

# 模拟定制

在使用 Moq 框架时，您可以进一步定制模拟对象，以增强有效的单元测试体验。可以将 `MockBehavior` 枚举传递到 Moq 的 `Mock` 对象构造函数中，以指定模拟的行为。枚举成员有 `Default`、`Strict` 和 `Loose`：

```cs
loanRepository= new Mock<ILoanRepository>(MockBehavior.Loose);
```

当选择 `Loose` 成员时，模拟将不会抛出任何异常。默认值将始终返回。这意味着对于引用类型，将返回 null，对于值类型，将返回零或空数组和可枚举类型：

```cs
loanRepository= new Mock<ILoanRepository>(MockBehavior.Strict);
```

选择 `Strict` 成员将使模拟对于每次在模拟上没有适当设置的调用都抛出异常。最后，`Default` 成员是模拟的默认行为，从技术上讲等同于 `Loose` 枚举成员。

# CallBase

在模拟构造期间初始化`CallBase`时，用于指定是否在没有匹配的设置时调用基类虚拟实现。默认值为`false`。这在模拟`System.Web`命名空间的 HTML/web 控件时非常有用：

```cs
loanRepository= new Mock<ILoanRepository>{CallBase=true};
```

# 模拟存储库

通过使用 Moq 中的`MockRepository`，可以避免在测试中分散创建模拟对象的代码，从而避免重复的代码。`MockRepository`可用于在单个位置创建和验证模拟，从而确保您可以通过设置`CallBase`、`DefaultValue`和`MockBehavior`进行模拟配置，并在一个地方验证模拟：

```cs
var mockRepository = new MockRepository(MockBehavior.Strict) { DefaultValue = DefaultValue.Mock };
var loanRepository = repository.Create<ILoanRepository>(MockBehavior.Loose);
var userRepository = repository.Create<IUserRepository>();
mockRepository.Verify();
```

在上述代码片段中，使用`MockBehaviour.Strict`创建了一个模拟存储库，并创建了两个模拟对象，每个对象都使用`loanRepository`模拟，覆盖了存储库中指定的默认`MockBehaviour`。最后一条语句是对`Verify`方法的调用，以验证存储库中创建的所有模拟对象的所有期望。

# 在模拟中实现多个接口

此外，您可以在单个模拟中实现多个接口。例如，我们可以创建一个模拟，实现`ILoanRepository`，然后使用`As<>`方法实现`IDisposable`接口，该方法用于向模拟添加接口实现并为其指定设置：

```cs
var loanRepository = new Mock<ILoanRepository>();
loanRepository.Setup(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 5, Range.Inclusive))).Returns(people);

loanRepository.As<IDisposable>().Setup(disposable => disposable.Dispose());
```

# 使用 Moq 进行验证的方法和属性调用

模拟行为在设置期间指定。这是对象和协作者的预期行为。在单元测试时，模拟不完整，直到验证了所有模拟依赖项的调用。了解方法执行的次数或属性访问的次数可能会有所帮助。

Moq 框架具有有用的验证方法，可用于验证模拟的方法和属性。此外，`Times`结构包含有用的成员，显示可以在方法上允许的调用次数。

`Verify`方法可用于验证在模拟上执行的方法调用及提供的参数是否与先前在模拟设置期间配置的内容匹配，并且使用了默认的`MockBehaviour`，即`Loose`。为了解释 Moq 中的验证概念，让我们创建一个依赖于`ILoanRepository`的`LoanService`类，并向其添加一个名为`GetOlderCarLoanDefaulters`的方法，以返回年龄大于`20`岁的贷款拖欠人的列表。`ILoanRepository`通过构造函数注入到`LoanService`中：

```cs
public class LoanService
{
    private ILoanRepository loanRepository;
    public LoanService(ILoanRepository loanRepository)
    {
        this.loanRepository = loanRepository;
    }

    public List<Person> GetOlderCarLoanDefaulters(int year)
    {
        List<Person> defaulters = loanRepository.GetCarLoanDefaulters(year);
        var filteredDefaulters = defaulters.Where(x => x.Age > 20).ToList();
        return filteredDefaulters;
    }
}
```

为了测试`LoanService`类，我们将创建一个`LoanServiceTest`测试类，该类使用依赖模拟来隔离`LoanService`进行单元测试。`LoanServiceTest`将包含一个构造函数，用于设置`LoanService`类所需的`ILoanRepository`的模拟：

```cs
public class LoanServiceTest
{
    private Mock<ILoanRepository> loanRepository;
    private LoanService loanService;
    public  LoanServiceTest()
    {
        loanRepository= new Mock<ILoanRepository>();
        List<Person> people = new List<Person>
        {
            new Person { FirstName = "Donald", LastName = "Duke", Age =30},
            new Person { FirstName = "Ayobami", LastName = "Adewole", Age =20}
        };
        loanRepository.Setup(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1,12,Range.Inclusive))).Returns(() => people);
        loanService = new LoanService(loanRepository.Object);
   }
}
```

`LoanServiceTest`构造函数包含对`ILoanRepository`接口的`GetCarLoanDefaulters`方法的模拟设置，包括参数期望和返回值。让我们创建一个名为`Test_GetOlderCarLoanDefaulters_ShouldReturnList`的测试方法，以测试`GetCarLoanDefaulters`。在断言语句之后，有`Verify`方法来检查`GetCarLoanDefaulters`是否被调用了一次：

```cs
[Fact]
public void Test_GetOlderCarLoanDefaulters_ShouldReturnList()
{
    List<Person> defaulters = loanService.GetOlderCarLoanDefaulters(12);
    Assert.NotNull(defaulters);
    Assert.All(defaulters, x => Assert.Contains("Donald", x.FirstName));
    loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.Once());
}
```

`Verify`方法接受两个参数：要验证的方法和`Time`结构。使用了`Time.Once`，指定模拟方法只能被调用一次。

`Times.AtLeast(int callCount)`用于指定模拟方法应该被调用的最小次数，该次数由`callCount`参数的值指定。这可用于验证方法被调用的次数：

```cs
[Fact]
public void Test_GetOlderCarLoanDefaulters_ShouldReturnList()
{
    List<Person> defaulters = loanService.GetOlderCarLoanDefaulters(12);
    Assert.NotNull(defaulters);
    Assert.All(defaulters, x => Assert.Contains("Donald", x.FirstName));
    loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.AtLeast(2));
}
```

在上述测试片段中，将`Times.AtLeast(2)`传递给`Verify`方法。当运行测试时，由于被测试的代码中的`GetCarLoanDefaulters`方法只被调用了一次，测试将失败，并显示`Moq.MoqException`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/5fc37630-7401-4e5b-91eb-3b83646e10be.png)

`Times.AtLeastOnce`可用于指定模拟方法应至少调用一次，这意味着该方法可以在被测试的代码中被多次调用。我们可以修改`Test_GetOlderCarLoanDefaulters_ShouldReturnList`中的`Verify`方法，以将第二个参数设置为`Time.AtLeastOnce`，以验证测试运行后`GetCarLoanDefaulters`至少在被测试的代码中被调用一次：

```cs
[Fact]
public void Test_GetOlderCarLoanDefaulters_ShouldReturnList()
{
    List<Person> defaulters = loanService.GetOlderCarLoanDefaulters(12);
    Assert.NotNull(defaulters);
    Assert.All(defaulters, x => Assert.Contains("Donald", x.FirstName));
    loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.AtLeastOnce);
}
```

`Times.AtMost(int callCount)`可用于指定在被测试的代码中应调用模拟方法的最大次数。 `callCount`参数用于传递方法的最大调用次数的值。这可用于限制允许对模拟方法的调用。如果调用方法的次数超过指定的`callCount`值，则会抛出 Moq 异常：

```cs
loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.AtMost(1));
```

`Times.AtMostOnce`类似于`Time.Once`或`Time.AtLeastOnce`，但不同之处在于模拟方法最多只能调用一次。如果方法被调用多次，则会抛出 Moq 异常，但如果在运行代码时未调用该方法，则不会抛出异常：

```cs
loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.AtMostOnce);
```

`Times.Between(callCountFrom,callCountTo, Range)`可用于在`Verify`方法中指定模拟方法应在`callCountFrom`和`callCountTo`之间调用，并且`Range`枚举用于指定是否包括或排除指定的范围：

```cs
loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.Between(1,2,Range.Inclusive));
```

`Times.Exactly(callCount)`在您希望指定模拟方法应在指定的`callCount`处调用时非常有用。如果模拟方法的调用次数少于指定的`callCount`或多次，将生成 Moq 异常，并提供期望和失败的详细描述：

```cs
[Fact]
public void Test_GetOlderCarLoanDefaulters_ShouldReturnList()
{
    List<Person> defaulters = loanService.GetOlderCarLoanDefaulters(12);
    Assert.NotNull(defaulters);
    Assert.All(defaulters, x => Assert.Contains("Donald", x.FirstName));
    loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.Exactly(2));
}
```

现在让我们检查代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/e6b75b04-d6c5-4546-9ac3-c279e4a9d943.png)

还有一个重要的是`Times.Never`。当使用时，它可以验证模拟方法从未被使用。当您不希望调用模拟方法时，可以使用此选项：

```cs
loanRepository.Verify(x => x.GetCarLoanDefaulters(It.IsInRange<int>(1, 12, Range.Inclusive)), Times.Never);
```

模拟属性验证与使用`VerifySet`和`VerifyGet`方法的模拟方法类似进行。`VerifySet`方法用于验证在模拟对象上设置了属性。此外，`VerifyGet`方法用于验证在模拟对象上读取了属性，而不管属性中包含的值是什么：

```cs
loanRepository.VerifyGet(x => x.Rate);
```

要验证在模拟对象上设置了属性，而不管设置了什么值，可以使用`VerifySet`方法，语法如下：

```cs
loanRepository.VerifySet(x => x.Rate);
```

有时，您可能希望验证在模拟对象上分配了特定值给属性。您可以通过将值分配给`VerifySet`方法中的属性来执行此操作：

```cs
loanRepository.VerifySet(x => x.Rate = 12.5);
```

Moq 4.8 中引入的`VerifyNoOtherCalls()`方法可用于确定除了已经验证的调用之外没有进行其他调用。`VerifyAll()`方法用于验证所有期望，无论它们是否已被标记为可验证。

# LINQ 到模拟

**语言集成查询**（**LINQ**）是在.NET 4.0 中引入的一种语言构造，它提供了.NET Framework 中的查询功能。 LINQ 具有以声明性查询语法编写的查询表达式。有不同的 LINQ 实现-LINQ 到 XML，用于查询 XML 文档，LINQ 到实体，用于 ADO.NET 实体框架操作，LINQ 到对象用于查询.NET 集合，文件，字符串等。

在本章中，我们使用 Lambda 表达式语法创建了模拟对象。 Moq 框架中提供的另一个令人兴奋的功能是**LINQ 到模拟**，它允许您使用类似 LINQ 的语法设置模拟。

LINQ 到模拟非常适用于简单的模拟，并且在您真的不关心验证依赖关系时。使用`Of<>`方法，您可以创建指定类型的模拟对象。

您可以使用 LINQ 到模拟来在单个模拟和递归模拟上进行多个设置，使用类似 LINQ 的语法：

```cs
 var loanRepository = Mock.Of<ILoanRepository>
                    (x => x.Rate==12.5F &&
                         x.LoanType.Name=="CarLoan"&& LoanType.Id==3 );
```

在前面的模拟初始化中，`Rate`和`LoanType`属性被设置为存根，在测试调用期间访问这些属性时，它们将使用属性的默认值。

# 高级的 Moq 功能

有时，Moq 提供的默认值可能不适用于某些测试场景，您需要创建自定义的默认值生成方法来补充 Moq 当前提供的`DefaultValue.Empty`和`DefaultValue.Mock`。这可以通过扩展 Moq 4.8 及更高版本中提供的`DefaultValueProvider`或`LookupOrFallbackDefaultValueProvider`来实现：

```cs
public class TestDefaultValueProvider : LookupOrFallbackDefaultValueProvider
{
    public TestDefaultValueProvider()
    {
        base.Register(typeof(string), (type, mock) => string.empty);
        base.Register(typeof(List<>), (type, mock) => Activator.CreateInstance(type));
    }
}
```

`TestDefaultValueProvider`类创建了子类`LookupOrFallbackDefaultValueProvider`，并为`string`和`List`的默认值进行了实现。对于任何类型的`string`，都将返回`string.empty`，并创建一个空列表，其中包含任何类型的`List`。`TestDefaultValueProvider`现在可以在`Mock`构造函数中用于模拟创建：

```cs
var loanRepository = new Mock<ILoanRepository> { DefaultValueProvider = new TestDefaultValueProvider()};
var objectName = loanRepository.Object.Name;
```

在前面的代码片段中，`objectName`变量将包含一个零长度的字符串，因为`TestDefaultValueProvider`中的实现表明应该为`string`类型分配一个空字符串。

# 模拟内部类型

根据项目的要求，您可能需要为内部类型创建模拟对象。在 C#中，内部类型或成员只能在同一程序集中的文件中访问。可以通过向相关项目的`AssemblyInfo.cs`文件添加自定义属性来模拟内部类型。

如果包含内部类型的程序集尚未具有`AssemblyInfo.cs`文件，您可以添加它。此外，当程序集没有强名称时，您可以添加`InternalsVisibleTo`属性，其中排除了公钥。您必须指定要与之共享可见性的项目名称，在这种情况下应该是测试项目。

如果将`LoanService`的访问修饰符更改为 internal，您将收到错误消息，`LoanService`由于其保护级别而无法访问。为了能够测试`LoanService`，而不更改访问修饰符，我们需要将`AssemblyInfo.cs`文件添加到项目中，并添加所需的属性，指定测试项目名称，以便与包含`LoanService`的程序集共享：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/d577ffd0-5843-454d-ae40-c150b5f0c98b.png)

`AssemblyInfo.cs`文件中添加的属性如下所示：

```cs
[assembly:InternalsVisibleTo("LoanApplication.Tests.Unit")
```

# 总结

Moq 框架与 xUnit.net 框架一起使用时，可以提供流畅的单元测试体验，并使整个 TDD 过程变得有价值。Moq 提供了强大的功能，有效使用时，可以简化单元测试的依赖项模拟的创建。

使用 Moq 创建的模拟对象可以让您在单元测试中替换具体的依赖项，以便通过您创建的模拟对象来隔离代码中的不同单元进行测试和后续重构，这有助于编写优雅的生产就绪代码。此外，您可以使用模拟对象来实验和测试依赖项中可用的功能，否则可能无法轻松地使用实际依赖项来完成。

在本章中，我们探讨了模拟的基础知识，并在单元测试中广泛使用了模拟。此外，我们配置了模拟以设置方法和属性，并返回异常。还解释了 Moq 库提供的一些其他功能，并介绍了模拟验证。

项目托管和持续集成将在下一章中介绍。这将包括测试和企业方法来自动运行测试，以确保能够提供有关代码覆盖率的质量反馈。
