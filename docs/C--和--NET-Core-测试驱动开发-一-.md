# C# 和 .NET Core 测试驱动开发（一）

> 原文：[`zh.annas-archive.org/md5/32CD200F397A73ED943D220E0FB2E744`](https://zh.annas-archive.org/md5/32CD200F397A73ED943D220E0FB2E744)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

您如何验证您的跨平台.NET Core 应用程序在部署到任何地方时都能正常工作？随着业务、团队和技术环境的发展，您的代码能够随之发展吗？通过遵循测试驱动开发的原则，您可以简化代码库，使查找和修复错误变得微不足道，并确保您的代码能够按照您的想法运行。

本书指导开发人员通过建立专业的测试驱动开发流程来创建健壮、可投入生产的 C# 7 和.NET Core 应用程序。为此，您将首先学习 TDD 生命周期的各个阶段、一些最佳实践和一些反模式。

在第一章介绍了 TDD 的基础知识后，您将立即开始创建一个示例 ASP.NET Core MVC 应用程序。您将学习如何使用 SOLID 原则编写可测试的代码，并设置依赖注入。

接下来，您将学习如何使用 xUnit.net 测试框架创建单元测试，以及如何使用其属性和断言。一旦掌握了基础知识，您将学习如何创建数据驱动的单元测试以及如何在代码中模拟依赖关系。

在本书的最后，您将通过使用 GitHub、TeamCity、VSTS 和 Cake 来创建一个健康的持续集成流程。最后，您将修改持续集成构建，以测试、版本化和打包一个示例应用程序。

# 本书适合对象

本书适用于希望通过实施测试驱动开发原则构建质量、灵活、易于维护和高效企业应用程序的.NET 开发人员。

# 本书涵盖内容

第一章，“探索测试驱动开发”，向您介绍了如何通过学习和遵循测试驱动开发的成熟原则来改善编码习惯和代码。

第二章，“使用.NET Core 入门”，向您介绍了.NET Core 和 C# 7 的超酷新跨平台功能。我们将通过实际操作来学习，在 Ubuntu Linux 上使用测试驱动开发原则创建一个 ASP.NET MVC 应用程序。

第三章，“编写可测试的代码”，演示了为了获得测试驱动开发周期的好处，您必须编写可测试的代码。在本章中，我们将讨论创建可测试代码的 SOLID 原则，并学习如何为依赖注入设置我们的.NET Core 应用程序。

第四章，“.NET Core 单元测试”，介绍了.NET Core 和 C#可用的单元测试框架。我们将使用 xUnit 框架创建一个共享的测试上下文，包括设置和清除代码。您还将了解如何创建基本的单元测试，并使用 xUnit 断言来证明单元测试的结果。

第五章，“数据驱动的单元测试”，介绍了允许您通过一系列数据输入来测试代码的概念，可以是内联的，也可以来自数据源。在本章中，我们将创建 xUnit 中的数据驱动单元测试或理论。

第六章，“模拟依赖关系”，解释了模拟对象是模仿真实对象行为的模拟对象。在本章中，您将学习如何使用 Moq 框架，使用 Moq 创建的模拟对象来隔离您正在测试的类与其依赖关系。

第七章，*持续集成和项目托管*，侧重于测试驱动开发周期的目标，即快速提供有关代码质量的反馈。持续集成流程将这种反馈周期延伸到发现代码集成问题。在本章中，您将开始创建一个持续集成流程，该流程可以为开发团队提供有关代码质量和集成问题的快速反馈。

第八章，*创建持续集成构建流程*，解释了一个出色的持续集成流程将许多不同的步骤整合成一个易于重复的流程。在本章中，您将配置 TeamCity 和 VSTS 使用跨平台构建自动化系统 Cake 来清理、构建、恢复软件包依赖关系并测试您的解决方案。

第九章，*测试和打包应用程序*，教您修改 Cake 构建脚本以运行 xUnit 测试套件。您将通过为.NET Core 支持的各种平台版本化和打包应用程序来完成该过程。

# 为了充分利用本书

假定您具有 C#编程和 Microsoft Visual Studio 的工作知识。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址是[`github.com/PacktPublishing/CSharp-and-.NET-Core-Test-Driven-Development`](https://github.com/PacktPublishing/CSharp-and-.NET-Core-Test-Driven-Development)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/CSharpanddotNETTestDrivenDevelopment_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/CSharpanddotNETTestDrivenDevelopment_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“为了使测试通过，您必须迭代实现生产代码。当实现以下`IsServerOnline`方法时，预计`Test_IsServerOnline_ShouldReturnTrue`测试方法将通过。”

代码块设置如下：

```cs
[Fact]
 public void Test_IsServerOnline_ShouldReturnTrue() 
 { 
    bool isOnline=IsServerOnline();   

    Assert.True(isOnline);
 }
```

任何命令行输入或输出都是按照以下格式编写的：

```cs
sudo apt-get update
sudo apt-get install dotnet-sdk-2.0.0
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“Visual Studio Code 将尝试下载 Linux 平台所需的依赖项，Linux 的 Omnisharp 和.NET Core 调试器。”

警告或重要说明看起来像这样。

技巧和窍门看起来像这样。


# 第一章：探索测试驱动开发

为了打造健壮、可维护和可扩展的软件应用程序，软件开发团队和利益相关者必须在软件开发过程的不同阶段早期做出一些重要决策。这些决策者必须在整个软件开发过程中采用软件行业经过测试和证明的最佳实践和标准。

当开发人员使用开发方法、编码风格和实践来构建代码库时，这些方法会自动使源代码变得僵化且难以维护，软件项目的质量会迅速下降。本章指出了导致编写糟糕代码的习惯和实践，因此应该避免。解释了应该学习的编程习惯、开发风格和方法，以便编写清洁和可维护的代码。

在本章中，我们将涵盖以下主题：

+   维护代码的困难

+   糟糕的代码是如何变成糟糕的

+   我们可以做些什么来防止糟糕的代码

+   测试驱动开发的原则

+   测试驱动开发周期

# 维护代码的困难

有两种类型的代码——好的代码和糟糕的代码。这两种类型的代码在编译时语法可能是正确的，运行代码可以得到预期的结果。然而，由于编写方式的原因，糟糕的代码在扩展或甚至对代码进行小改动时会导致严重问题。

当程序员使用不专业的方法和风格编写代码时，通常会导致糟糕的代码。此外，使用难以阅读的编码风格或格式，以及未能正确有效地测试代码都是糟糕代码的先兆。当程序员为了满足即将到来的截止日期和项目里程碑而牺牲专业精神时，代码可能会写得很糟糕。

我曾遇到一些软件项目，它们迅速成为被遗弃的遗留软件项目，因为不断出现的生产错误和无法轻松地满足用户的变更请求。这是因为这些软件应用程序在投入生产时积累了严重的技术债务，这是由于软件开发人员编写了糟糕的代码，导致了糟糕的设计和开发决策，并使用了已知会导致未来维护问题的编程风格。

源代码元素——方法、类、注释和其他工件——应该易于阅读、理解、调试、重构和扩展，如果需要由原始开发人员以外的其他开发人员进行；否则，糟糕的代码已经被编写。

当你在扩展或添加新功能时，你会知道你的代码有问题，因为你会破坏现有的工作功能。当代码部分无法解码或对其进行任何更改会使系统停止时，也会发生这种情况。糟糕的代码通常是因为不遵守面向对象和“不要重复自己”（DRY）原则或错误使用这些原则。

DRY 是编程中的一个重要原则，旨在将系统分解为小组件。这些组件可以轻松管理、维护和重复使用，以避免编写重复的代码并使代码的不同部分执行相同的功能。

# 糟糕的代码是如何出现的？

糟糕的代码不仅仅出现在代码库中；程序员写了糟糕的代码。大多数情况下，糟糕的代码可能是由于以下任何原因之一而写成的：

+   开发人员在编写代码时使用错误的方法经常被归因于组件之间的紧密耦合

+   错误的程序设计

+   程序元素和对象的糟糕命名约定

+   编写不可读的代码以及没有适当的测试用例的代码库，因此在需要维护代码库时会导致困难

# 紧密耦合

大多数传统软件应用程序都被认为是紧密耦合的，灵活性和模块化性很少或根本没有。紧密耦合的软件组件会导致刚性的代码库，难以修改、扩展和维护。随着大多数软件应用程序随着时间的推移而发展，当应用程序的组件紧密耦合时，会产生大量的维护问题。这是由于需求变化、用户业务流程和操作的变化所导致的。

第三方库和框架可以减少开发时间，并允许开发人员集中精力实施用户的业务逻辑和需求，而无需浪费宝贵的生产时间通过实现常见或乏味的任务来重新发明轮子。然而，有时开发人员会将应用程序与第三方库和框架紧密耦合，从而创建维护瓶颈，需要大力修复当需要替换引用的库或框架时。

以下代码片段显示了与第三方`smpp`库紧密耦合的示例：

```cs
public void SendSMS()
{
    SmppManager smppManager= new SmppManager(); 
    smppManager.SendMessage("0802312345","Hello", "John");
}

public class SmppManager
{
    private string sourceAddress;
    private SmppClient smppClient;

    public SmppManager()
    {
       smppClient = new SmppClient();
       smppClient.Start();            
    }        

    public void SendMessage(string recipient, string message, string senderName)
    {
       // send message using referenced library            
    }    
}
```

# 代码异味

**代码异味**是由*Kent Beck*首次使用的一个术语，它指出了源代码中的更深层次的问题。代码库中的代码异味可能来自于源代码中的复制、使用不一致或模糊的命名约定和编码风格、创建具有长参数列表的方法以及具有庞大方法和类，即知道并做太多事情，从而违反了单一责任原则。列表还在继续。

在源代码中常见的代码异味是当开发人员创建两个或更多执行相同操作的方法，几乎没有变化或在应该在单个点中实现的程序细节或事实在多个方法或类中复制，导致代码库难以维护。

以下两个 ASP.NET MVC 动作方法有代码行，创建了一个强类型的字符串年份和月份列表。这些代码行本来可以被重构为第三个方法，并被这两个方法调用，但却在这两个方法中被复制：

```cs
[HttpGet]
public ActionResult GetAllTransactions()
{
    List<string> years = new List<string>();
    for (int i = DateTime.Now.Year; i >= 2015; i--)
         years.Add(i.ToString());
    List<string> months = new List<string>();
    for (int j = 1; j <= 12; j++)
         months.Add(j.ToString());
    ViewBag.Transactions= GetTransactions(years,months);
     return View();
}

[HttpGet]
public ActionResult SearchTransactions()
{
    List<string> years = new List<string>();
    for (int i = DateTime.Now.Year; i >= 2015; i--)
         years.Add(i.ToString());
    List<string> months = new List<string>();
    for (int j = 1; j <= 12; j++)
        months.Add(j.ToString());
    ViewBag.Years = years;
    ViewBag.Months = months;
    return View();
}
```

另一个常见的代码异味出现在开发人员创建具有长参数列表的方法时，就像以下方法中所示：

```cs
public void ProcessTransaction(string  username, string password, float transactionAmount, string transactionType, DateTime time, bool canProcess, bool retryOnfailure)
{
    //Do something
}
```

# 坏或破损的设计

在实施应用程序时，经常会出现结构或设计和模式导致糟糕的代码，尤其是在错误使用面向对象编程原则或设计模式时。一个常见的反模式是**意大利面条式编码**。这在对面向对象理解不深的开发人员中很常见，这涉及创建具有不清晰结构、几乎没有可重用性以及对象和组件之间没有关系的代码库。这导致应用程序难以维护和扩展。

在经验不足的开发人员中有一种常见的做法，即在解决应用程序复杂性时不必要或不适当地使用设计模式。当错误使用设计模式时，会给代码库带来糟糕的结构和设计。使用设计模式应该简化复杂性，并为软件问题创建可读和可维护的解决方案。当某个模式导致可读性问题并明显增加了程序的复杂性时，值得重新考虑是否使用该模式，因为该模式被误用了。

例如，单例模式用于创建对资源的单个实例。单例类的设计应该有一个私有构造函数，没有参数，一个静态变量引用资源的单个实例，以及一个管理的公共手段来引用静态变量。单例模式可以简化对单一共享资源的访问，但如果没有考虑线程安全性，也可能会导致很多问题。两个或更多线程可以同时访问`if (smtpGateway==null)`这一行，如果这行被评估为`true`，就会创建资源的多个实例，就像下面代码中所示的实现一样：

```cs
public class SMTPGateway
{
    private static SMTPGateway smtpGateway=null;

    private SMTPGateway()
    {
    }

    public static SMTPGateway SMTPGatewayObject
    {
        get
        {
            if (smtpGateway==null)
            {
                smtpGateway = new SMTPGateway();
            }
            return smtpGateway;
        }
    }
} 
```

# 命名程序元素

有意义和描述性的元素命名可以极大地提高源代码的可读性。它可以让程序的逻辑流程更容易理解。令人惊讶的是，软件开发人员仍然会给程序元素起太短或者不够描述性的名字，比如给变量起一个字母的名字，或者使用缩写来命名变量。

对元素使用通用或模糊的名称会导致歧义。例如，将一个方法命名为`Extract()`或`Calculate()`，乍一看会导致主观解释。对变量使用模糊的名称也是如此。例如：

```cs
int x2;

string xxya;
```

虽然程序元素的命名本身就是一门艺术，但是名称应该被选择来定义目的，并简要描述元素，并确保所选名称符合所使用的编程语言的标准和规则。

有关可接受的命名准则和约定的更多信息，请访问：[`docs.microsoft.com/en-us/dotnet/standard/design-guidelines/naming-guidelines`](https://docs.microsoft.com/en-us/dotnet/standard/design-guidelines/naming-guidelines)。

# 源代码的可读性

一个良好的代码库可以通过一个新团队成员或者甚至是程序员在离开几年后能够轻松理解来轻松区分出一个糟糕的代码库。由于时间紧迫和截止日期临近，软件开发团队往往会妥协和牺牲专业精神来满足截止日期，不遵循推荐的最佳实践和标准。这经常导致他们产生不可读的代码。

以下代码片段将执行其预期的功能，尽管其中包含使用糟糕的命名约定编写的元素，这影响了代码的可读性：

```cs
public void updatetableloginentries()
{
   com.Connection = conn;
   SqlParameter par1 = new SqlParameter();
   par1.ParameterName = "@username";
   par1.Value = main.username;
   com.Parameters.Add(par1);
   SqlParameter par2 = new SqlParameter();
   par2.ParameterName = "@date";
   par2.Value = main.date;
   com.Parameters.Add(par2);
   SqlParameter par3 = new SqlParameter();
   par3.ParameterName = "@logintime";
   par3.Value = main.logintime;
   com.Parameters.Add(par3);
   SqlParameter par4 = new SqlParameter();
   par4.ParameterName = "@logouttime";
   par4.Value = DateTime.Now.ToShortTimeString(); ;
   com.Parameters.Add(par4);
   com.CommandType = CommandType.Text;
   com.CommandText = "update loginentries set logouttime=@logouttime where username=@username and date=@date and logintime=@logintime";
   openconn();
   com.ExecuteNonQuery();
   closeconn();
}
```

# 糟糕的源代码文档

当使用编程语言的编码风格和约定编写代码时，可以很容易地理解代码，同时避免之前讨论过的糟糕的代码陷阱。然而，源代码文档非常有价值，在软件项目中的重要性不可低估。对类和方法进行简要而有意义的文档编写可以让开发人员快速了解它们的内部结构和操作。

当没有适当的文档时，理解复杂或写得不好的类会变成一场噩梦。当原始编写代码的程序员不再提供澄清时，宝贵的生产时间可能会因为试图理解类或方法的实现而丢失。

# 未经测试的代码

尽管已经有很多文章和讨论在各种开发者会议上启动了不同类型的测试——测试驱动开发、行为驱动开发和验收测试驱动开发，但令人担忧的是，仍然有开发人员不断开发和发布未经彻底测试或根本没有经过测试的软件应用程序。

发布未经充分测试的应用程序可能会产生灾难性后果和维护问题。值得注意的是**美国国家航空航天局**于**1998 年 12 月 11 日**发射的**火星气候轨道飞行器**在接近火星时失败，原因是由于转换错误导致的软件错误，其中轨道飞行器的程序代码在计算时使用的是磅而不是牛顿。对负责计算度量标准的特定模块进行简单的单元测试可能会检测到错误并可能防止失败。

此外，根据 2016 年*测试优先方法的现状报告*，由名为**QASymphony**的测试服务公司对来自 15 个不同国家的 200 多家软件组织的测试优先方法的采用进行了调查，结果显示近一半的受访者在他们开发的应用程序中没有实施测试优先方法。

# 我们可以做些什么来防止糟糕的代码

编写干净的代码需要有意识地保持专业精神，并在软件开发过程的各个阶段遵循最佳行业标准。从软件项目开发的一开始就应该避免糟糕的代码，因为通过糟糕的代码积累的坏账可能会减慢软件项目的完成速度，并在软件部署到生产环境后造成未来问题。

要避免糟糕的代码，你必须懒惰，因为一般说来懒惰的程序员是最好的和最聪明的程序员，因为他们讨厌重复的任务，比如不得不回去修复本可以避免的问题。尽量使用避免编写糟糕代码的编程风格和方法，以避免不得不重写代码以修复可避免的问题、错误或支付技术债务。

# 松散耦合

**松散耦合**是紧密耦合的直接相反。这是一种良好的面向对象编程实践，通过允许组件几乎不知道其他组件的内部工作和实现来实现关注点的分离。通信是通过接口进行的。这种方法允许轻松替换组件，而不需要对整个代码库进行太多更改。在*紧耦合*部分的示例代码可以重构以实现松散耦合：

```cs
//The dependency injection would be done using Ninject
public ISmppManager smppManager { get; private set; }

public void SendSMS()
{    
    smppManager.SendMessage("0802312345","Hello", "John");
}

public class SmppManager
{
    private string sourceAddress;
    private SmppClient smppClient;

    public SmppManager()
    {
       smppClient = new SmppClient();
       smppClient.Start();            
    }        

    public void SendMessage(string recipient, string message, string senderName)
    {
       // send message using referenced library            
    }    
}
public interface ISmppManager
{
    void SendMessage(string recipient, string message, string senderName);
}
```

# 声音架构和设计

通过使用良好的开发架构和设计策略可以避免糟糕的代码。这将确保开发团队和组织具有高级架构、策略、实践、准则和治理计划，团队成员必须遵循以防止走捷径和避免在整个开发过程中出现糟糕的代码。

通过持续学习和改进，软件开发团队成员可以对编写糟糕的代码产生厚厚的皮肤。*糟糕或破损的设计*部分中的示例代码片段可以重构为线程安全，并避免与线程相关的问题，如下所示：

```cs
public class SMTPGateway
{
    private static SMTPGateway smtpGateway=null;
    private static object lockObject= new object();

    private SMTPGateway()
    {
    }

    public static SMTPGateway SMTPGatewayObject
    {
        get
        {
            lock (lockObject)
            {
                if (smtpGateway==null)
                {
                    smtpGateway = new SMTPGateway();
                }
            }
            return smtpGateway;
        }
    }
} 
```

# 预防和检测代码异味

应该避免导致代码异味的编程风格和编码格式。通过充分关注*代码异味*部分中讨论的糟糕代码指针，可以避免代码的重复。在*代码异味*部分提到的源代码的两种方法中的重复代码可以重构为第三种方法。这样可以避免代码的重复，并且可以轻松进行修改：

```cs
[HttpGet]
public ActionResult GetAllTransactions()
{
    var yearsAndMonths=GetYearsAndMonths();
    ViewBag.Transactions= GetTransactions(yearsAndMonths.Item1,yearsAndMonths.Item2);
    return View();
}

[HttpGet]
public ActionResult SearchTransactions()
{
    var yearsAndMonths=GetYearsAndMonths();
    ViewBag.Years = yearsAndMonths.Item1;
    ViewBag.Months = yearsAndMonths.Item2;
    return View();
}

private (List<string>, List<string>) GetYearsAndMonths(){
    List<string> years = new List<string>();
    for (int i = DateTime.Now.Year; i >= 2015; i--)
         years.Add(i.ToString());
    List<string> months = new List<string>();
    for (int j = 1; j <= 12; j++)
        months.Add(j.ToString());
    return (years,months);
}
```

此外，在*代码异味*部分中具有长参数列表的方法可以重构为使用**C# Plain Old CLR Object**（**POCO**）以实现清晰和可重用性：

```cs
public void ProcessTransaction(Transaction transaction)
{
    //Do something
}

public class Transaction
{
    public string  Username{get;set;}
    public string Password{get;set;}
    public float TransactionAmount{get;set;}
    public string TransactionType{get;set;}
    public DateTime Time{get;set;}
    public bool CanProcess{get;set;}
    public bool RetryOnfailure{get;set;}    
}
```

开发团队应该有由团队成员共同制定的准则、原则和编码约定和标准，并应不断更新和完善。有效使用这些将防止软件代码库中的代码异味，并允许团队成员轻松识别潜在的糟糕代码。

# C#编码约定

遵循 C#编码约定指南有助于掌握编写清晰、可读、易于修改和易于维护的代码。使用描述性的变量名称，代表它们的用途，如下面的代码所示：

```cs
int accountNumber;

string firstName;
```

此外，一行上有多个语句或声明会降低可读性。注释应该在新的一行上，而不是在代码的末尾。您可以在以下链接了解更多关于 C#编码约定的信息：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/coding-conventions`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/coding-conventions)。

# 简洁而恰当的文档

您应该始终尝试编写自解释的代码。这可以通过良好的编程风格实现。以这样一种方式编写代码，使得您的类、方法和其他对象都是自解释的。新的开发人员应该能够使用您的代码，而不必在理解代码及其内部结构之前感到紧张。

编码元素应该具有描述性和意义，以向读者提供洞察力。在必须记录方法或类以提供进一步澄清的情况下，采用“保持简单”的方法，简要说明某个决定的原因。检查以下代码片段；没有人希望为包含 200 行代码的类阅读两页文档：

```cs
///
/// This class uses SHA1 algorithm for encryption with randomly generated salt for uniqueness
///
public class AESEncryptor
{
    //Code goes here
}
```

KISS，也称为“保持简单，愚蠢”，是一种设计原则，它指出大多数系统在保持简单而不是使其不必要地复杂时运行得最好。该原则旨在帮助程序员尽可能简化代码，以确保未来可以轻松维护代码。

# 为什么要进行测试驱动开发？

每当我与不实践测试驱动开发的人进行讨论时，他们通常有一个共同点，那就是它消耗时间和资源，而且并不能真正带来投资回报。我通常会回答他们，问哪个更好，即在应用程序开发过程中检测错误和潜在瓶颈并修复它们，还是在应用程序处于生产状态时进行热修复？测试驱动开发将为您节省大量问题，并确保您生成健壮且无故障的应用程序。

# 面向长期发展

为了避免由于用户需求变化而对系统进行修改时可能导致的未来问题，以及由于代码库中固有的糟糕代码和累积的技术债务而暴露的错误，您需要具有以未来为考量并接受变化的思维方式。

使用灵活的模式，并且在编写代码时始终遵循良好的面向对象开发和设计原则。大多数软件项目的需求在其生命周期内都会发生变化。假设某个组件或部分不会发生变化是错误的，因此请尝试建立一个机制，使应用程序能够优雅地接受未来的变化。

# 测试驱动开发的原则

测试驱动开发（TDD）是一种迭代的敏捷开发技术，强调先测试开发，这意味着在编写生产就绪的代码之前编写测试。TDD 技术侧重于通过不断重构代码来确保代码通过先前编写的测试，从而编写干净和高质量的代码。

TDD 作为一种先测试的开发方法，更加强调构建经过充分测试的软件应用程序。这使开发人员能够根据在经过深思熟虑后定义的测试任务来编写代码。在 TDD 中，常见的做法是在编写实际应用程序代码之前编写测试代码。

TDD 引入了一个全新的开发范式，并改变了你的思维方式，开始在甚至开始编写代码之前考虑测试你的代码。这与传统的开发技术相反，传统技术将代码测试推迟到开发周期的后期阶段，这种方法被称为**最后测试开发**（**TLD**）。

TDD 已经在多个会议和黑客马拉松上进行了讨论。许多技术倡导者和博客作者都在博客中讨论了 TDD、它的原则和好处。与此同时，也有许多关于 TDD 的演讲和文章。诚实的事实是 TDD 很棒，它有效，当正确和一贯地实践时，它提供了巨大的好处。

你可能会想，就像每个新接触 TDD 的开发人员一样，为什么要先写测试，因为你相信自己的编码直觉可以编写始终有效的干净代码，并且通常在编码完成后会测试整个代码。你的编码直觉可能是正确的，也可能不是。在代码通过一组书面测试用例并通过验证之前，没有办法验证这个假设；信任是好的，但控制更好。

TDD 中的测试用例是通过用户故事或正在开发的软件应用程序的用例来准备的。然后编写代码并进行迭代重构，直到测试通过。例如，编写用于验证信用卡长度的方法可能包含用例来验证正确长度、不正确长度，甚至当空或空信用卡作为参数传递给方法时。

自 TDD 最初被推广以来，已经提出了许多变体。其中一种是**行为驱动开发**（**BDD**）或**验收测试驱动开发**（**ATDD**），它遵循 TDD 的所有原则，而测试是基于预期的用户指定行为。

# TDD 的起源

关于 TDD 实践是何时引入计算机编程或者是哪家公司首先使用的，实际上没有任何书面证据。然而，1957 年 D.D. McCracken 的《数字计算机编程》中有一段摘录，表明 TDD 的概念并不新鲜，早期的人们已经使用过，尽管名称显然不同。

在编码开始之前，可能会对结账问题进行第一次攻击。为了充分确定答案的准确性，有必要准备一个手工计算的检查案例，以便将来与机器计算的答案进行比较。这意味着存储程序机永远不会用于真正的一次性问题。总是必须有迭代的元素来使其付出。

此外，在 1960 年代初，IBM 的人们为 NASA 运行了一个项目（**Project Mecury**），他们利用了类似 TDD 的技术，进行了半天的迭代，并且开发团队对所做的更改进行了审查。这是一个手动过程，无法与我们今天拥有的自动化测试相比。

TDD 最初是由 Kent Beck 推广的。他将其归因于他在一本古老书中读到的一段摘录，其中 TDD 被描述为简单的陈述，*你拿输入磁带，手动输入你期望的输出磁带，然后编程直到实际输出磁带与期望输出相匹配*。当他在 Smalltalk 开发了第一个 xUnit 测试框架时，Kent Beck 重新定义了 TDD 的概念。

可以肯定地说，Smalltalk 社区在 TDD 变得普遍之前就已经使用了 TDD，因为社区中使用了**SUnit**。直到*Kent Beck*和其他爱好者将 SUnit 移植到**JUnit**之后，TDD 才变得广为人知。从那时起，不同的测试框架已经被开发出来。一个流行的工具是**xUnit**，可以为大量编程语言提供端口。

# TDD 的误解

在涉及 TDD 时，开发人员有不同的观点。大多数开发人员抱怨完全实践 TDD 所需的时间和资源，以及实践 TDD 可能不可行，基于紧迫的截止日期和时间表。这种看法在刚刚采用该技术的开发人员中很常见，因为 TDD 需要编写双倍的代码，而这些时间本可以用来开发其他功能，而且 TDD 最适合具有小功能或任务的项目，对于大型项目来说，可能会浪费时间，回报很少。

此外，一些开发人员抱怨模拟可能会使 TDD 变得非常困难和令人沮丧，因为所需的依赖关系不应该在实现依赖代码的同时实现，而应该进行模拟。使用传统的测试最后的方法，可以实现依赖关系，然后可以测试代码的所有不同部分。

另一个常见的误解是，在真正意义上，直到确定设计依赖于代码实现之前，测试才不能被编写。这是不正确的，因为采用 TDD 将确保对代码实现的计划清晰明了，从而产生一个适当的设计，可以帮助编写高效可靠的测试。

有时候，一些人会将 TDD 和单元测试混为一谈，认为它们是一样的。TDD 和单元测试并不相同。单元测试涉及在最小的编码单元或级别上实践 TDD，这是一种方法或函数，而 TDD 是一种技术和设计方法，包括单元测试、集成测试以及验收测试。

刚接触 TDD 的开发人员经常认为在编写实际代码之前必须完全编写测试。事实恰恰相反，因为 TDD 是一种迭代技术。TDD 倾向于探索性过程，你编写测试并编写足够的代码。如果失败，就重构代码直到通过，然后可以继续实现应用程序的下一个功能。

TDD 并不是一个可以自动修复所有糟糕编码行为的灵丹妙药。你可以实践 TDD，但仍然编写糟糕的代码甚至糟糕的测试。如果没有正确使用 TDD 原则和实践，或者试图在不适合使用 TDD 的地方使用 TDD，这是可能的。

# TDD 的好处

TDD，如果正确和适当地完成，可以带来良好的投资回报，因为它有助于开发自测代码，从而产生具有更少或没有错误的健壮软件应用程序。这是因为大部分可能出现在生产中的错误和问题在开发阶段已经被捕捉和修复了。

除了源代码文档，编写测试也是一种良好的编码实践，因为它们作为源代码的微型文档，可以快速理解代码的工作原理。测试将显示预期的输入以及预期的输出或结果。从测试中可以轻松理解应用程序的结构，因为所有对象都将有测试，以及对象方法的测试，显示它们的使用方式。

正确和持续地实践 TDD 有助于编写具有良好抽象、灵活设计和架构的优雅代码。这是因为，为了有效地测试应用程序的所有部分，各种依赖关系需要被分解成可以独立测试的组件，并在集成后进行测试。

代码的清晰性在于使用最佳行业标准编写代码，易于维护，可读性强，并且编写了用于验证其一致行为的测试。这表明没有测试的代码是糟糕的代码，因为没有直接验证其完整性的特定方式。

# 测试的类型

测试软件项目可以采用不同的形式，通常由开发人员和测试分析员或专家进行。测试是为了确定软件是否符合其指定的期望，如果可能的话，识别错误，并验证软件是否可用。大多数程序员通常认为测试和调试是一样的。调试是为了诊断软件中的错误和问题，并采取可能的纠正措施。

# 单元测试

这是测试的一个级别，涉及测试构成软件应用程序组件的每个单元。这是测试的最低级别，它在方法或函数级别进行。它主要由程序员完成，特别是为了显示代码的正确性和要求是否已经正确实现。单元测试通常具有一个或多个输入和输出。

这是通常在软件开发中进行的第一级测试，旨在隔离软件系统的单元并独立或隔离地测试它们。通过单元测试，系统中固有的问题和错误可以在开发过程的早期轻松检测到。

# 集成测试

集成测试是通过组合和测试不同的单元或组件来完成的，这些单元或组件必须在隔离状态下进行测试。这个测试是为了确保应用程序的不同单元可以共同工作以满足用户的需求。通过集成测试，您可以在不同组件交互和交换数据时发现系统中的错误。

这项测试可以由程序员、软件测试人员或质量保证分析员进行。可以使用不同的方法进行集成测试：

+   **自上而下**：在较低级别组件之前，先集成和测试顶层组件

+   **自下而上**：在顶层组件之前，先集成和测试较低级别的组件

+   **大爆炸**：所有组件一起集成并一次性测试

# 系统测试

这个测试级别是您验证整个集成系统以确保其符合指定的用户需求。这个测试通常在集成测试之后立即进行，由专门的测试人员或质量保证分析员进行。

整个软件系统套件是从用户的角度进行测试，以识别隐藏的问题或错误和可用性问题。对实施的系统进行了严格的测试，使用系统应处理的真实输入，并验证输出是否符合预期数据。

# 用户验收测试

用户验收测试通常用于指定软件应用程序的工作方式。这些测试是为业务用户和程序员编写的，用于确定系统是否符合期望和用户特定要求，以及系统是否根据规格完全和正确地开发。这项测试由最终用户与系统开发人员合作进行，以确定是否正式接受系统或进行调整或修改。

# TDD 的原则

TDD 的实践有助于设计清晰的代码，并作为大型代码库中回归的缓冲。它允许开发人员轻松确定新实施的功能是否通过运行测试时获得的即时反馈破坏了先前正常工作的其他功能。TDD 的工作原理如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/8df88590-65cc-4355-8b98-a6d3a80abea2.png)

# 编写测试

这是技术的初始步骤，您必须编写描述要开发的组件或功能的测试。组件可以是用户界面、业务规则或逻辑、数据持久性例程，或实现特定用户需求的方法。测试需要简洁，并应包含组件测试所需的数据输入和期望的预期结果。

在编写测试时，从技术上讲，你已经解决了一半的开发任务，因为通过编写测试来构思代码的设计。在编写的测试之后，更容易处理困难的代码，这就是已经编写的测试。在这一点上，作为 TDD 新手，不要期望测试是 100%完美或具有完整的代码覆盖率，但通过持续的练习和充分的重构，这是可以实现的。

# 编写代码

在编写完测试之后，你应该编写足够的代码来实现之前编写的测试所需的功能。请记住，这里的目标是尽量采用良好的实践和标准来编写代码，以使测试通过。应避免所有导致编写糟糕或糟糕代码的方法。

尽量避免测试过度拟合，即为了使测试通过而编写代码的情况。相反，你应该编写代码来实现功能或用户需求，以确保覆盖功能的每种可能用例，避免代码在测试用例执行和生产环境中执行时具有不同的行为。

# 运行测试

当你确信已经有足够的代码使测试通过时，你应该运行测试，使用你选择的测试套件。此时，测试可能会通过或失败。这取决于你如何编写代码。

TDD 的一个基本规则是多次运行测试，直到测试通过。最初，在代码完全实现之前运行测试时，测试将失败，这是预期的行为。

# 重构

为了实现完整的代码覆盖率，测试和源代码都必须进行重构和多次测试，以确保编写出健壮且干净的代码。重构应该是迭代的，直到实现完整的覆盖率。重构步骤应该删除代码中的重复部分，并尝试修复任何代码异味的迹象。

TDD 的本质是编写干净的代码，从而构建可靠的应用程序，这取决于所编写的测试类型（单元测试、验收测试或集成测试）。重构可以局部地影响一个方法，也可以影响多个类。例如，在重构一个接口或一个类中的多个方法时，建议您逐渐进行更改，一次一个测试，直到所有测试及其实现代码都被重构。

# 以错误的方式进行 TDD

尽管练习 TDD 可能很有趣，但也可能被错误地执行。对于 TDD 新手来说，有时可能会编写过大的怪物测试，这远远超出了测试简洁性和能够快速执行 TDD 循环的目的，导致了生产开发时间的浪费。

部分采用该技术也可能减少 TDD 的全部好处。在团队中只有少数开发人员使用该技术而其他人不使用的情况下，这将导致代码片段化，其中一部分代码经过测试，另一部分没有经过测试，从而导致应用程序不可靠。

应避免为自然微不足道或不需要的代码编写测试；例如，为对象访问器编写测试。测试应该经常运行，特别是通过测试运行器、构建工具或持续集成工具。不经常运行测试可能导致情况，即即使已经进行了更改并且组件可能失败，代码基地的真实状态也不为人所知。

# TDD 循环

TDD 技术遵循一个被称为红-绿-重构循环的原则，红色状态是初始状态，表示 TDD 循环的开始。在红色状态下，测试刚刚被编写，并且在运行时将失败。

下一个状态是绿色状态，它显示在实际应用代码编写后测试已通过。重构代码是确保代码完整性和健壮性的重要步骤。重构将反复进行，直到代码满足性能和需求期望为止。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/ddddbd5c-0bb6-4cba-b577-c1f53eefe39b.png)

在周期开始时，尚未编写用于运行测试的生产代码，因此预计测试将失败。例如，在以下代码片段中，`IsServerOnline`方法尚未实现，当运行`Test_IsServerOnline_ShouldReturnTrue`单元测试方法时，它应该失败。

```cs
public bool IsServerOnline()
{
    return false;
}

 [Fact]
 public void Test_IsServerOnline_ShouldReturnTrue() 
 { 
    bool isOnline=IsServerOnline();   

    Assert.True(isOnline);
 }
```

为了使测试通过，您必须迭代实现生产代码。当实现以下`IsServerOnline`方法时，预期`Test_IsServerOnline_ShouldReturnTrue`测试方法将通过。

```cs
public bool IsServerOnline()
{
    string address="localhost";
    int port=8034;
    SmppManager smppManager= new SmppManager(address, port); 
    bool isOnline=smppManager.TestConnection();
    return isOnline;
}

 [Fact]
 public void Test_IsServerOnline_ShouldReturnTrue() 
 { 
    bool isOnline=IsServerOnline();   

    Assert.True(isOnline);
 }
```

当测试运行并通过时，根据您使用的测试运行器显示绿色，这会立即向您提供有关代码状态的反馈。这让您对代码的正确运行和预期行为感到自信和内心的喜悦。

重构是一个迭代的努力，您将不断修改先前编写的代码以通过测试，直到它达到了生产就绪状态，并且完全实现了需求，并且适用于所有可能的用例和场景。

# 总结

通过本章讨论的原则和编码模式，可以避免大多数潜在的软件项目维护瓶颈。成为专业人士需要保持一致性，要有纪律性，并坚持良好的编码习惯、实践，并对 TDD 持有专业态度。

编写易于维护的清晰代码将在长期内得到回报，因为将需要更少的工作量来进行用户请求的更改，并且当应用程序始终可供使用且几乎没有错误时，用户将感到满意。

在下一章中，我们将探索.NET Core 框架及其能力和局限性。此外，我们将在审查 C#编程语言的第 7 版中介绍的新功能之前，先了解 Microsoft Visual Studio Code。


# 第二章：开始使用.NET Core

当微软发布第一个版本的.NET Framework 时，这是一个创建、运行和部署服务和应用程序的平台，它改变了游戏规则，是微软开发社区的一场革命。使用初始版本的框架开发了几个尖端应用程序，然后发布了几个版本。

多年来，.NET Framework 得到了蓬勃发展和成熟，支持多种编程语言，并包含了多个功能，使得在该平台上编程变得简单而有价值。但是，尽管框架非常强大和吸引人，但限制了开发和部署应用程序只能在微软操作系统变体上进行。

为了为开发人员解决.NET Framework 的限制，创建一个面向云的、跨平台的.NET Framework 实现，微软开始使用.NET Framework 开发.NET Core 平台。随着 2016 年版本 1.0 的推出，.NET 平台的应用程序开发进入了一个新的维度，因为.NET 开发人员现在可以轻松地构建在 Windows、Linux、macOS 和云、嵌入式和物联网设备上运行的应用程序。.NET Core 与.NET Framework、Xamarin 和 Mono 兼容，通过.NET 标准。

本章将介绍.NET Core 和 C# 7 的超酷新跨平台功能。我们将在 Ubuntu Linux 上使用 TDD 创建一个 ASP.NET MVC 应用程序来学习。在本章中，我们将涵盖以下主题：

+   .NET Core 框架

+   .NET Core 应用程序的结构

+   微软的 Visual Studio Code 编辑器之旅

+   C# 7 的新功能一览

+   创建 ASP.NET MVC Core 应用程序

# .NET Core 框架

**.NET Core**是一个跨平台的开源开发框架，可以在 Windows、Linux 和 macOS 上运行，并支持 x86、x64 和 ARM 架构。.NET Core 是从.NET Framework 分叉出来的，从技术上讲，它是后者的一个子集，尽管是简化的、模块化的。.NET Core 是一个开发平台，可以让您在开发和部署应用程序时拥有很大的灵活性。新平台使您摆脱了通常在应用程序部署过程中遇到的麻烦。因此，您不必担心在部署服务器上管理应用程序运行时的版本。

目前，版本 2.0.7 中，.NET Core 包括具有出色性能和许多功能的.NET 运行时。微软声称这是最快的.NET 平台版本。它有更多的 API 和更多的项目模板，比如用于在.NET Core 上运行的 ReactJS 和 AngularJS 应用程序的模板。此外，版本 2.0.7 还有一组命令行工具，使您能够在不同平台上轻松构建和运行命令行应用程序，以及简化的打包和对 Macintosh 上的 Visual Studio 的支持。.NET Core 的一个重要副产品是跨平台模块化 Web 框架 ASP.NET Core，它是 ASP.NET 的全面重新设计，并在.NET Core 上运行。

.NET Framework 非常强大，并包含多个库用于应用程序开发。然而，一些框架的组件和库可能与 Windows 操作系统耦合。例如，`System.Drawing`库依赖于 Windows GDI，这就是为什么.NET Framework 不能被认为是跨平台的，尽管它有不同的实现。

为了使.NET Core 真正跨平台，像 Windows Forms 和**Windows Presentation Foundation**（**WPF**）这样对 Windows 操作系统有很强依赖的组件已经从平台中移除。ASP.NET Web Forms 和**Windows Communication Foundation**（**WCF**）也已被移除，并用 ASP.NET Core MVC 和 ASP.NET Core Web API 替代。此外，**Entity Framework**（**EF**）已经被简化，使其跨平台，并命名为 Entity Framework Core。

此外，由于.NET Framework 对 Windows 操作系统的依赖，微软无法开放源代码。然而，.NET Core 是完全开源的，托管在 GitHub 上，并拥有一个不断努力开发新功能和扩展平台范围的蓬勃发展的开发者社区。

# .NET 标准

**.NET 标准**是微软维护的一组规范和标准，所有.NET 平台都必须遵循和实现。它正式规定了所有.NET 平台变体都应该实现的 API。目前.NET 平台上有三个开发平台—.NET Core、.NET Framework 和 Xamarin。.NET 平台需要提供统一性和一致性，使得在这三个.NET 平台变体上更容易共享代码和重用库。

.NET 平台提供了一组统一的基类库 API 的定义，所有.NET 平台都必须实现，以便开发人员可以轻松地在.NET 平台上开发应用程序和可重用库。目前的版本是 2.0.7，.NET 标准提供了新的 API，这些 API 在.NET Core 1.0 中没有实现，但现在在 2.0 版本中已经实现。超过 20,000 个 API 已经添加到运行时组件中。

此外，.NET 标准是一个目标框架，这意味着你可以开发你的应用程序以针对特定版本的.NET 标准，使得应用程序可以在实现该标准的任何.NET 平台上运行，并且你可以轻松地在不同的.NET 平台之间共享代码、库和二进制文件。当构建应用程序以针对.NET 标准时，你应该知道较高版本的.NET 标准有更多可用的 API，但并不是许多平台都实现了。建议你始终针对较低版本的标准，这将保证它被许多平台实现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/79979ff9-3e9a-489c-ab1d-65ae71a535f1.png)

# .NET 核心组件

.NET Core 作为通用应用程序开发平台，由**CoreCLR**、**CoreFX**、**SDK 和 CLI 工具**、**应用程序主机**和**dotnet 应用程序启动器**组成：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/fa1eaeb2-5f73-4cc8-8f01-bfb2c3b84a79.png)

CoreCLR，也称为.NET Core 运行时，是.NET Core 的核心，是 CLR 的跨平台实现；原始的.NET Framework CLR 已经重构为 CoreCLR。CoreCLR，即公共语言运行时，管理对象的使用和引用，不同编程语言中的对象的通信和交互，并通过在对象不再使用时释放内存来执行垃圾收集。CoreCLR 包括以下内容：

+   垃圾收集器

+   **即时**（**JIT**）编译器

+   本地互操作

+   .NET 基本类型

CoreFX 是.NET Core 的一组框架或基础库，它提供原始数据类型、文件系统、应用程序组合类型、控制台和基本实用工具。CoreFX 包含了一系列精简的类库。

.NET Core SDK 包含一组工具，包括**命令行界面**（**CLI**）工具和编译器，用于构建应用程序和库在.NET Core 上运行。SDK 工具和语言编译器提供功能，通过 CoreFX 库支持的语言组件，使编码更加简单和快速。

为了启动一个.NET Core 应用程序，dotnet 应用程序主机是负责选择和托管应用程序所需运行时的组件。.NET Core 有控制台应用程序作为主要应用程序模型，以及其他应用程序模型，如 ASP.NET Core、Windows 10 通用 Windows 平台和 Xamarin Forms。

# 支持的语言

.NET Core 1.0 仅支持**C#**和**F#**，但随着.NET Core 2.0 的发布，**VB.NET**现在也受到了平台的支持。支持的语言的编译器在.NET Core 上运行，并提供对平台基础功能的访问。这是可能的，因为.NET Core 实现了.NET 标准规范，并公开了.NET Framework 中可用的 API。支持的语言和.NET SDK 工具可以集成到不同的编辑器和 IDE 中，为您提供不同的编辑器选项，用于开发应用程序。

# 何时选择.NET Core 而不是.NET Framework

.NET Core 和.NET Framework 都非常适合用于*开发健壮和可扩展的企业应用程序*；这是因为这两个平台都建立在坚实的代码基础上，并提供了丰富的库和例程，简化了大多数开发任务。这两个平台共享许多相似的组件，因此可以在两个开发平台之间共享代码。然而，这两个平台是不同的，选择.NET Core 作为首选的开发平台应受开发方法以及部署需求和要求的影响。

# 跨平台要求

显然，当您开发的应用程序要在多个平台上运行时，应该使用.NET Core。由于.NET Core 是跨平台的，因此适用于开发可以在**Windows**、**Linux**和**macOS**上运行的服务和 Web 应用程序。此外，微软推出了**Visual Studio Code**，这是一个具有对.NET Core 的全面支持的编辑器，提供智能感知和调试功能，以及传统上仅在**Visual Studio IDE**中可用的其他 IDE 功能。

# 部署的便利性

使用.NET Core，您可以并排安装不同的版本，这是在使用.NET Framework 时不可用的功能。通过.NET Core 的并排安装，可以在单个服务器上安装多个应用程序，使每个应用程序都可以在其自己的.NET Core 版本上运行。最近，人们对容器和应用程序容器化引起了很多关注。容器用于创建软件应用程序的独立包，包括使应用程序在共享操作系统上与其他应用程序隔离运行所需的运行时。当使用.NET Core 作为开发平台时，将.NET 应用程序容器化要好得多。这是因为它具有跨平台支持，从而允许将应用程序部署到不同操作系统的容器中。此外，使用.NET Core 创建的容器映像更小、更轻量。

# 可扩展性和性能

使用.NET Core，开发使用微服务架构的应用程序相对较容易。使用微服务架构，您可以开发使用不同技术混合的应用程序，例如使用 PHP、Java 或 Rails 开发的服务。您可以使用.NET Core 开发微服务，以部署到云平台或容器中。使用.NET Core，您可以开发可扩展的应用程序，可以在高性能计算机或高端服务器上运行，从而使您的应用程序可以轻松为数十万用户提供服务。

# .NET Core 的限制

虽然.NET Core 是强大的、易于使用的，并在应用程序开发中提供了几个好处，但它目前并不适用于所有的开发问题和场景。微软从.NET Framework 中删除了几项技术，以使.NET Core 变得简化和跨平台。因此，这些技术在.NET Core 中不可用。

当您的应用程序将使用.NET Core 中不可用的技术时，例如在表示层使用 WPF 或 Windows Forms，WCF 服务器实现，甚至目前没有.NET Core 版本的第三方库，建议您使用.NET Framework 开发应用程序。

# .NET Core 应用程序的结构

随着.NET Core 2.0 的发布，添加了新的模板，为可以在平台上运行的不同应用程序类型提供了更多选项。除了现有的项目模板之外，还添加了以下**单页应用程序**（**SPA**）模板：

+   角度

+   ReactJS

+   ReactJS 和 Redux

.NET Core 中的控制台应用程序与.NET Framework 具有类似的结构，而 ASP.NET Core 具有一些新组件，包括以前版本的 ASP.NET 中没有的文件夹和文件。

# ASP.NET Core MVC 项目结构

多年来，ASP.NET Web 框架已经完全成熟，从 Web 表单过渡到 MVC 和 Web API。ASP.NET Core 是一个新的 Web 框架，用于开发可以在.NET Core 上运行的 Web 应用程序和 Web API。它是 ASP.NET 的精简和更简化版本，易于部署，并具有内置的依赖注入。ASP.NET Core 可以与 AngularJS、Bootstrap 和 ReactJS 等框架集成。

ASP.NET Core MVC，类似于 ASP.NET MVC，是构建 Web 应用程序和 API 的框架，使用*模型视图控制器模式*。与 ASP.NET MVC 一样，它支持模型绑定和验证，标签助手，并使用*Razor 语法*用于 Razor 页面和 MVC 视图。

ASP.NET Core MVC 应用程序的结构与 ASP.NET MVC 不同，添加了新的文件夹和文件。当您从 Visual Studio 2017，Visual Studio for Mac 或通过解决方案资源管理器中的 CLI 工具创建新的 ASP.NET Core 项目时，您可以看到添加到项目结构的新组件。

# wwwroot 文件夹

在 ASP.NET Core 中，新添加的`wwwroot`文件夹用于保存库和静态内容，例如图像，JavaScript 文件和库，以及 CSS 和 HTML，以便轻松访问并直接提供给 Web 客户端。`wwwroot`文件夹包含`.css`，图像，`.js`和`.lib`文件夹，用于组织站点的静态内容。

# 模型，视图和控制器文件夹

与 ASP.NET MVC 项目类似，ASP.NET MVC 核心应用程序的根文件夹也包含**模型**，**视图**和**控制器**，遵循 MVC 模式的约定，以正确分离 Web 应用程序文件，代码和表示逻辑。

# JSON 文件 - bower.json，appsettings.json，bundleconfig.json

引入的一些其他文件包括`appsettings.json`，其中包含所有应用程序设置，`bower.json`，其中包含用于管理项目中使用的客户端包括 CSS 和 JavaScript 框架的条目，以及`bundleconfig.json`，其中包含用于配置项目的捆绑和最小化的条目。

# Program.cs

与 C#控制台应用程序类似，ASP.NET Core 具有`Program`类，这是一个重要的类，包含应用程序的入口点。该文件具有用于运行应用程序的`Main()`方法，并用于创建`WebHostBuilder`的实例，用于创建应用程序的主机。在`Main`方法中指定要由应用程序使用的`Startup`类：

```cs
 public class Program
 {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .Build();
    }
```

# Startup.cs

ASP.NET Core 应用程序需要`Startup`类来管理应用程序的请求管道，配置服务和进行依赖注入。

不同的`Startup`类可以为不同的环境创建；例如，您可以在应用程序中创建两个`Startup`类，一个用于开发环境，另一个用于生产环境。您还可以指定一个`Startup`类用于所有环境。

`Startup`类有两个方法——`Configure()`，这是必须的，用于确定应用程序如何响应 HTTP 请求，以及`ConfigureServices()`，这是可选的，用于在调用`Configure`方法之前配置服务。这两种方法在应用程序启动时都会被调用：

```cs
 public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }

```

# 微软的 Visual Studio Code 编辑器之旅

开发.NET Core 应用程序变得更加容易，不仅因为平台的流畅性和健壮性，还因为引入了**Visual Studio Code**，这是一个跨平台编辑器，可以在 Windows、Linux 和 macOS 上运行。在创建.NET Core 应用程序之前，您不需要在系统上安装 Visual Studio IDE。

Visual Studio Code 虽然没有 Visual Studio IDE 那么强大和功能丰富，但确实具有内置的生产力工具和功能，使得使用它轻松创建.NET Core 应用程序。您还可以在 Visual Studio Code 中安装用于多种编程语言的扩展，从 Visual Studio Marketplace 中获取，从而可以灵活地编辑其他编程语言编写的代码。

# 在 Linux 上安装.NET Core

为了展示.NET Core 的跨平台功能，让我们在 Ubuntu 17.04 桌面版上设置.NET Core 开发环境。在安装 Visual Studio Code 之前，让我们在**Ubuntu OS**上安装.NET Core。首先，您需要通过在添加 Microsoft 产品 feed 之前注册 Microsoft 签名密钥来进行一次性注册：

1.  启动系统终端并运行以下命令注册微软签名密钥：

```cs
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
```

1.  使用此命令注册 Microsoft 产品 feed：

```cs
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-zesty-prod zesty main" > /etc/apt/sources.list.d/dotnetdev.list
```

1.  要在 Linux 操作系统上安装.NET Core SDK 和其他开发.NET Core 应用程序所需的组件，请运行以下命令：

```cs
sudo apt-get update
sudo apt-get install dotnet-sdk-2.0.0
```

1.  这些命令将更新系统，您应该会看到之前添加的 Microsoft 存储库在 Ubuntu 尝试从中获取更新的存储库列表中。更新后，.NET Core 工具将被下载并安装到系统上。您终端屏幕上显示的信息应该与以下截图中的信息类似：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/3a3748ac-cf5e-4ae0-8041-eadcea29414c.png)

1.  安装完成后，在`Documents`文件夹内创建一个新文件夹，并将其命名为`testapp`。将目录更改为新创建的文件夹，并创建一个新的控制台应用程序来测试安装。请参阅以下命令和命令的结果截图：

```cs
cd /home/user/Documents/testapp
dotnet new console
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b8149bd8-8130-4331-910b-e87bb25ef0c0.png)

1.  您会在终端上看到.NET Core 正在创建项目和所需的文件。项目成功创建后，终端上将显示`Restore succeeded`。在`testapp`文件夹中，框架将添加一个`obj`文件夹，`Program.cs`和`testapp.csproj`文件。

1.  您可以继续使用`dotnet run`命令运行控制台应用程序。该命令将在终端上显示`Hello World!`之前编译和运行项目。

# 在 Linux 上安装和设置 Visual Studio Code

由于 Visual Studio Code 是一个跨平台编辑器，可以安装在许多 Linux OS 的变体上，逐渐添加其他 Linux 发行版的软件包。要在**Ubuntu**上安装 Visual Studio Code，请执行以下步骤：

1.  从[`code.visualstudio.com/download`](https://code.visualstudio.com/)下载适用于 Ubuntu 和 Debian Linux 变体的`.deb`软件包。

1.  从终端安装下载的文件，这将安装编辑器、`apt`存储库和签名密钥，以确保在运行系统更新命令时可以自动更新编辑器：

```cs
sudo dpkg -i <package_name>.deb
sudo apt-get install -f
```

1.  安装成功后，您应该能够启动新安装的 Visual Studio Code 编辑器。该编辑器的外观和感觉与 Visual Studio IDE 略有相似。

# 探索 Visual Studio Code

成功安装 Visual Studio Code 在您的 Ubuntu 实例上后，您需要在开始使用编辑器编写代码之前进行初始环境设置：

1.  从“开始”菜单启动 Visual Studio Code，并从 Visual Studio Marketplace 安装 C#扩展到编辑器。您可以通过按下*Ctrl* + *Shift* + *X*来启动扩展，通过“查看”菜单并单击“扩展”，或直接单击“扩展”选项卡；这将加载一个可用扩展的列表，因此单击并安装 C#扩展。

1.  安装扩展后，单击“重新加载”按钮以在编辑器中激活 C#扩展：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/4756b0c5-1806-4efb-a83a-79512ae250c5.png)

1.  打开您之前创建的控制台应用程序的文件夹；要做到这一点，单击“文件”菜单并选择“打开文件夹”，或按下*Ctrl* + *K*，*Ctrl* + *O.* 这将打开文件管理器；浏览到文件夹的路径并单击打开。这将在 Visual Studio Code 中加载项目的内容。在后台，Visual Studio Code 将尝试下载 Linux 平台所需的依赖项，包括 Linux 的 Omnisharp 和.NET Core 调试器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/fc691b0d-0075-472a-aa73-f1d3c45d5634.png)

1.  要创建一个新项目，您可以使用编辑器的集成终端，而无需通过系统终端。单击“查看”菜单，然后选择“集成终端”。这将在编辑器中打开终端选项卡，您可以在其中输入命令来创建新项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/fe857388-8cc6-41cf-ba2b-a016c8f76981.png)

1.  在打开的项目中，您将看到一个通知，需要构建和调试应用程序所需的资源缺失。如果单击“是”，在资源管理器选项卡中，您可以看到一个`.vscode`树，其中添加了`launch.json`和`tasks.json`文件。单击`Program.cs`文件以将文件加载到编辑器中。从“调试”菜单中选择“开始调试”，或按下*F5*运行应用程序；您应该在编辑器的调试控制台上看到`Hello World!`的显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/0e38a634-11cd-4c49-b6e4-d3241bbb1b12.png)

当您启动 Visual Studio Code 时，它会加载上次关闭时的状态，打开您上次访问的文件和文件夹。编辑器的布局易于导航和使用，并带有诸如：

+   状态栏显示您当前打开文件的信息。

+   活动栏提供了访问资源管理器视图以查看项目文件夹和文件，以及源代码控制视图以管理项目的源代码版本控制。调试视图用于查看变量、断点和与调试相关的活动，搜索视图允许您搜索文件夹和文件。扩展视图允许您查看可以安装到编辑器中的可用扩展。

+   编辑区用于编辑项目文件，允许您同时打开最多三个文件进行编辑。

+   面板区域显示不同的面板，用于输出、调试控制台、终端和问题：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/2d24345d-99b6-4fbd-9ae5-864b36bc6da1.png)

# 查看 C# 7 的新功能

多年来，C#编程语言已经成熟；随着每个版本的发布，越来越多的语言特性和构造被添加进来。这门语言最初只是由微软内部开发，并且只能在 Windows 操作系统上运行，现在已经成为开源和跨平台。这是通过.NET Core 和语言的 7 版（7.0 和 7.1）实现的，它增加了语言的特色并改进了可用的功能。特别是语言的 7.2 版和 8.0 版的路线图承诺为语言增加更多功能。

# 元组增强

**元组**在 C#语言中的第 4 版中引入，并以简化形式使用，以提供具有两个或更多数据元素的结构，允许您创建可以返回两个或更多数据元素的方法。在 C# 7 之前，引用元组的元素是通过使用*Item1，Item2，...ItemN*来完成的，其中*N*是元组结构中元素的数量。从 C# 7 开始，元组现在支持包含字段的语义命名，引入了更清晰和更有效的创建和使用元组的方法。

您现在可以通过直接为每个成员分配一个值来创建元组。此赋值将创建一个包含元素*Item1*，*Item2*的元组：

```cs
var names = ("John", "Doe");
```

您还可以创建具有元组中包含的元素的语义名称的元组：

```cs
(string firstName, string lastName) names = ("John", "Doe");
```

元组的名称，而不是具有*Item1*，*Item2*等字段，将在编译时具有可以作为`firstName`和`lastName`引用的字段。

当使用 POCO 可能过于繁琐时，您可以创建自己的方法来返回具有两个或更多数据元素的元组：

```cs
private (string, string) GetNames()
{
    (string firstName, string lastName) names = ("John", "Doe");
    return names;
}
```

# Out 关键字

在 C#中，参数可以按引用或值传递。当您通过引用将参数传递给方法、属性或构造函数时，参数的值将被更改，并且在方法或构造函数超出范围时所做的更改将被保留。使用`out`关键字，您可以在 C#中将方法的参数作为引用传递。在 C# 7 之前，要使用`out`关键字，您必须在将其作为`out`参数传递给方法之前声明一个变量：

```cs
class Program
{
    static void Main(string[] args)
    {
        string firstName, lastName;
        GetNames(out firstName, out lastName);
    }
    private static void GetNames(out string firstName, out string lastName)
    {
        firstName="John";
        lastName="Doe";
    }
}
```

在 C# 7 中，您现在可以将 out 变量传递给方法，而无需先声明变量，前面的代码片段现在看起来像以下内容，这样可以防止您在分配或初始化变量之前错误地使用变量，并使代码更加清晰：

```cs
class Program
{
    static void Main(string[] args)
    {
        GetNames(out string firstName, out string lastName);
    }
    private static void GetNames(out string firstName, out string lastName)
    {
        firstName="John";
        lastName="Doe";
    }
}
```

语言中已添加了对隐式类型输出变量的支持，允许编译器推断变量的类型：

```cs
class Program
{
    static void Main(string[] args)
    {
        GetNames(out var firstName, out var lastName);
    }
    private static void GetNames(out string firstName, out string lastName)
    {
        firstName="John";
        lastName="Doe";
    }
}
```

# Ref 局部变量和返回

C#语言一直有`ref`关键字，允许您使用并返回对其他地方定义的变量的引用。C# 7 添加了另一个功能，`ref`局部变量和`returns`，它提高了性能，并允许您声明在较早版本的语言中不可能的辅助方法。`ref`局部变量和`returns`关键字有一些限制——您不能在`async`方法中使用它们，也不能返回具有相同执行范围的变量的引用。

# Ref 局部变量

`ref`局部关键字允许您通过使用`ref`关键字声明局部变量来存储引用，并在方法调用或赋值之前添加`ref`关键字。例如，在以下代码中，`day`字符串变量引用`dayOfWeek`；更改`day`的值也会更改`dayOfWeek`的值，反之亦然：

```cs
string dayOfWeek = "Sunday";
ref string day = ref dayOfWeek;
Console.WriteLine($"day-{day}, dayOfWeek-{dayOfWeek}");
day = "Monday";
Console.WriteLine($"day-{day}, dayOfWeek-{dayOfWeek}");
dayOfWeek = "Tuesday";
Console.WriteLine($"day-{day}, dayOfWeek-{dayOfWeek}");

-----------------
Output:

day: Sunday
dayOfWeek:  Sunday

day: Monday
dayOfWeek:  Monday

day: Tuesday
dayOfWeek:  Tuesday
```

# Ref 返回

您还可以将`ref`关键字用作方法的返回类型。要实现这一点，将`ref`关键字添加到方法签名中，并在方法体内，在`return`关键字之后添加`ref`。在以下代码片段中，声明并初始化了一个字符串数组。然后，该方法将字符串数组的第五个元素作为引用返回：

```cs
public ref string GetFifthDayOfWeek()
{
    string [] daysOfWeek= new string [7] {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"};
    return ref daysOfWeek[4];
}
```

# 局部函数

**局部**或**嵌套函数**允许您在另一个函数内定义一个函数。这个特性在一些编程语言中已经有很多年了，但是在 C# 7 中才刚刚引入。当您需要一个小型且在`container`方法的上下文之外不可重用的函数时，这是一个理想的选择：

```cs
class Program
{
    static void Main(string[] args)
    {
        GetNames(out var firstName, out var lastName); 

        void GetNames(out string firstName, out string lastName)
        {
            firstName="John";
            lastName="Doe";
        }
    }
}
```

# 模式匹配

C# 7 包括模式，这是一种语言元素特性，允许您在除了对象类型之外的属性上执行方法分派。它扩展了已经在覆盖和虚拟方法中实现的语言构造，用于实现类型和数据元素的分派。在语言的 7.0 版本中，`is`和`switch`表达式已经更新以支持**模式匹配**，因此您现在可以使用这些表达式来确定感兴趣的对象是否具有特定模式。

使用`is`模式表达式，您现在可以编写包含处理不相关类型元素的算法例程的代码。`is`表达式现在可以与模式一起使用，除了能够测试类型之外。

引入的模式匹配可以采用三种形式：

+   **类型模式**：这涉及检查对象是否是某种类型，然后将对象的值提取到表达式中定义的新变量中：

```cs
public void ProcessLoan(Loan loan)
{
    if(loan is CarLoan carLoan)
    {
        // do something
    }
}
```

+   **Var 模式**：创建一个与对象相同类型的新变量并赋值：

```cs
public void ProcessLoan(Loan loan)
{
    if(loan is var carLoan)
    {
        // do something
    }
}
```

+   常量模式：检查提供的对象是否等同于一个常量表达式：

```cs
public void ProcessLoan(Loan loan)
{
    if(loan is null)
    {
        // do something
    }
}
```

通过更新的 switch 表达式，您现在可以在 case 语句中使用模式和条件，并且可以在除了基本或原始类型之外的任何类型上进行 switch，同时允许您使用 when 关键字来额外指定模式的规则：

```cs
public void ProcessLoan(Loan loan)
{
    switch(loan)
    {
        case CarLoan carLoan:
            // do something
            break;
        case HouseLoan houseLoan when (houseLoan.IsElligible==true):
            //do something
            break;
        case null:
            //throw some custom exception
            break;
        default:
            // do something       
    }
}
```

# 数字分隔符和二进制字面量

在 C# 7 中添加了一种新的语法糖，即**数字分隔符**。这种构造极大地提高了代码的可读性，特别是在处理 C#支持的不同数值类型的大量数字时。在 C# 7 之前，操作大数值以添加分隔符有点混乱和难以阅读。引入数字分隔符后，您现在可以使用下划线（`_`）作为数字的分隔符：

```cs
var longDigit = 2_300_400_500_78;
```

在这个版本中还新增了**二进制字面量**。现在可以通过简单地在二进制值前加上`0b`来创建二进制字面量：

```cs
var binaryValue = 0b11101011;
```

# 创建一个 ASP.NET MVC Core 应用程序

ASP.NET Core 提供了一种优雅的方式来构建在 Windows、Linux 和 macOS 上运行的 Web 应用程序和 API，这要归功于.NET Core 平台的工具和 SDK，这些工具和 SDK 简化了开发尖端应用程序并支持应用程序版本的并行。使用 ASP.NET Core，您的应用程序的表面积更小，这可以提高性能，因为您只需要包含运行应用程序所需的 NuGet 包。ASP.NET Core 还可以与客户端库和框架集成，允许您使用您已经熟悉的 CSS 和 JS 库来开发 Web 应用程序。

ASP.NET Core 使用 Kestrel 运行，Kestrel 是包含在 ASP.NET Core 项目模板中的 Web 服务器。Kestrel 是一个基于**libuv**的进程内跨平台 HTTP 服务器实现，libuv 是一个跨平台的异步 I/O 库，使构建和调试 ASP.NET Core 应用程序变得更加容易。它监听 HTTP 请求，然后将请求的详细信息和特性打包到一个`HttpContext`对象中。Kestrel 可以作为独立的 Web 服务器使用，也可以与 IIS 或 Apache Web 服务器一起使用，其他 Web 服务器接收到的请求将被转发到 Kestrel，这个概念被称为反向代理。

**ASP.NET MVC Core**为您提供了一个可测试的框架，用于使用*Model View Controller*模式进行现代 Web 应用程序开发，这使您可以充分实践测试驱动开发。在 ASP.NET 2.0 中新增的是对 Razor 页面的支持，这现在是开发 ASP.NET Core Web 应用程序用户界面的推荐方法。

要创建一个新的 ASP.NET MVC Core 项目：

1.  打开 Visual Studio Code，并通过选择“视图”菜单中的“集成终端”来访问集成终端面板。在终端上，运行以下命令：

```cs
cd /home/<user>/Documents/
mkdir LoanApp
cd LoanApp
dotnet new mvc
```

1.  创建应用程序后，使用 Visual Studio Code 打开项目文件夹，并选择`Startup.cs`文件。您应该注意到屏幕顶部的通知，提示“从'LoanApp'缺少构建和调试所需的资产。是否添加？”，选择是：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/b461a4e5-e5e9-4e40-8d1f-91b0d0b99697.png)

1.  按下*F5*键来构建和运行 MVC 应用程序。这告诉 Kestrel web 服务器运行该应用程序，并在计算机上启动默认浏览器，地址为`http://localhost:5000`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dncore-tdd/img/5859d47a-a4f2-4833-96ea-d321ad99d212.png)

# 摘要

.NET Core 平台虽然新，但正在迅速成熟，2.0.7 版本引入了许多功能和增强功能，简化了构建不同类型的跨平台应用程序。在本章中，我们已经对平台进行了介绍，介绍了 C# 7 的新功能，并在 Ubuntu Linux 上设置了开发环境，同时创建了我们的第一个 ASP.NET MVC Core 应用程序。

在下一章中，我们将解释要注意避免编写不可测试代码，并且我们将带领您了解可以帮助您编写可测试和高质量代码的 SOLID 原则。


# 第三章：编写可测试的代码

在第一章中，*探索测试驱动开发*，解释了编写代码以防止代码异味的陷阱。编写良好的代码本身就是一种艺术，而编写可以有效测试的代码的过程需要开发人员额外的努力和承诺，以编写可以反复测试而不费吹灰之力的干净代码。

练习 TDD 可以提高代码生产效率，鼓励编写健壮且易于维护的良好代码是事实。然而，如果参与软件项目的开发人员编写不可测试的代码，那么花在 TDD 上的时间可能是浪费的，该技术的投资回报可能无法实现。这通常可以追溯到使用糟糕的代码设计架构，以及未充分或有效地使用面向对象设计原则。

编写测试和编写主要代码一样重要。为不可测试的代码编写测试非常累人且非常困难，这就是为什么首先应该避免不可测试的代码的原因。代码之所以不可测试，可能有不同的原因，比如代码做得太多（**怪兽代码**），违反了单一职责原则，架构使用错误，或者面向对象设计有缺陷。

在本章中，我们将涵盖以下主题：

+   编写不可测试代码的警告信号

+   迪米特法则

+   SOLID 架构原则

+   为 ASP.NET Core MVC 设置 DI 容器

# 编写不可测试代码的警告信号

有效和持续的 TDD 实践可以改善编写代码的过程，使测试变得更容易，从而提高代码质量和软件应用的健壮性。然而，当项目的代码库包含不可测试的代码部分时，编写单元测试或集成测试变得极其困难，甚至几乎不可能。

当软件项目的代码库中存在不可测试的代码时，软件开发团队无法明确验证应用程序功能和特性的一致行为。为了避免这种可预防的情况，编写可测试的代码不是一个选择，而是每个重视质量软件的严肃开发团队的必须。

不可测试的代码是由于违反了已被证明和测试可以提高代码质量的常见标准、实践和原则而产生的。虽然专业素养随着良好实践和经验的反复使用而来，但有一些常见的糟糕代码设计和编写方法即使对于初学者来说也是常识，比如在不需要时使用全局变量、代码的紧耦合、硬编码依赖关系或可能在代码中发生变化的值。

在本节中，我们将讨论一些常见的反模式和陷阱，当编写代码时应该注意，因为它们可能会使为生产代码编写测试变得困难。

# 紧耦合

**耦合**是对象相互依赖或密切相关的程度。进一步解释，当`LoanProcessor`类与`EligibilityChecker`紧密耦合时，更改后者可能会影响前者的行为或修改其状态。

大多数不可测试的代码通常是由于不同部分的代码中存在的固有依赖关系造成的，通常是通过使用依赖关系的具体实现，导致了本应在应用程序边界上分离的关注点混合在一起。

具有紧密耦合依赖关系的单元测试代码将导致测试紧密耦合的不同对象。在单元测试期间，应该在构造函数中注入的依赖关系理想情况下应该很容易模拟，但这将是不可能的。这通常会减慢整体测试过程，因为所有依赖关系都必须在受测试的代码中构建。

在以下代码片段中，`LoanProcessor` 与 `EligibilityChecker` 紧密耦合。这是因为 `EligibilityChecker` 在 `LoanProcessor` 构造函数中使用了 new 关键字进行实例化。对 `EligibilityChecker` 的更改将影响 `LoanProcessor`，可能导致其出现故障。此外，对 `LoanProcessor` 中包含的任何方法进行单元测试都将导致 `EligibilityChecker` 被构造：

```cs
public class LoanProcessor
{
    private EligibilityChecker eligibilityChecker;

    public LoanProcessor()
    {
       eligibilityChecker= new EligibilityChecker();
    }        

    public void ProcessCustomerLoan(Loan loan)
    {
       throw new NotImplementedException();
    }    
}
```

解决 `LoanProcessor` 中紧密耦合的一种方法是使用**依赖注入**（**DI**）。由于 `LoanProcessor` 无法在隔离环境中进行测试，因为 `EligibilityChecker` 对象将必须在构造函数中实例化，所以可以通过构造函数将 `EligibilityChecker` 注入到 `LoanProcessor` 中：

```cs
public class LoanProcessor
{
    private EligibilityChecker eligibilityChecker;

    public LoanProcessor(EligibilityChecker eligibilityChecker)
    {
       this.eligibilityChecker= eligibilityChecker;
    }        

    public void ProcessCustomerLoan(Loan loan)
    {
       bool isEligible=eligibilityChecker.CheckLoan(loan);
       throw new NotImplementedException();
    }    
}
```

通过注入 `EligibilityChecker`，测试 `LoanProcessor` 变得更容易，因为这使您可以编写一个测试，其中模拟 `EligibilityChecker` 的实现，从而允许您在隔离环境中测试 `LoanProcessor`。

另外，可以通过 `LoanProcessor` 类的属性或成员注入 `EligibilityChecker`，而不是通过 `LoanProcessor` 构造函数传递依赖项：

```cs
public class LoanProcessor
{
    private EligibilityChecker eligibilityChecker;

    public EligibilityChecker EligibilityCheckerObject 
    {
        set { eligibilityChecker = value; }
    }     

    public void ProcessCustomerLoan(Loan loan)
    {
       bool isEligible=eligibilityChecker.CheckLoan(eligibilityChecker);
       throw new NotImplementedException();
    }    
}
```

通过构造函数或属性注入依赖后，`LoanProcessor` 和 `EligibilityChecker` 现在变得松散耦合，从而使得编写单元测试和模拟 `EligibilityChecker` 变得容易。

要使类松散耦合且可测试，必须确保该类不实例化其他类和对象。在类的构造函数或方法中实例化对象可能会导致无法注入模拟或虚拟对象，从而使代码无法进行测试。

# 怪物构造函数

要测试一个方法，您必须实例化或构造包含该方法的类。开发人员最常见的错误之一是创建我所谓的**怪物构造函数**，它只是一个做了太多工作或真正工作的构造函数，比如执行 I/O 操作、数据库调用、静态初始化、读取一些大文件或与外部服务建立通信。

当一个类设计有一个构造函数，用于初始化或实例化除值对象（列表、数组和字典）之外的对象时，该类在技术上具有非灵活的结构。这是糟糕的类设计，因为该类自动与其实例化的类紧密耦合，使得单元测试变得困难。具有这种设计的任何类也违反了单一责任原则，因为对象图的创建是可以委托给另一个类的责任。

在具有做大量工作的构造函数的类中测试方法会带来巨大的成本。实质上，要测试具有上述设计的类中的方法，您被迫要经历在构造函数中创建依赖对象的痛苦。如果依赖对象在构造时进行数据库调用，那么每次测试该类中的方法时，这个调用都会被重复，使得测试变得缓慢和痛苦：

```cs
public class LoanProcessor
{
    private EligibilityChecker eligibilityChecker;
    private CurrencyConverter currencyConverter;

    public LoanProcessor()
    {
       eligibilityChecker= new EligibilityChecker();
       currencyConverter = new CurrencyConverter();
       currencyConverter.DownloadCurrentRates();
       eligibilityChecker.CurrentRates= currencyConverter.Rates;
    }
}
```

在上述代码片段中，对象图的构建是在 `LoanProcessor` 构造函数中完成的，这肯定会使得该类难以测试。最好的做法是拥有一个精简的构造函数，它做很少的工作，并且对其他对象的了解很少，特别是它们能做什么，但不知道它们是如何做到的。

有时开发人员使用一种测试技巧，即为一个类创建多个构造函数。其中一个构造函数将被指定为仅用于测试的构造函数。虽然使用这种方法可以使类在隔离环境中进行测试，但也存在不好的一面。例如，使用多个构造函数创建的类可能会被其他类引用，并使用做大量工作的构造函数进行实例化。这可能会使得测试这些依赖类变得非常困难。

以下代码片段说明了为了测试类而创建单独构造函数的糟糕设计：

```cs
public class LoanProcessor
{
    private EligibilityChecker eligibilityChecker;
    private CurrencyConverter currencyConverter;

    public LoanProcessor()
    {
       eligibilityChecker= new EligibilityChecker();
       currencyConverter = new CurrencyConverter();
       currencyConverter.DownloadCurrentRates();
       eligibilityChecker.CurrentRates= currencyConverter.Rates;
    } 

    // constructor for testing
    public LoanProcessor(EligibilityChecker eligibilityChecker,CurrencyConverter currencyConverter)
    {
       this.eligibilityChecker= eligibilityChecker;
       this.currencyConverter = currencyConverter;
    }
}
```

有一些重要的警告信号可以帮助您设计一个构造函数工作量较小的松散耦合类。避免在构造函数中使用`new`操作符，以允许注入依赖对象。您应该初始化并分配通过构造函数注入的所有对象到适当的字段中。轻量级值对象的实例化也应该在构造函数中完成。

此外，应避免静态方法调用，因为静态调用无法被注入或模拟。此外，应避免在构造函数中使用迭代或条件逻辑；每次测试类时，逻辑或循环都将被执行，导致过多的开销。

在设计类时要考虑测试，不要在构造函数中创建依赖对象或协作者。当您的类需要依赖其他类时，请注入依赖项。确保只创建值对象。在代码中创建对象图时，使用*工厂方法*来实现。工厂方法用于创建对象。

# 具有多个责任的类

理想情况下，一个类应该只有一个责任。当您设计的类具有多个责任时，可能会在类之间产生交互，使得代码修改变得困难，并且几乎不可能对交互进行隔离测试。

有一些指标可以清楚地表明一个类做了太多事情并且具有多个责任。例如，当您在为一个类命名时感到困难，最终可能会在类名中使用`and`这个词，这表明该类做了太多事情。

一个具有多个责任的类的另一个标志是，类中的字段仅在某些方法中使用，或者类具有仅对参数而不是类字段进行操作的静态方法。此外，当一个类具有长列表的字段或方法以及许多依赖对象传递到类构造函数中时，表示该类做了太多事情。

在以下片段中，`LoanProcessor`类的依赖项已经整洁地注入到构造函数中，使其与依赖项松散耦合。然而，该类有多个改变的原因；该类既包含用于数据检索的代码，又包含业务规则处理的代码：

```cs
public class LoanProcessor
{
    private EligibilityChecker eligibilityChecker;
    private DbContext dbContext;

    public LoanProcessor(EligibilityChecker eligibilityChecker, DbContext dbContext)
    {
       this.eligibilityChecker= eligibilityChecker;
       this.dbContext= dbContext;
    }

    public double CalculateCarLoanRate(Loan loan)
    {
        double rate=12.5F;
        bool isEligible=eligibilityChecker.IsApplicantEligible(loan);
        if(isEligible)
          rate=rate-loan.DiscountFactor; 
        return rate;
    }

    public List<CarLoan> GetCarLoans()
    {
        return dbContext.CarLoan;
    }          
}
```

为了使类易于维护并且易于测试，`GetCarLoans`方法不应该在`LoanProcessor`中。应该将`LoanProcessor`与`GetCarLoans`一起重构到数据访问层类中。

具有本节描述的特征的类可能很难进行调试和测试。新团队成员可能很难快速理解类的内部工作原理。如果您的代码库中有具有这些属性的类，建议通过识别责任并将其分离到不同的类中，并根据其责任命名类来进行重构。

# 静态对象

在代码中使用**静态变量**、**方法**和**对象**可能是有用的，因为这些允许对象在所有实例中具有相同的值，因为只创建了一个对象的副本并放入内存中。然而，测试包含静态内容的代码，特别是静态方法的代码，可能会产生测试问题，因为您无法在子类中覆盖静态方法，并且使用模拟框架来模拟静态方法是一项非常艰巨的任务：

```cs
public static class LoanProcessor
{
    private static EligibilityChecker eligibilityChecker= new EligibilityChecker();

    public static double CalculateCarLoanRate(Loan loan)
    {
        double rate=12.5F;
        bool isEligible=eligibilityChecker.IsApplicantEligible(loan);
        if(isEligible)
          rate=rate-loan.DiscountFactor; 
        return rate;
    }     
}
```

当您创建维护状态的静态方法时，例如在前面片段中的`LoanProcessor`中的`CalculateCarLoanRate`方法，静态方法无法通过多态进行子类化或扩展。此外，静态方法无法使用接口进行定义，因此使得模拟变得不可能，因为大多数模拟框架都有效地使用接口。

# 迪米特法则

软件应用程序是由不同组件组成的复杂系统，这些组件进行通信以实现解决现实生活问题和业务流程自动化的整体目的。实际上，这些组件必须共存、互动，并在组件边界之间共享信息，而不会混淆不同的关注点，以促进组件的可重用性和整体系统的灵活性。

在软件编程中，技术上没有严格遵循的硬性法律。然而，已经制定了各种原则和法律，作为指导方针，可以帮助软件开发人员和从业者，促进构建具有高内聚性和松耦合性的组件的软件应用程序，以充分封装数据，并确保产生易于理解和扩展的高质量源代码，从而降低软件的维护成本。其中之一就是**迪米特法则**（**LoD**）。

LoD，也称为**最少知识原则**，是开发面向对象软件应用程序的重要设计方法或规则。该规则于 1987 年由 Ian Holland 在东北大学制定。通过正确理解这一原则，软件开发人员可以编写易于测试的代码，并构建具有更少或没有错误的软件应用程序。该法则的制定是：

+   每个单元只应对当前单元“密切”相关的单元有限了解。

+   每个单元只能与其朋友交谈；不要与陌生人交谈。

LoD 强调低耦合，这实际上意味着一个对象对另一个对象的了解应该很少或非常有限。将 LoD 与典型的类对象联系起来，类中的方法只应对密切相关对象的其他方法有限了解。

LoD 作为软件开发人员的启发式，以促进软件模块和组件中的信息隐藏。LoD 有两种形式——**对象或动态形式**和**类或静态形式**。

LoD 的类形式被公式化为：

**类**（**C**）的**方法**（**M**）只能向以下类的对象发送消息：

+   M 的参数类，包括 C

+   C 的实例变量

+   在 M 中创建的实例的类

+   C 的属性或字段

LoD 的对象形式被公式化为：

在 M 中，消息只能发送到以下对象：

+   M 的参数，包括封闭对象。

+   M 调用封闭对象返回的即时部分对象，包括封闭对象的属性，或者封闭对象的属性集合的元素：

```cs
public class LoanProcessor
{
    private CurrencyConverter currencyConverter;

    public LoanProcessor(LoanCalculator loanCalculator)
    {
       currencyConverter = loanCalculator.GetCurrencyConverter();
    }
}
```

前面的代码明显违反了 LoD，这是因为`LoanProcessor`实际上并不关心`LoanCalculator`，因为它没有保留任何对它的引用。在代码中，`LoanProcessor`已经在与`LoanCalculator`进行交流，一个陌生人。这段代码实际上并不可重用，因为任何试图重用它们的类或代码都将需要`CurrencyConverter`和`LoanProcessor`，尽管从技术上讲，`LoanCalculator`在构造函数之外并未被使用。

为了对`LoanProcessor`编写单元测试，需要创建对象图。必须创建`LoanCalculator`以便`CurrencyConverter`可用。这会在系统中创建耦合，如果`LoanCalculator`被重构，这是可能的，那么可能会导致`LoanProcessor`出现故障，导致单元测试停止运行。

`LoanCalculator`类可以被模拟，以便单独测试`LoanProcessor`，但这有时会使测试变得难以阅读，最好避免耦合，这样可以编写灵活且易于测试的代码。

要重构前面的代码片段，并使其符合 LoD 并从类构造函数中获取其依赖项，从而消除对`LoanCalculator`的额外依赖，并减少代码的耦合：

```cs
public class LoanProcessor
{
    private CurrencyConverter currencyConverter;

    public LoanProcessor(CurrencyConverter currencyConverter)
    {
       this.currencyConverter = currencyConverter;
    }     
}
```

# 火车失事

另一个违反 LoD 的反模式是所谓的**火车失事**或**链式调用**。这是一系列函数的链，并且当你在一行代码中追加了一系列 C#方法时就会发生。当你花时间试图弄清楚一行代码的作用时，你就会知道你写了一个火车失事的代码：

```cs
loanCalculator.
    CalculateHouseLoan(loanDTO).
        GetPaymentRate().
            GetMaximumYearsToPay();
```

你可能想知道这种现象如何违反了 LoD。首先，代码缺乏可读性，不易维护。此外，代码行不可重用，因为一行代码中有三个方法调用。

这行代码可以通过减少交互和消除方法链来进行重构，以使其符合“不要和陌生人说话”的原则。这个原则解释了调用点或方法应该一次只与一个对象交互。通过消除方法链，生成的代码可以在其他地方重复使用，而不必费力理解代码的作用：

```cs
var houseLoan=loanCalculator.CalculateHouseLoan(loanDTO);
var paymentRate=houseLoan.GetPaymentRate();
var maximumYears=paymentRate.GetMaximumYearsToPay();
```

一个对象应该对其他对象的知识和信息有限。此外，对象中的方法应该对应用程序的对象图具有很少的认识。通过有意识的努力，使用 LoD，你可以构建松散耦合且易于维护的软件应用程序。

# SOLID 架构原则

软件应用程序开发的程序和方法，从第一步到最后一步，应该简单易懂，无论是新手还是专家都能理解。这些程序，当与正确的原则结合使用时，使开发和维护软件应用程序的过程变得简单和无缝。

开发人员不时采用和使用不同的开发原则和模式，以简化复杂性并使软件应用程序代码库易于维护。其中一个原则就是 SOLID 原则。这个原则已经被证明非常有用，是每个面向对象系统的严肃程序员必须了解的。

SOLID 是开发面向对象系统的五个基本原则的首字母缩写。这五个原则是用于类设计的，表示为：

+   **S**：单一职责原则

+   **O**：开闭原则

+   **L**：里氏替换原则

+   **I**：接口隔离原则

+   **D**：依赖反转原则

这些原则首次被整合成 SOLID 的首字母缩写，并在 2000 年代初由*罗伯特·C·马丁*（通常被称为**鲍勃叔叔**）推广。这五个原则是用于类设计的，遵守这些原则可以帮助管理依赖关系，避免创建混乱的、到处都是依赖的僵化代码库。

对 SOLID 原则的正确理解和运用可以使软件开发人员实现非常高的内聚度，并编写易于理解和维护的高质量代码。有了 SOLID 原则，你可以编写干净的代码，构建健壮且可扩展的软件应用程序。

事实上，鲍勃叔叔澄清了 SOLID 原则不是法律或规则，而是已经观察到在几种情况下起作用的启发式。要有效地使用这些原则，你必须搜索你的代码，检查违反原则的部分，然后进行重构。

# 单一职责原则

**单一职责原则**（**SRP**）是五个 SOLID 原则中的第一个。该原则规定一个类在任何时候只能有一个改变的理由。这简单地意味着一个类一次只能执行一个职责或有一个责任。

软件项目的业务需求通常不是固定的。在软件项目发布之前，甚至在软件的整个生命周期中，需求会不时地发生变化，开发人员必须根据变化调整代码库。为了使软件应用程序满足其业务需求并适应变化，必须使用灵活的设计模式，并且类始终只有一个责任。

此外，重要的是要理解，当一个类有多个责任时，即使进行最微小的更改也会对整个代码库产生巨大影响。对类的更改可能会导致连锁反应，导致之前工作的功能或其他方法出现故障。例如，如果你有一个解析`.csv`文件的类，同时它还调用一个 Web 服务来检索与`.csv`文件解析无关的信息，那么这个类就有多个改变的原因。对 Web 服务调用的更改将影响该类，尽管这些更改与`.csv`文件解析无关。

以下代码片段中的`LoanCalculator`类的设计明显违反了 SRP。`LoanCalculator`有两个责任——第一个是计算房屋和汽车贷款，第二个是从 XML 文件和 XML 字符串中解析贷款利率：

```cs
public class LoanCalculator
{
    public CarLoan CalculateCarLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();
    }

    public HouseLoan CalculateHouseLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();
    }

    public List<Rate> ParseRatesFromXmlString(string xmlString)
    {
        throw new NotImplementedException();
    }

    public List<Rate> ParseRatesFromXmlFile(string xmlFile)
    {
        throw new NotImplementedException();
    }
}
```

`LoanCalculator`类的双重责任状态会产生一些问题。首先，该类变得非常不稳定，因为对一个责任的更改可能会影响另一个责任。例如，对要解析的 XML 内容结构的更改可能需要重写、测试和重新部署该类；尽管如此，对第二个关注点——贷款计算——并没有进行更改。

`LoanCalculator`类中的混乱代码可以通过重新设计类并分离责任来修复。新设计将是将 XML 利率解析的责任移交给一个新的`RateParser`类，并将贷款计算的关注点留在现有类中：

```cs
public class RateParser : IRateParser
{    
    public List<Rate> ParseRatesFromXml(string xmlString)
    {
        throw new NotImplementedException();
    }
    public List<Rate> ParseRatesFromXmlFile(string xmlFile)
    {
        throw new NotImplementedException();
    }
}
```

通过从`LoanCalculator`中提取`RateParser`类，`RateParser`现在可以作为`LoanCalculator`中的一个依赖使用。对`RateParser`中的任何方法的更改不会影响`LoanCalculator`，因为它们现在处理不同的关注点，每个类只有一个改变的原因：

```cs
public class LoanCalculator
{
    private IRateParser rateParser;

    public LoanCalculator(IRateParser rateParser)
    {
        this.rateParser=rateParser;
    }

    public CarLoan CalculateCarLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();
    }

    public HouseLoan CalculateCarLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();
    }  
}
```

将关注点分开在代码库中创造了很大的灵活性，并允许轻松测试这两个类。通过新的设计，对`RateParser`的更改不会影响`LoanCalculator`，这两个类可以独立进行单元测试。

责任不应该混在一个类中。你应该避免在一个类中混淆责任，这会导致做太多事情的怪兽类。相反，如果你能想到一个改变类的理由或动机，那么它已经有了多个责任；将类分成每个只包含单一责任的类。

类似地，对以下代码片段中的`LoanRepository`类的第一印象可能不会直接表明关注点混淆。但是，如果仔细检查该类，数据访问和业务逻辑代码都混在一起，这使得它违反了 SRP：

```cs
public class LoanRepository
{
    private DbContext dbContext;
    private IEligibilityChecker eligibilityChecker;

    public LoanRepository(DbContext dbContext,IEligibilityChecker eligibilityChecker)
    {
        this.dbContext=dbContext;
        this.eligibilityChecker= eligibilityChecker;
    }

    public List<CarLoan> GetCarLoans()
    {
        return dbContext.CarLoan;
    }

    public List<HouseLoan> GetHouseLoans()
    {
        return dbContext.HouseLoan;
    }

    public double CalculateCarLoanRate(CarLoan carLoan)
    {
        double rate=12.5F;
        bool isEligible=eligibilityChecker.IsApplicantEligible(carLoan);
        if(isEligible)
          rate=rate-carLoan.DiscountFactor; 
        return rate;
    }
}
```

这个类可以通过将计算汽车贷款利率的业务逻辑代码分离到一个新的类——`LoanService`中来重构，这将允许`LoanRepository`类只包含与数据层相关的代码，从而使其符合 SRP：

```cs
public class LoanService
{
    private IEligibilityChecker eligibilityChecker;

    public LoanService(IEligibilityChecker eligibilityChecker)
    {
        this.eligibilityChecker= eligibilityChecker;
    }    

    public double CalculateCarLoanRate(CarLoan carLoan)
    {
        double rate=12.5F;
        bool isEligible=eligibilityChecker.IsApplicantEligible(carLoan);
        if(isEligible)
          rate=rate-carLoan.DiscountFactor; 
        return rate;
    }
}
```

通过将业务逻辑代码分离到`LoanService`类中，`LoanRepository`类现在只有一个依赖，即`DbContext`实体框架。未来，`LoanRepository`可以很容易地进行维护和测试。新的`LoanService`类也符合 SRP：

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

    public List<HouseLoan> GetHouseLoans()
    {
        return dbContext.HouseLoan;
    }    
}
```

当您的代码中的问题得到很好的管理时，代码库将具有高内聚性，并且将来会更加灵活、易于测试和维护。有了高内聚性，类将松散耦合，对类的更改将很少可能破坏整个系统。

# 开闭原则

设计和最终编写生产代码的方法应该是允许向项目的代码库添加新功能，而无需进行多次更改、更改代码库的几个部分或类，或破坏已经正常工作且状态良好的现有功能。

如果由于对类中的方法进行更改而导致必须对多个部分或模块进行更改，这表明代码设计存在问题。这就是**开闭原则**（OCP）所解决的问题，允许您的代码库设计灵活，以便您可以轻松进行修改和增强。

OCP 规定软件实体（如类、方法和模块）应设计为对扩展开放，但对修改关闭。这个原则可以通过继承或设计模式（如工厂、观察者和策略模式）来实现。这是指类和方法可以被设计为允许添加新功能，以供现有代码使用，而无需实际修改或更改现有代码，而是通过扩展现有代码的行为。

在 C#中，通过正确使用对象抽象，您可以拥有封闭的类，这些类对修改关闭，而类的行为可以通过派生类进行扩展。派生类是封闭类的子类。使用继承，您可以创建通过扩展其基类添加更多功能的类，而无需修改基类。

考虑以下代码片段中的`LoanCalculator`类，它具有一个`CalculateLoan`方法，必须能够计算传递给它的任何类型的贷款的详细信息。在不使用 OCP 的情况下，可以使用`if..else if`语句来计算要求。

`LoanCalculator`类具有严格的结构，当需要支持新类型时需要进行大量工作。例如，如果您打算添加更多类型的客户贷款，您必须修改`CalculateLoan`方法并添加额外的`else if`语句以适应新类型的贷款。`LoanCalculator`违反了 OCP，因为该类不是封闭的以进行修改：

```cs
public class LoanCalculator
{
    private IRateParser rateParser;

    public LoanCalculator(IRateParser rateParser)
    {
        this.rateParser=rateParser;
    }

    public Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan();
        if(loanDTO.LoanType==LoanType.CarLoan)
        {
            loan.LoanType=LoanType.CarLoan;
            loan.InterestRate=rateParser.GetRateByLoanType(LoanType.CarLoan);
            // do other processing
        }
        else if(loanDTO.LoanType==LoanType.HouseLoan)
        {
            loan.LoanType=LoanType.HouseLoan;
            loan.InterestRate=rateParser.GetRateByLoanType(LoanType.HouseLoan);
            // do other processing
        }        
        return loan;
    }   
}
```

为了使`LoanCalculator`类对扩展开放而对修改关闭，我们可以使用继承来简化重构。 `LoanCalculator`将被重构以允许从中创建子类。将`LoanCalculator`作为基类将有助于创建两个派生类，`HouseLoanCalculator`和`CarLoanCalulator`。计算不同类型贷款的业务逻辑已从`CalculateLoan`方法中移除，并在两个派生类中实现，如下面的代码片段所示：

```cs
public class LoanCalculator
{
    protected IRateParser rateParser;

    public LoanCalculator(IRateParser rateParser)
    {
        this.rateParser=rateParser;
    }

    public Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan(); 
        // do some base processing
        return loan;
    }   
}
```

`LoanCalculator`类中的`If`条件已从`CalculateLoan`方法中移除。现在，新的`CarLoanCaculator`类包含了获取汽车贷款计算的逻辑：

```cs
public class CarLoanCalculator : LoanCalculator
{    
    public CarLoanCalculator(IRateParser rateParser) :base(rateParser)
    {
        base.rateParser=rateParser;
    }

    public override Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan();
        loan.LoanType=loanDTO.LoanType;
        loan.InterestRate=rateParser.GetRateByLoanType(loanDTO.LoanType);
        // do other processing
        return loan
    }   
}
```

`HouseLoanCalculator`类是从`LoanCalculator`创建的，具有覆盖基类`LoanCalculator`中的`CalculateLoan`方法的`CalculateLoan`方法。对`HouseLoanCalculator`进行的任何更改都不会影响其基类的`CalculateLoan`方法：

```cs
public class HouseLoanCalculator : LoanCalculator
{    
    public HouseLoanCalculator(IRateParser rateParser) :base(rateParser)
    {
        base.rateParser=rateParser;
    }

    public override Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan();
        loan.LoanType=LoanType.HouseLoan;
        loan.InterestRate=rateParser.GetRateByLoanType(LoanType.HouseLoan);
        // do other processing
        return loan;
    }    
}
```

如果引入了新类型的贷款，比如研究生学习贷款，可以创建一个新类`PostGraduateStudyLoan`来扩展`LoanCalculator`并实现`CalculateLoan`方法，而无需对`LoanCalculator`类进行任何修改。

从技术上讲，观察 OCP 意味着您的代码中的类和方法应该对扩展开放，这意味着可以扩展类和方法以添加新的行为来支持新的或不断变化的应用程序需求。而且类和方法对于修改是封闭的，这意味着您不能对源代码进行更改。

为了使`LoanCalculator`对更改开放，我们将其作为其他类型的基类派生。或者，我们可以创建一个`ILoanCalculator`抽象，而不是使用经典的对象继承：

```cs
public interface ILoanCalculator
{
    Loan CalculateLoan(LoanDTO loanDTO);
}
```

`CarLoanCalculator`类现在可以被创建来实现`ILoanCalculator`接口。这将需要`CarLoanCalculator`类明确实现接口中定义的方法和属性。

```cs
public class CarLoanCalculator : ILoanCalculator
{    
    private IRateParser rateParser;

    public CarLoanCalculator(IRateParser rateParser)
    {
        this.rateParser=rateParser;
    }

    public Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan();
        loan.LoanType=loanDTO.LoanType;
        loan.InterestRate=rateParser.GetRateByLoanType(loanDTO.LoanType);
        // do other processing
        return loan
    }   
}
```

`HouseLoanCalculator`类也可以被创建来实现`ILoanCalculator`，通过构造函数将`IRateParser`对象注入其中，类似于`CarLoanCalculator`。`CalculateLoan`方法可以被实现为具有计算房屋贷款所需的特定代码。通过简单地创建类并使其实现`ILoanCalculator`接口，可以添加任何其他类型的贷款：

```cs
public class HouseLoanCalculator  : ILoanCalculator
{    
    private IRateParser rateParser;

    public HouseLoanCalculator (IRateParser rateParser)
    {
        this.rateParser=rateParser;
    }

    public Loan CalculateLoan(LoanDTO loanDTO)
    {
        Loan loan = new Loan();
        loan.LoanType=loanDTO.LoanType;
        loan.InterestRate=rateParser.GetRateByLoanType(loanDTO.LoanType);
        // do other processing
        return loan
    }   
}
```

使用 OCP，您可以创建灵活的软件应用程序，其行为可以轻松扩展，从而避免代码基础僵化且缺乏可重用性。通过适当使用 OCP，通过有效使用代码抽象和对象多态性，可以对代码基础进行更改，而无需更改许多部分，并且付出很少的努力。您真的不必重新编译代码基础来实现这一点。

# Liskov 替换原则

**Liskov 替换原则**（LSP），有时也称为**按合同设计**，是 SOLID 原则中的第三个原则，最初由*Barbara Liskov*提出。LSP 规定，派生类或子类应该可以替换基类或超类，而无需对基类进行修改或在系统中生成任何运行时错误。

LSP 可以通过以下数学符号进一步解释——假设 S 是 T 的子集，T 的对象可以替换 S 的对象，而不会破坏系统的现有工作功能或引起任何类型的错误。

为了说明 LSP 的概念，让我们考虑一个带有`Drive`方法的`Car`超类。如果`Car`有两个派生类，`SalonCar`和`JeepCar`，它们都有`Drive`方法的重写实现，那么无论何时需要`Car`，都应该可以使用`SalonCar`和`JeepCar`来替代`Car`类。派生类与`Car`有一个*是一个*的关系，因为`SalonCar`是`Car`，`JeepCar`是`Car`。

为了设计您的类并实现它们以符合 LSP，您应该确保派生类的元素是按照合同设计的。派生类的方法定义应该与基类的相似，尽管实现可能会有所不同，因为不同的业务需求。

此外，重要的是派生类的实现不违反基类或接口中实现的任何约束。当您部分实现接口或基类时，通过具有未实现的方法，您正在违反 LSP。

以下代码片段具有`LoanCalculator`基类，具有`CalculateLoan`方法和两个派生类，`HouseLoanCalculator`和`CarLoanCalculator`，它们具有`CalculateLoan`方法并且可以具有不同的实现：

```cs
public class LoanCalculator
{
    public Loan CalculateLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();
    }   
}

public class HouseLoanCalculator  : LoanCalculator
{     
    public override Loan CalculateLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();   
    }   
}

public class CarLoanCalculator  : LoanCalculator
{     
    public override Loan CalculateLoan(LoanDTO loanDTO)
    {
        throw new NotImplementedException();   
    }   
}
```

如果在前面的代码片段中没有违反 LSP，那么`HouseLoanCalculator`和`CarLoanCalculator`派生类可以在需要`LoanCalculator`引用的任何地方使用。这在以下代码片段中的`Main`方法中得到了证明：

```cs
public static void Main(string [] args)
{
    //substituting CarLoanCalulator for LoanCalculator
    RateParser rateParser = new RateParser();
    LoanCalculator loanCalculator= new CarLoanCalculator(rateParser);
    Loan carLoan= loanCalulator.CalculateLoan();

    //substituting HouseLoanCalculator for LoanCalculator
    loanCalculator= new HouseLoanCalculator(rateParser);
    Loan houseLoan= loanCalulator.CalculateLoan();

    Console.WriteLine($"Car Loan Interest Rate - {carLoan.InterestRate}");
    Console.WriteLine($"House Loan Interest Rate - {houseLoan.InterestRate}");
}

```

# 接口隔离原则

接口是一种面向对象的编程构造，被对象用来定义它们公开的方法和属性，并促进与其他对象的交互。接口包含相关方法，具有空的方法体但没有实现。接口是面向对象编程和设计中的有用构造；它允许创建灵活且松耦合的软件应用程序。

接口隔离原则（ISP）规定接口应该是适度的，只包含所需的属性和方法的定义，客户端不应被强制实现他们不使用的接口，或依赖他们不需要的方法。

要有效地在代码库中实现 ISP，您应该倾向于创建简单而薄的接口，这些接口具有逻辑上分组在一起以解决特定业务案例的方法。通过创建薄接口，类代码中包含的方法可以轻松实现，同时保持代码库的清晰和优雅。

另一方面，如果您的接口臃肿或臃肿，其中包含类不需要的功能的方法，您更有可能违反 ISP 并在代码中创建耦合，这将导致代码库无法轻松测试。

与其拥有臃肿或臃肿的接口，不如创建两个或更多个薄接口，将方法逻辑地分组，并让您的类实现多个接口，或让接口继承其他薄接口，这种现象被称为多重继承，在 C#中得到支持。

以下片段中的`IRateCalculator`接口违反了 ISP。它可以被视为一个污染的接口，因为唯一实现它的类不需要`FindLender`方法，因为`RateCalculator`类不需要它：

```cs
public interface IRateCalculator
{
    Rate GetYearlyCarLoanRate();
    Rate GetYearlyHouseLoanRate();
    Lender FindLender(LoanType loanType);
}
```

`RateCalculator`类具有`GetYearlyCarLoanRate`和`GetYearlyHouseLoanRate`方法，这些方法是必需的以满足类的要求。通过实现`IRateCalculator`，`RateCalculator`被迫为`FindLender`方法实现，而这并不需要：

```cs
public class RateCalculator :IRateCalculator
{
    public Rate GetYearlyCarLoanRate()
    {
        throw new NotImplementedException();
    }

    public Rate GetYearlyHouseLoanRate()
    {
        throw new NotImplementedException();
    }

    public Lender FindLender(LoanType loanType)
    {
        throw new NotImplementedException();
    }
}
```

前述的`IRateCalculator`可以重构为两个具有可以逻辑分组在一起的方法的连贯接口。通过小接口，可以以极大的灵活性编写代码，并且易于对实现接口的类进行单元测试：

```cs
public interface IRateCalculator
{
    Rate GetYearlyCarLoanRate();
    Rate GetYearlyHouseLonaRate();
}

public interface ILenderManager
{
    Lender FindLender(LoanType loanType);
}
```

通过将`IRateCalculator`重构为两个接口，`RateCalculator`可以被重构以删除不需要的`FindLender`方法：

```cs
public class RateCalculator :IRateCalculator
{
    public Rate GetYearlyCarLoanRate()
    {
        throw new NotImplementedException();
    }

    public Rate GetYearlyHouseLonaRate()
    {
        throw new NotImplementedException();
    }    
}
```

在实现符合 ISP 的接口时要注意的反模式是为每个方法创建一个接口，试图创建薄接口；这可能导致创建多个接口，从而导致难以维护的代码库。

# 依赖反转原则

刚性或糟糕的设计可能会使软件应用程序的组件或模块的更改变得非常困难，并创建维护问题。这些不灵活的设计通常会破坏先前正常工作的功能。这可能以原则和模式的错误使用、糟糕的代码和不同组件或层的耦合形式出现，从而使维护过程变得非常困难。

当应用程序代码库中存在严格的设计时，仔细检查代码将会发现模块之间紧密耦合，使得更改变得困难。对任何模块的更改可能会导致破坏先前正常工作的另一个模块的风险。观察 SOLID 原则中的最后一个——依赖反转原则（DIP）可以消除模块之间的任何耦合，使代码库灵活且易于维护。

DIP 有两种形式，都旨在实现代码的灵活性和对象及其依赖项之间的松耦合：

+   高级模块不应依赖于低级模块；两者都应依赖于抽象

+   抽象不应依赖于细节；细节应依赖于抽象

当高级模块或实体直接耦合到低级模块时，对低级模块进行更改通常会直接影响高级模块，导致它们发生变化，产生连锁反应。在实际情况下，当对高级模块进行更改时，低级模块应该发生变化。

此外，您可以在需要类与其他类通信或发送消息的任何地方应用 DIP。DIP 倡导应用程序开发中众所周知的分层原则或关注点分离原则：

```cs
public class AuthenticationManager
{
    private DbContext dbContext;

    public AuthenticationManager(DbContext dbContext)
    {
        this.dbContext=dbContext;
    }
}
```

在上面的代码片段中，`AuthenticationManager`类代表了一个高级模块，而传递给类构造函数的`DbContext` Entity Framework 是一个负责 CRUD 和数据层活动的低级模块。虽然非专业的开发人员可能不会在代码结构中看到任何问题，但它违反了 DIP。这是因为`AuthenticationManager`类依赖于`DbContext`类，并且对`DbContext`内部代码进行更改的尝试将会传播到`AuthenticationManager`，导致它发生变化，从而违反 OCP。

我们可以重构`AuthenticationManager`类，使其具有良好的设计并符合 DIP。这将需要创建一个`IDbContext`接口，并使`DbContext`实现该接口。

```cs
public interface IDbContext
{
    int SaveChanges();
    void Dispose();
}

public class DbContext : IDbContext
{
    public int SaveChanges()
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        throw new NotImplementedException();
    }
}
```

`AuthenticationManager`可以根据接口编码，从而打破与`DbContext`的耦合或直接依赖，并且依赖于抽象。对`AuthenticationManager`进行编码，使其针对`IDbContext`意味着接口将被注入到`AuthenticationManager`的构造函数中，或者使用*属性注入*：

```cs
public class AuthenticationManager
{
    private IDbContext dbContext;

    public AuthenticationManager(IDbContext dbContext)
    {
        this.dbContext=dbContext;
    }
}
```

重构完成后，`AuthenticationManager`现在使用依赖反转，并依赖于抽象—`IDbContext`。将来，如果对`DbContext`类进行更改，将不再影响`AuthenticationManager`类，并且不会违反 OCP。

虽然通过构造函数将`IDbContext`注入到`AutheticationManager`中非常优雅，但`IDbcontext`也可以通过公共属性注入到`AuthenticationManager`中：

```cs
public class AuthenticationManager
{
    private IDbContext dbContext;

    private IDbContext DbContext
    {
        set
        {
            dbContext=value;
        }
    }
}
```

此外，DI 也可以通过*接口注入*来实现，其中对象引用是使用接口操作传递的。这简单地意味着使用接口来注入依赖项。以下代码片段解释了使用接口注入来实现依赖的概念。

`IRateParser`是使用`ParseRate`方法定义创建的。第二个接口`IRepository`包含`InjectRateParser`方法，该方法接受`IRateParser`作为参数，并将注入依赖项。

```cs
public interface IRateParser
{
    Rate ParseRate();
}

public interface IRepository
{
    void InjectRateParser(IRateParser rateParser);
}
```

现在，让我们创建`LoanRepository`类来实现`IRepository`接口，并为`InjectRateParser`创建一个代码实现，以将`IRateParser`存储库作为依赖项注入到`LoanRepository`类中以供代码使用：

```cs
public class LoanRepository : IRepository
{
    IRateParser rateParser;

    public void InjectRateParser(IRateParser rateParser)
    {
        this.rateParser = rateParser;
    }

     public float GetCheapestRate(LoanType loanType)
     {
         return rateParser.GetRateByLoanType(loanType);
     }
}
```

接下来，我们可以创建`IRateParser`依赖的具体实现，`XmlRateParser`和`RestServiceRateParser`，它们都包含了从 XML 和 REST 源解析贷款利率的`ParseRate`方法的实现：

```cs
public class XmlRateParser : IRateParser
{
    public Rate ParseRate()
    {
        // Parse rate available from xml file
        throw new NotImplementedException();
    }
}

public class RestServiceRateParser : IRateParser
{
    public Rate ParseRate()
    {
        // Parse rate available from REST service
        throw new NotImplementedException();
    }
}
```

总之，我们可以使用在前面的代码片段中创建的接口和类来测试*接口注入*概念。创建了`IRateParser`的具体对象，它被注入到`LoanRepository`类中，通过`IRepository`接口，并且可以使用`IRateParser`接口的两种实现之一来构造它。

```cs
IRateParser rateParser = new XmlRateParser();           
LoanRepository loanRepository = new LoanRepository();
((IRepository)loanRepository).InjectRateParser(rateParser);
var rate= loanRepository.GetCheapestRate();

rateParser = new RestServiceRateParser();       
((IRepository)loanRepository).InjectRateParser(rateParser);
rate= loanRepository.GetCheapestRate();

```

在本节中描述的任何三种技术都可以有效地用于在需要时将依赖项注入到代码中。适当有效地使用 DIP 可以促进创建易于维护的松散耦合的应用程序。

# 为 ASP.NET Core MVC 设置 DI 容器

ASP.NET Core 的核心是 DI。该框架提供了内置的 DI 服务，允许开发人员创建松散耦合的应用程序，并防止依赖关系的实例化或构造。使用内置的 DI 服务，您的应用程序代码可以设置为使用 DI，并且依赖项可以被注入到`Startup`类中的方法中。虽然默认的 DI 容器具有一些很酷的功能，但您仍然可以在 ASP.NET Core 应用程序中使用其他已知的成熟的 DI 容器。

您可以将代码配置为以两种模式使用 DI：

+   **构造函数注入**：类所需的接口通过类的公共构造函数传递或注入。使用私有构造函数无法进行构造函数注入，当尝试这样做时，将引发`InvalidOperationException`。在具有重载构造函数的类中，只能使用一个构造函数进行 DI。

+   **属性注入**：通过在类中使用公共接口属性将依赖项注入到类中。可以使用这两种模式之一来请求依赖项，这些依赖项将由 DI 容器注入。

DI 容器，也称为**控制反转**（**IoC**）容器，通常是一个可以创建具有其关联依赖项的类的类或工厂。在成功构造具有注入依赖项的类之前，项目必须设计或设置为使用 DI，并且 DI 容器必须已配置为具有依赖类型。实质上，DI 将具有包含接口到其具体类的映射的配置，并将使用此配置来解析所需依赖项的类。

ASP.NET Core 内置的 IoC 容器由`IServiceProvider`接口表示，您可以使用`Startup`类中的`ConfigureService`方法对其进行配置。容器默认支持构造函数注入。在`ConfigureService`方法中，可以定义服务和平台功能，例如 Entity Framework Core 和 ASP.NET MVC Core：

```cs
public void ConfigureServices(IServiceCollection services)
{
    // Add framework services.
    services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
    services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

    services.AddMvc();

    // Configured DI
    services.AddTransient<ILenderManager, LenderManager >();
    services.AddTransient<IRateCalculator, RateCalculator>();
}
```

ASP.NET Core 内置容器具有一些扩展方法，例如`AddDbContext`、`AddIdentity`和`AddMvc`，您可以使用这些方法添加其他服务。可以使用`AddTransient`方法配置应用程序依赖项，该方法接受两个泛型类型参数，第一个是接口，第二个是具体类。`AddTransient`方法将接口映射到具体类，因此每次请求时都会创建服务。容器使用此配置为在 ASP.NET MVC 项目中需要它的每个对象注入接口。

用于配置服务的其他扩展方法是`AddScoped`和`AddSingleton`方法。`AddScoped`每次请求只创建一次服务：

```cs
services.AddScoped<ILenderManager, LenderManager >();
```

`AddSingleton`方法只在首次请求时创建服务，并将其保存在内存中，使其可供后续请求使用。您可以自行实例化单例，也可以让容器来处理：

```cs
// instantiating singleton 
services.AddSingleton<ILenderManager>(new LenderManager()); 

// alternative way of configuring singleton service
services.AddSingleton<IRateCalculator, RateCalculator>();
```

ASP.NET Core 的内置 IoC 容器轻量级且功能有限，但基本上您可以在应用程序中使用它进行 DI 配置。但是，您可以将其替换为.NET 中可用的其他 IoC 容器，例如**Ninject**或**Autofac**。

使用 DI 将简化应用程序开发体验，并使您能够编写松散耦合且易于测试的代码。在典型的 ASP.NET Core MVC 应用程序中，您应该使用 DI 来处理依赖项，例如**存储库**、**控制器**、**适配器**和**服务**，并避免对服务或`HttpContext`进行静态访问。

# 摘要

本章中使用的面向对象设计原则将帮助您掌握编写清晰、灵活、易于维护和易于测试代码所需的技能。本章中解释的 LoD 和 SOLID 原则可以作为创建松散耦合的面向对象软件应用程序的指导原则。

为了获得 TDD 周期的好处，您必须编写可测试的代码。所涵盖的 SOLID 原则描述了适当的实践，可以促进编写可轻松维护并在需要时进行增强的可测试代码。本章的最后一节着重介绍了为 ASP.NET Core MVC 应用程序设置和使用依赖注入容器。

在下一章中，我们将讨论良好单元测试的属性，.NET 生态系统中可用于创建测试的单元测试框架，以及在单元测试 ASP.NET MVC Core 项目时需要考虑的内容，我们还将深入探讨在.NET Core 平台上使用 xUnit 库进行单元测试的属性。
