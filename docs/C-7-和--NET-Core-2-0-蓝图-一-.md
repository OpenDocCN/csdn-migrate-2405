# C#7 和 .NET Core 2.0 蓝图（一）

> 原文：[`zh.annas-archive.org/md5/7C3D5DACD7BE632FD426A045B35F94C4`](https://zh.annas-archive.org/md5/7C3D5DACD7BE632FD426A045B35F94C4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《C# 7 和.NET Core 2.0 蓝图》。通过采用*蓝图*方法来展示.NET Core 2.0 的强大之处，您将学习如何在创建可用的令人兴奋的应用程序时使用.NET Core 2.0。

# 这本书适合谁

本书旨在面向那些对 C#编程语言有很好掌握但可能需要更多了解.NET Core 的开发人员。

# 本书涵盖的内容

第一章，*电子书管理和目录应用*，介绍了 C# 7 引入的新功能，使开发人员能够编写更少的代码并提高生产力。我们将创建一个电子书管理应用程序。如果你和我一样，在硬盘和外部驱动器上都散落着电子书，这个应用程序将提供一个机制将所有这些不同的位置汇聚到一个虚拟存储空间中。该应用程序已经具备功能，但可以进一步增强以满足您的需求。

第二章，*板球比分计算器和跟踪器*，指出面向对象编程（OOP）是编写.NET 应用程序的关键要素。适当的 OOP 确保开发人员可以轻松地在项目之间共享代码。在本章中，我们将创建一个 ASP.NET Bootstrap Web 应用程序，用于跟踪您两支最喜欢的板球队的比分。也正是通过这个应用程序，面向对象编程的原则将变得明显。

第三章，*跨平台.NET Core 系统信息管理器*，介绍了.NET Core 是什么；.NET Core 允许我们创建在 Windows、macOS 和 Linux 上运行的应用程序。为了在本章中加以说明，我们将创建一个简单的信息仪表板应用程序，显示我们正在运行的计算机的信息以及该计算机位置的天气情况。

第四章，*使用 MongoDB 的任务错误记录 ASP .NET Core MVC 应用程序*，通过创建一个任务/错误记录应用程序，介绍了在 ASP.NET Core MVC 中使用 MongoDB。MongoDB 可以让开发人员更加高效，并且可以轻松地添加到.NET Core 中。

第五章，*ASP.NET SignalR 聊天应用程序*，开始让你想象具有服务器端代码实时推送数据到网页的能力，而无需用户刷新页面。ASP.NET SignalR 库为开发人员提供了一种简化的方法，以向应用程序添加实时网络功能。当阅读第八章，*使用 OAuth 的 Twitter 克隆*时，请记住这一点。这是一个完美的应用程序，可以集成 SignalR。

第六章，*使用 Entity Framework Core 的 Web 研究工具*，讨论了 Entity Framework Core，这是我们.NET Core 教育中的一个重要组成部分。开发应用程序中最令人沮丧的部分之一是尝试建立代码与数据库之间的通信层。Entity Framework Core 可以轻松解决这个问题，并且本章向您展示了如何实现。

第七章，*无服务器电子邮件验证 Azure 函数*，向您展示如何创建 Azure 函数以及如何从 ASP.NET Core MVC 应用程序调用该函数。Azure 函数将只验证电子邮件地址。本章介绍了无服务器计算，并在阅读本章时将清楚地了解其好处。

第八章，*使用 OAuth 创建 Twitter 克隆*，表达了我有时希望能够调整 Twitter 以满足自己的需求，例如保存喜爱的推文。在本章中，我们将看看使用 ASP.NET Core MVC 创建基本 Twitter 克隆有多容易。然后，您可以轻松地向应用程序添加功能，以定制满足您特定需求。

第九章，*使用 Docker 和 ASP.NET Core*，探讨了当今非常流行的 Docker，以及其非常重要的原因。本章说明了 Docker 如何使开发人员受益。我还将向您展示如何创建 ASP.NET Core MVC 应用程序并在 Docker 容器中运行它。在本章的最后部分，我们将看到如何使用 Docker Hub 和 GitHub 设置自动构建。

# 充分利用本书

假设您至少对 C# 6.0 有很好的理解。本书中的所有示例将在相关的地方使用 C# 7。

您需要安装最新补丁的 Visual Studio 2017。如果您没有 Visual Studio 2017，可以免费从[`www.visualstudio.com/downloads/`](https://www.visualstudio.com/downloads/)安装 Visual Studio Community 2017。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如：“您可以随意命名应用程序，但我将我的称为`eBookManager`。”

代码块设置如下：

```cs
namespace eBookManager.Engine 
{ 
    public class DeweyDecimal 
    { 
        public string ComputerScience { get; set; } = "000"; 
        public string DataProcessing { get; set; } = "004"; 
        public string ComputerProgramming { get; set; } = "005"; 
    } 
} 
```

任何命令行输入或输出都是这样写的：

```cs
    mongod -dbpath D:MongoTask 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如：“在添加了所有存储空间和电子书之后，您将看到列出的虚拟存储空间。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。


# 第一章：电子书管理器和目录应用程序

C# 7 是一个很棒的版本，可在 Visual Studio 2017 中使用。它向开发人员介绍了许多强大的功能，其中一些以前只在其他语言中可用。C# 7 引入的新功能使开发人员能够编写更少的代码，提高生产力。

可用的功能有：

+   元组

+   模式匹配

+   `Out`变量

+   解构

+   本地函数

+   文字改进

+   引用返回和本地变量

+   泛化的异步和返回类型

+   访问器、构造函数和终结器的表达式体

+   抛出表达式

本章将介绍其中一些功能，而本书的其余部分将在学习过程中介绍其他功能。在本章中，我们将创建一个`eBookManager`应用程序。如果您和我一样，在硬盘和一些外部驱动器上散落着电子书，那么这个应用程序将提供一种机制，将所有这些不同的位置汇集到一个虚拟存储空间中。该应用程序是功能性的，但可以进一步增强以满足您的需求。这样的应用程序范围是广阔的。您可以从 GitHub（[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints)）下载源代码，并跟随它，看看 C# 7 的一些新功能是如何运作的。

让我们开始吧！

# 设置项目

使用 Visual Studio 2017，我们将创建一个简单的 Windows 窗体应用程序模板项目。您可以随意命名应用程序，但我将其命名为`eBookManager`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ade7f9fc-3db8-4ea4-b8c7-0e5fe8dc5ddd.png)

项目将被创建，并将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d6f1b4b1-aa41-4d72-be7d-fb8ae2c5d455.png)

我们的解决方案需要一个类库项目来包含驱动`eBookManager`应用程序的类。在解决方案中添加一个新的类库项目，并将其命名为`eBookManager.Engine`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/074b1507-958b-47fc-8f1a-d6c028346f27.png)

将解决方案添加到类库项目中，默认类名更改为`Document`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d19a9066-c506-4932-8ffa-17d1b6bfaedc.png)

`Document`类将代表一本电子书。想到一本书，我们可以有多个属性来代表一本书，但又代表所有书籍。一个例子是作者。所有书籍都必须有作者，否则它就不存在。

我知道有些人可能会认为机器也可以生成文档，但它生成的信息可能最初是由人写的。以代码注释为例。开发人员在代码中编写注释，工具从中生成文档。开发人员仍然是作者。

我添加到类中的属性仅仅是我认为可能代表一本书的解释。请随意添加其他代码，使其成为您自己的。

打开`Document.cs`文件，并将以下代码添加到类中：

```cs
namespace eBookManager.Engine 
{ 
    public class Document 
    { 
        public string Title { get; set; } 
        public string FileName { get; set; } 
        public string Extension { get; set; } 
        public DateTime LastAccessed { get; set; } 
        public DateTime Created { get; set; } 
        public string FilePath { get; set; } 
        public string FileSize { get; set; } 
        public string ISBN { get; set; } 
        public string Price { get; set; } 
        public string Publisher { get; set; } 
        public string Author { get; set; } 
        public DateTime PublishDate { get; set; } 
        public DeweyDecimal Classification { get; set; } 
        public string Category { get; set; } 
    } 
} 
```

您会注意到我包括了一个名为`Classification`的属性，类型为`DeweyDecimal`。我们还没有添加这个类，接下来会添加。

在`eBookManager.Engine`项目中，添加一个名为`DeweyDecimal`的类。如果您不想为您的电子书进行这种分类，可以不添加这个类。我包括它是为了完整起见。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/505f9689-7e75-45a1-ac2e-90f997d423bc.png)

您的`DeweyDecimal`类必须与之前添加的`Document`类在同一个项目中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d21a2328-fe07-4c99-9207-e7fdb7aee38c.png)

“杜威十进制”系统非常庞大。因此，我没有考虑到每种书籍分类。我也只假设您想要处理编程电子书。然而，实际上，您可能想要添加其他分类，如文学、科学、艺术等。这取决于您。

所以让我们创建一个代表杜威十进制系统的类：

1.  打开`DeweyDecimal`类并将以下代码添加到类中：

```cs
namespace eBookManager.Engine 
{ 
    public class DeweyDecimal 
    { 
        public string ComputerScience { get; set; } = "000"; 
        public string DataProcessing { get; set; } = "004"; 
        public string ComputerProgramming { get; set; } = "005"; 
    } 
}
```

字母狂人可能会不同意我的观点，但我想提醒他们，我是一个代码狂人。这里表示的分类只是为了让我能够编目与编程和计算机科学相关的电子书。如前所述，您可以根据自己的需要进行更改。

1.  我们现在需要在`eBookManager.Engine`解决方案的核心中添加。这是一个名为`DocumentEngine`的类，它将是一个包含您需要处理文档的方法的类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d2cacf4e-425d-48ba-8b6e-b54c93db28fe.png)

您的`eBookManager.Engine`解决方案现在将包含以下类：

+   +   `DeweyDecimal`

+   `Document`

+   `DocumentEngine`

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/1a779efd-e56b-49df-b3d1-b419fdb71258.png)

1.  我们现在需要从`eBookManager`项目中添加对`eBookManager.Engine`的引用。我相信你们都知道如何做到这一点：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0d58c2d1-d2d6-44b1-9003-e98f2910f514.png)

`eBookManager.Engine`项目将在引用管理器屏幕的项目部分中可用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3077c08c-964a-4df0-a3ff-2e94f13733e0.png)

1.  添加了引用后，我们需要一个负责导入新书籍的 Windows 表单。在`eBookManager`解决方案中添加一个名为`ImportBooks`的新表单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3fb2a00a-dd6b-443e-aea3-f45855b51aec.png)

1.  在我们忘记之前，向`ImportBooks`表单添加一个`ImageList`控件，并将其命名为`tvImages`。这将包含我们想要编目的不同类型文档的图像。

`ImageList`是您从工具箱添加到`ImportBooks`表单上的控件。您可以从`ImageList`属性访问图像集合编辑器。

图标可以在 GitHub 上可下载的源代码的`img`文件夹中找到，网址为[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints)。

这里的图标适用于 PDF、MS Word 和 ePub 文件类型。它还包含文件夹图像：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c9767272-01b8-47e1-818b-6c8fb5db1a32.png)

1.  现在，要在 C# 7 中使用元组，您需要添加`System.ValueTuple` NuGet 包。右键单击解决方案，然后选择管理解决方案的 NuGet 包...

请注意，如果您正在运行.NET Framework 4.7，则`System.ValueTuple`已包含在该框架版本中。因此，您将不需要从 NuGet 获取它。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2497780d-23bd-4ad4-8652-5a213b6c65e4.png)

1.  搜索`System.ValueTuple`并将其添加到您的解决方案项目中。然后单击安装，让进程完成（您将在 Visual Studio 的输出窗口中看到进度）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/70de0865-a9b2-43db-99df-9133fb4459d2.png)

我喜欢在我的项目中使用扩展方法。我通常为此目的添加一个单独的项目和/或类。在这个应用程序中，我添加了一个`eBookManager.Helper`类库项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6252e916-0d45-49c9-8058-79975d06054d.png)

1.  这个帮助类也必须作为引用添加到`eBookManager`解决方案中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0c1750f1-688f-47d9-a836-4c60109dd1df.png)

最后，我将使用 JSON 作为我的电子书目录的简单文件存储。JSON 非常灵活，可以被各种编程语言消耗。JSON 之所以如此好用，是因为它相对轻量级，生成的输出是人类可读的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/12a59967-de8b-4831-a04e-d6224481671a.png)

1.  转到解决方案的 NuGet 包管理器并搜索`Newtonsoft.Json`。然后将其添加到解决方案中的项目并单击安装按钮。

您现在已经设置了`eBookManager`应用程序所需的基本内容。接下来，我们将通过编写一些代码进一步深入应用程序的核心。

# 虚拟存储空间和扩展方法

让我们首先讨论虚拟存储空间背后的逻辑。这是硬盘（或硬盘）上几个物理空间的单一虚拟表示。存储空间将被视为一个特定的电子书组*存储*的单一区域。我使用术语*存储*是因为存储空间并不存在。它更多地代表了一种分组，而不是硬盘上的物理空间：

1.  要开始创建虚拟存储空间，将一个名为`StorageSpace`的新类添加到`eBookManager.Engine`项目中。打开`StorageSpace.cs`文件，并向其中添加以下代码：

```cs
using System; 
using System.Collections.Generic; 

namespace eBookManager.Engine 
{ 
    [Serializable] 
    public class StorageSpace 
    { 
        public int ID { get; set; } 
        public string Name { get; set; } 
        public string Description { get; set; } 
        public List<Document> BookList { get; set; } 
    } 
} 
```

请注意，您需要在这里包含`System.Collections.Generic`命名空间，因为`StorageSpace`类包含一个名为`BookList`的属性，类型为`List<Document>`，它将包含该特定存储空间中的所有书籍。

现在我们需要把注意力集中在`eBookManager.Helper`项目中的`ExtensionMethods`类上。这将是一个静态类，因为扩展方法需要以静态的方式来作用于扩展方法定义的各种对象。

1.  在`eBookManager.Helper`项目中添加一个新类，并修改`ExtensionMethods`类如下：

```cs
public static class ExtensionMethods 
{ 

} 
```

让我们将第一个扩展方法添加到名为`ToInt()`的类中。这个扩展方法的作用是获取一个`string`值并尝试将其解析为一个`integer`值。每当我需要将`string`转换为`integer`时，我都懒得输入`Convert.ToInt32(stringVariable)`。正因为如此，我使用了一个扩展方法。

1.  在`ExtensionMethods`类中添加以下静态方法：

```cs
public static int ToInt(this string value, int defaultInteger = 0) 
{ 
    try 
    { 
        if (int.TryParse(value, out int validInteger)) 
          // Out variables 
         return validInteger; 
        else 
         return defaultInteger; 
    } 
    catch  
    { 
        return defaultInteger; 
    } 
} 
```

`ToInt()`扩展方法仅对`string`起作用。这是由方法签名中的`this string value`代码定义的，其中`value`是将包含您要转换为`integer`的`string`的变量名称。它还有一个名为`defaultInteger`的默认参数，设置为`0`。除非调用扩展方法的开发人员想要返回默认的整数值`0`，否则他们可以将不同的整数传递给这个扩展方法（例如`-1`）。

这也是我们发现 C# 7 的第一个特性的地方。改进了`out`变量。在以前的 C#版本中，我们必须对`out`变量执行以下操作：

```cs
int validInteger; 
if (int.TryParse(value, out validInteger)) 
{ 

} 
```

有一个预声明的整数变量挂在那里，如果`string`值解析为`integer`，它就会得到它的值。C# 7 简化了代码：

```cs
if (int.TryParse(value, out int validInteger)) 
```

C# 7 允许开发人员在作为`out`参数传递的地方声明一个`out`变量。继续讨论`ExtensionMethods`类的其他方法，这些方法用于提供以下逻辑：

+   `读取`和`写入`到数据源

+   检查存储空间是否存在

+   将字节转换为兆字节

+   将`string`转换为`integer`（如前所述）

`ToMegabytes`方法非常简单。在各个地方都不必写这个计算，将其定义在一个扩展方法中是有意义的：

```cs
public static double ToMegabytes(this long bytes) 
{ 
    return (bytes > 0) ? (bytes / 1024f) / 1024f : bytes; 
} 
```

我们还需要一种方法来检查特定的存储空间是否已经存在。

确保从`eBookManager.Helper`项目中向`eBookManager.Engine`添加项目引用。

这个扩展方法的作用也是返回下一个存储空间 ID 给调用代码。如果存储空间不存在，返回的 ID 将是在创建新存储空间时可以使用的下一个 ID：

```cs
public static bool StorageSpaceExists(this List<StorageSpace> space, string nameValueToCheck, out int storageSpaceId) 
{ 
    bool exists = false; 
    storageSpaceId = 0; 

    if (space.Count() != 0) 
    { 
       int count = (from r in space 
                 where r.Name.Equals(nameValueToCheck) 
                 select r).Count(); 

        if (count > 0) 
            exists = true; 

        storageSpaceId = (from r in space 
                          select r.ID).Max() + 1;                                 
    } 
    return exists; 
} 
```

我们还需要创建一个方法，将我们的数据转换为 JSON 后写入文件：

```cs
public static void WriteToDataStore(this List<StorageSpace> value, string storagePath, bool appendToExistingFile = false) 
{ 
    JsonSerializer json = new JsonSerializer(); 
    json.Formatting = Formatting.Indented; 
    using (StreamWriter sw = new StreamWriter(storagePath,  
     appendToExistingFile)) 
    { 
        using (JsonWriter writer = new JsonTextWriter(sw)) 
        { 
            json.Serialize(writer, value); 
        } 
    } 
} 
```

这个方法相当不言自明。它作用于一个`List<StorageSpace>`对象，并将创建 JSON 数据，覆盖在`storagePath`变量中定义的文件中。

最后，我们需要能够再次将数据读取到`List<StorageSpace>`对象中，并将其返回给调用代码：

```cs
public static List<StorageSpace> ReadFromDataStore(this List<StorageSpace> value, string storagePath) 
{ 
    JsonSerializer json = new JsonSerializer(); 
    if (!File.Exists(storagePath)) 
    { 
        var newFile = File.Create(storagePath); 
        newFile.Close(); 
    } 
    using (StreamReader sr = new StreamReader(storagePath)) 
    { 
        using (JsonReader reader = new JsonTextReader(sr)) 
        { 
            var retVal = 
             json.Deserialize<List<StorageSpace>>(reader); 
            if (retVal is null) 
                retVal = new List<StorageSpace>(); 

            return retVal; 
        } 
    } 
} 
```

该方法将返回一个空的`List<StorageSpace>`对象，并且文件中不包含任何内容。`ExtensionMethods`类可以包含许多您经常使用的扩展方法。这是一个很好的分离经常使用的代码的方法。

# DocumentEngine 类

这个类的目的仅仅是为文档提供支持代码。在`eBookManager`应用程序中，我将使用一个名为`GetFileProperties()`的单一方法，它将（你猜对了）返回所选文件的属性。这个类也只包含这一个方法。当应用程序根据您的特定目的进行修改时，您可以修改这个类并添加特定于文档的其他方法。

`DocumentEngine`类向我们介绍了 C# 7 的下一个特性，称为“元组”。元组到底是做什么的？开发人员经常需要从方法中返回多个值。除了其他解决方案外，当然可以使用`out`参数，但这在`async`方法中不起作用。元组提供了更好的方法来做到这一点。

在`DocumentEngine`类中添加以下代码：

```cs
public (DateTime dateCreated, DateTime dateLastAccessed, string fileName, string fileExtension, long fileLength, bool error) GetFileProperties(string filePath) 
{ 
    var returnTuple = (created: DateTime.MinValue,
    lastDateAccessed: DateTime.MinValue, name: "", ext: "",
    fileSize: 0L, error: false); 

    try 
    { 
        FileInfo fi = new FileInfo(filePath); 
        fi.Refresh(); 
        returnTuple = (fi.CreationTime, fi.LastAccessTime, fi.Name, 
        fi.Extension, fi.Length, false); 
    } 
    catch 
    { 
        returnTuple.error = true; 
    } 
    return returnTuple; 
} 
```

`GetFileProperties()`方法返回一个元组，格式为`(DateTime dateCreated, DateTime dateLastAccessed, string fileName, string fileExtension, long fileLength, bool error)`，并且允许我们轻松地检查从调用代码返回的值。

在尝试获取特定文件的属性之前，我通过以下方式初始化“元组”：

```cs
var returnTuple = (created: DateTime.MinValue, lastDateAccessed: DateTime.MinValue, name: "", ext: "", fileSize: 0L, error: false); 
```

如果出现异常，我可以返回默认值。使用`FileInfo`类读取文件属性非常简单。然后我可以通过以下方式将文件属性分配给“元组”：

```cs
returnTuple = (fi.CreationTime, fi.LastAccessTime, fi.Name, fi.Extension, fi.Length, false); 
```

然后将“元组”返回给调用代码，在那里将根据需要使用。接下来我们将看一下调用代码。

# 导入书籍表单

`ImportBooks`表单正如其名称所示。它允许我们创建虚拟存储空间并将书籍导入到这些空间中。表单设计如下：

！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/971b4446-fbf5-449f-94d0-7682e834a5ea.png)

`TreeView`控件以`tv`为前缀，按钮以`btn`为前缀，组合框以`dl`为前缀，文本框以`txt`为前缀，日期时间选择器以`dt`为前缀。当这个表单加载时，如果已经定义了任何存储空间，那么这些存储空间将列在`dlVirtualStorageSpaces`组合框中。单击“选择源文件夹”按钮将允许我们选择源文件夹以查找电子书。

如果存储空间不存在，我们可以通过单击`btnAddNewStorageSpace`按钮添加新的虚拟存储空间。这将允许我们为新的存储空间添加名称和描述，并单击`btnSaveNewStorageSpace`按钮。

从`tvFoundBooks` TreeView 中选择电子书将填充表单右侧的“文件详细信息”组控件。然后您可以添加额外的书籍详细信息，并单击`btnAddeBookToStorageSpace`按钮将书籍添加到我们的空间中：

1.  您需要确保以下命名空间添加到您的`ImportBooks`类中：

```cs
using eBookManager.Engine; 
using System; 
using System.Collections.Generic; 
using System.IO; 
using System.Linq; 
using System.Windows.Forms; 
using static eBookManager.Helper.ExtensionMethods; 
using static System.Math; 
```

1.  接下来，让我们从最合乎逻辑的地方开始，即构造函数`ImportBooks()`和表单变量。在构造函数上方添加以下代码：

```cs
private string _jsonPath; 
private List<StorageSpace> spaces; 
private enum StorageSpaceSelection { New = -9999, NoSelection = -1 } 
```

枚举器的用处将在以后的代码中变得明显。"_jsonPath"变量将包含用于存储我们的电子书信息的文件的路径。

1.  按照以下方式修改构造函数：

```cs
public ImportBooks() 
{ 
    InitializeComponent(); 
    _jsonPath = Path.Combine(Application.StartupPath, 
    "bookData.txt"); 
    spaces = spaces.ReadFromDataStore(_jsonPath); 
} 
```

`_jsonPath`初始化为应用程序的执行文件夹，并且文件硬编码为`bookData.txt`。如果您想要配置这些设置，可以提供一个设置屏幕，但我决定让应用程序使用硬编码设置。

1.  接下来，我们需要添加另一个枚举器，定义我们将能够在应用程序中保存的文件扩展名。在这里，我们将看到 C# 7 的另一个特性，称为“表达式体”属性。

# 表达式体访问器、构造函数和终结器

如果以下表达式看起来令人生畏，那是因为它使用了 C# 6 中引入并在 C# 7 中扩展的一个特性：

```cs
private HashSet<string> AllowedExtensions => new HashSet<string>(StringComparer.InvariantCultureIgnoreCase) { ".doc",".docx",".pdf", ".epub" }; 
private enum Extention { doc = 0, docx = 1, pdf = 2, epub = 3 } 
```

前面的例子返回了我们应用程序允许的文件扩展名的`HashSet`。这些自 C# 6 以来就存在，但在 C# 7 中已经扩展到包括*访问器*、*构造函数*和*终结器*。让我们简化一下这些例子。

假设我们需要修改`Document`类以在类内部设置字段`_defaultDate`；传统上，我们需要这样做：

```cs
private DateTime _defaultDate; 

public Document() 
{ 
    _defaultDate = DateTime.Now; 
} 
```

在 C# 7 中，我们可以通过简单地执行以下操作大大简化这段代码：

```cs
private DateTime _defaultDate; 
public Document() => _defaultDate = DateTime.Now; 
```

这是完全合法的，可以正确编译。同样，终结器（或解构器）也可以这样做。`AllowedExtensions`属性也是`表达式体`属性的一个很好的实现。`表达式体`属性实际上自 C# 6 以来就一直存在，但谁在计数呢？

假设我们只想返回 PDF 的`Extension`枚举的`string`值，我们可以这样做：

```cs
public string PDFExtension 
{ 
    get 
    { 
        return nameof(Extention.pdf); 
    } 
} 
```

该属性只有一个获取器，永远不会返回除`Extension.pdf`之外的任何内容。通过更改代码来简化：

```cs
public string PDFExtension => nameof(Extention.pdf); 
```

就是这样。一行代码完全可以做到与以前的七行代码相同的事情。同样，*表达式体*属性访问器也被简化了。考虑以下 11 行代码：

```cs
public string DefaultSavePath 
{ 
    get 
    { 
        return _jsonPath; 
    } 
    set 
    { 
        _jsonPath = value; 
    } 
} 
```

有了 C# 7，我们可以简化为以下内容：

```cs
public string DefaultSavePath 
{ 
    get => _jsonPath; 
    set => _jsonPath = value; 
} 
```

这使我们的代码更易读，更快速编写。回到我们的`AllowedExtensions`属性；传统上，它将被写成如下形式：

```cs
private HashSet<string> AllowedExtensions 
{ 
    get 
    { 
        return new HashSet<string> 
        (StringComparer.InvariantCultureIgnoreCase) { ".doc", 
        ".docx", ".pdf", ".epub" }; 
    } 
} 
```

自 C# 6 以来，我们已经能够简化这个过程，就像我们之前看到的那样。这为开发人员提供了一个减少不必要代码的好方法。

# 填充 TreeView 控件

当我们查看`PopulateBookList()`方法时，我们可以看到`AllowedExtensions`属性的实现。这个方法的作用只是用选定的源位置找到的文件和文件夹填充`TreeView`控件。考虑以下代码：

```cs
public void PopulateBookList(string paramDir, TreeNode paramNode) 
{ 
    DirectoryInfo dir = new DirectoryInfo(paramDir); 
    foreach (DirectoryInfo dirInfo in dir.GetDirectories()) 
    { 
        TreeNode node = new TreeNode(dirInfo.Name); 
        node.ImageIndex = 4; 
        node.SelectedImageIndex = 5; 

        if (paramNode != null) 
            paramNode.Nodes.Add(node); 
        else 
            tvFoundBooks.Nodes.Add(node); 
        PopulateBookList(dirInfo.FullName, node); 
    } 
    foreach (FileInfo fleInfo in dir.GetFiles().Where
    (x => AllowedExtensions.Contains(x.Extension)).ToList()) 
    { 
        TreeNode node = new TreeNode(fleInfo.Name); 
        node.Tag = fleInfo.FullName; 
        int iconIndex = Enum.Parse(typeof(Extention), 
         fleInfo.Extension.TrimStart('.'), true).GetHashCode(); 

        node.ImageIndex = iconIndex; 
        node.SelectedImageIndex = iconIndex; 
        if (paramNode != null) 
            paramNode.Nodes.Add(node); 
        else 
            tvFoundBooks.Nodes.Add(node); 
    } 
} 
```

我们需要调用这个方法的第一个地方显然是在方法内部，因为这是一个递归方法。我们需要调用它的第二个地方是在`btnSelectSourceFolder`按钮的单击事件中：

```cs
private void btnSelectSourceFolder_Click(object sender, EventArgs e) 
{ 
    try 
    { 
        FolderBrowserDialog fbd = new FolderBrowserDialog(); 
        fbd.Description = "Select the location of your eBooks and 
        documents"; 

        DialogResult dlgResult = fbd.ShowDialog(); 
        if (dlgResult == DialogResult.OK) 
        { 
            tvFoundBooks.Nodes.Clear(); 
            tvFoundBooks.ImageList = tvImages; 

            string path = fbd.SelectedPath; 
            DirectoryInfo di = new DirectoryInfo(path); 
            TreeNode root = new TreeNode(di.Name); 
            root.ImageIndex = 4; 
            root.SelectedImageIndex = 5; 
            tvFoundBooks.Nodes.Add(root); 
            PopulateBookList(di.FullName, root); 
            tvFoundBooks.Sort(); 

            root.Expand(); 
        } 
    } 
    catch (Exception ex) 
    { 
        MessageBox.Show(ex.Message); 
    } 
} 
```

这都是非常简单直接的代码。选择要递归的文件夹，并使用我们的`AllowedExtensions`属性中包含的文件扩展名匹配找到的所有文件，然后填充`TreeView`控件。

当有人在`tvFoundBooks` `TreeView`控件中选择一本书时，我们还需要查看代码。当选择一本书时，我们需要读取所选文件的属性，并将这些属性返回到文件详细信息部分：

```cs
private void tvFoundBooks_AfterSelect(object sender, TreeViewEventArgs e) 
{ 
    DocumentEngine engine = new DocumentEngine(); 
    string path = e.Node.Tag?.ToString() ?? ""; 

    if (File.Exists(path)) 
    { 
        var (dateCreated, dateLastAccessed, fileName, 
        fileExtention, fileLength, hasError) = 
        engine.GetFileProperties(e.Node.Tag.ToString()); 

        if (!hasError) 
        { 
            txtFileName.Text = fileName; 
            txtExtension.Text = fileExtention; 
            dtCreated.Value = dateCreated; 
            dtLastAccessed.Value = dateLastAccessed; 
            txtFilePath.Text = e.Node.Tag.ToString(); 
            txtFileSize.Text = $"{Round(fileLength.ToMegabytes(),
            2).ToString()} MB"; 
        } 
    } 
} 
```

您会注意到这里我们在`DocumentEngine`类上调用`GetFileProperties()`方法，该方法返回元组。

# 本地函数

这是 C# 7 中的一个功能，我真的很惊讶我会在哪里找到它的用途。事实证明，本地函数确实非常有用。有些人称之为*嵌套函数*，这些函数嵌套在另一个父函数中。显然，它只在父函数内部范围内有效，并提供了一种有用的方式来调用代码，否则在父函数外部没有任何真正的用途。考虑`PopulateStorageSpacesList()`方法：

```cs
private void PopulateStorageSpacesList() 
{ 
    List<KeyValuePair<int, string>> lstSpaces = 
    new List<KeyValuePair<int, string>>(); 
    BindStorageSpaceList((int)StorageSpaceSelection.NoSelection, 
    "Select Storage Space"); 

    void BindStorageSpaceList(int key, string value)
    // Local function 
    { 
        lstSpaces.Add(new KeyValuePair<int, string>(key, value)); 
    } 

    if (spaces is null || spaces.Count() == 0) // Pattern matching 
    { 
        BindStorageSpaceList((int)StorageSpaceSelection.New, "
        <create new>"); 
    } 
    else 
    { 
        foreach (var space in spaces) 
        { 
            BindStorageSpaceList(space.ID, space.Name); 
        } 
    } 

    dlVirtualStorageSpaces.DataSource = new 
    BindingSource(lstSpaces, null); 
    dlVirtualStorageSpaces.DisplayMember = "Value"; 
    dlVirtualStorageSpaces.ValueMember = "Key"; 
} 
```

要查看`PopulateStorageSpacesList()`如何调用本地函数`BindStorageSpaceList()`，请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fe2e05bf-ca6a-4d1d-875d-24d09bd593fd.png)

您会注意到本地函数可以在父函数内的任何地方调用。在这种情况下，`BindStorageSpaceList()`本地函数不返回任何内容，但您可以从本地函数返回任何您喜欢的内容。您也可以这样做：

```cs
private void SomeMethod() 
{ 
    int currentYear = GetCurrentYear(); 

    int GetCurrentYear(int iAddYears = 0) 
    { 
        return DateTime.Now.Year + iAddYears; 
    } 

    int nextYear = GetCurrentYear(1); 
} 
```

本地函数可以从父函数的任何地方访问。

# 模式匹配

继续使用`PopulateStorageSpacesList()`方法，我们可以看到另一个 C# 7 功能的使用，称为**模式匹配**。`spaces is null`代码行可能是最简单的模式匹配形式。实际上，模式匹配支持多种模式。

考虑一个`switch`语句：

```cs
switch (objObject) 
{ 
    case null: 
        WriteLine("null"); // Constant pattern 
        break; 

    case Document doc when doc.Author.Equals("Stephen King"): 
        WriteLine("Stephen King is the author"); 
        break; 

    case Document doc when doc.Author.StartsWith("Stephen"): 
        WriteLine("Stephen is the author"); 
        break; 

    default: 
        break; 
} 
```

模式匹配允许开发人员使用`is`表达式来查看某物是否与特定模式匹配。请记住，模式需要检查最具体到最一般的模式。如果您只是以`case Document doc:`开始，那么传递给`switch`语句的类型为`Document`的所有对象都会匹配。您永远不会找到作者是`Stephen King`或以`Stephen`开头的特定文档。

对于从 C 语言继承的构造，自 70 年代以来它并没有改变太多。C# 7 通过模式匹配改变了这一切。

# 完成 ImportBooks 代码

让我们来看看`ImportBooks`表单中的其余代码。如果之前已保存了任何现有存储空间，表单加载将只填充存储空间列表：

```cs
private void ImportBooks_Load(object sender, EventArgs e) 
{ 
    PopulateStorageSpacesList(); 

    if (dlVirtualStorageSpaces.Items.Count == 0) 
    { 
        dlVirtualStorageSpaces.Items.Add("<create new storage 
        space>"); 
    } 

    lblEbookCount.Text = ""; 
} 
```

现在我们需要添加更改所选存储空间的逻辑。`dlVirtualStorageSpaces`控件的`SelectedIndexChanged()`事件修改如下：

```cs
private void dlVirtualStorageSpaces_SelectedIndexChanged(object sender, EventArgs e) 
{ 
    int selectedValue = 
    dlVirtualStorageSpaces.SelectedValue.ToString().ToInt(); 

    if (selectedValue == (int)StorageSpaceSelection.New) // -9999 
    { 
        txtNewStorageSpaceName.Visible = true; 
        lblStorageSpaceDescription.Visible = true; 
        txtStorageSpaceDescription.ReadOnly = false; 
        btnSaveNewStorageSpace.Visible = true; 
        btnCancelNewStorageSpaceSave.Visible = true; 
        dlVirtualStorageSpaces.Enabled = false; 
        btnAddNewStorageSpace.Enabled = false; 
        lblEbookCount.Text = ""; 
    } 
    else if (selectedValue != 
    (int)StorageSpaceSelection.NoSelection) 
    { 
        // Find the contents of the selected storage space 
        int contentCount = (from c in spaces 
                            where c.ID == selectedValue 
                            select c).Count(); 
        if (contentCount > 0) 
        { 
            StorageSpace selectedSpace = (from c in spaces 
                                          where c.ID == 
                                          selectedValue 
                                          select c).First(); 

            txtStorageSpaceDescription.Text = 
            selectedSpace.Description; 

            List<Document> eBooks = (selectedSpace.BookList == 
            null) 
             ? new List<Document> { } : selectedSpace.BookList; 
            lblEbookCount.Text = $"Storage Space contains 
             {eBooks.Count()} {(eBooks.Count() == 1 ? "eBook" :
             "eBooks")}"; 
        } 
    } 
    else 
    { 
        lblEbookCount.Text = ""; 
    } 
} 
```

我不会在这里对代码进行任何详细的解释，因为它相对明显它在做什么。

# 抛出表达式

我们还需要添加保存新存储空间的代码。将以下代码添加到`btnSaveNewStorageSpace`按钮的`Click`事件中：

```cs
private void btnSaveNewStorageSpace_Click(object sender,
  EventArgs e) 
  { 
    try 
    { 
        if (txtNewStorageSpaceName.Text.Length != 0) 
        { 
            string newName = txtNewStorageSpaceName.Text; 

            // throw expressions: bool spaceExists = 
           (space exists = false) ? return false : throw exception                     
            // Out variables 
            bool spaceExists = (!spaces.StorageSpaceExists
            (newName, out int nextID)) ? false : throw new 
            Exception("The storage space you are 
             trying to add already exists."); 

            if (!spaceExists) 
            { 
                StorageSpace newSpace = new StorageSpace(); 
                newSpace.Name = newName; 
                newSpace.ID = nextID; 
                newSpace.Description = 
                txtStorageSpaceDescription.Text; 
                spaces.Add(newSpace); 
                PopulateStorageSpacesList(); 
                // Save new Storage Space Name 
                txtNewStorageSpaceName.Clear(); 
                txtNewStorageSpaceName.Visible = false; 
                lblStorageSpaceDescription.Visible = false; 
                txtStorageSpaceDescription.ReadOnly = true; 
                txtStorageSpaceDescription.Clear(); 
                btnSaveNewStorageSpace.Visible = false; 
                btnCancelNewStorageSpaceSave.Visible = false; 
                dlVirtualStorageSpaces.Enabled = true; 
                btnAddNewStorageSpace.Enabled = true; 
            } 
        } 
    } 
    catch (Exception ex) 
    { 
        txtNewStorageSpaceName.SelectAll(); 
        MessageBox.Show(ex.Message); 
    } 
} 
```

在这里，我们可以看到 C# 7 语言中的另一个新功能，称为**throw 表达式**。这使开发人员能够从表达式中抛出异常。相关代码如下：

```cs
bool spaceExists = (!spaces.StorageSpaceExists(newName, out int nextID)) ? false : throw new Exception("The storage space you are trying to add already exists."); 
```

我总是喜欢记住代码的结构如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6e4b9f28-daa1-46cb-9216-2f708f101a55.png)

最后几个方法处理将电子书保存在所选虚拟存储空间中。修改`btnAddBookToStorageSpace`按钮的`Click`事件。此代码还包含一个 throw 表达式。如果您没有从组合框中选择存储空间，则会抛出新异常：

```cs
private void btnAddeBookToStorageSpace_Click(object sender, EventArgs e) 
{ 
    try 
    { 
        int selectedStorageSpaceID = 
         dlVirtualStorageSpaces.SelectedValue.ToString().ToInt(); 
        if ((selectedStorageSpaceID !=   
         (int)StorageSpaceSelection.NoSelection) 
        && (selectedStorageSpaceID !=
          (int)StorageSpaceSelection.New)) 
        { 
            UpdateStorageSpaceBooks(selectedStorageSpaceID); 
        } 
        else throw new Exception("Please select a Storage 
       Space to add your eBook to"); // throw expressions 
    } 
    catch (Exception ex) 
    { 
        MessageBox.Show(ex.Message); 
    } 
} 
```

开发人员现在可以立即在代码中抛出异常。这相当不错，使代码更清晰。

# 将所选书籍保存到存储空间

以下代码基本上更新了所选存储空间中的书籍列表（在与用户确认后）如果它已经包含特定书籍。否则，它将将书籍添加到书籍列表作为新书：

```cs
private void UpdateStorageSpaceBooks(int storageSpaceId) 
{ 
    try 
    { 
        int iCount = (from s in spaces 
                      where s.ID == storageSpaceId 
                      select s).Count(); 
        if (iCount > 0) // The space will always exist 
        { 
            // Update 
            StorageSpace existingSpace = (from s in spaces 
              where s.ID == storageSpaceId select s).First(); 

            List<Document> ebooks = existingSpace.BookList; 

            int iBooksExist = (ebooks != null) ? (from b in ebooks 
              where $"{b.FileName}".Equals($"
               {txtFileName.Text.Trim()}") 
                 select b).Count() : 0; 

            if (iBooksExist > 0) 
            { 
                // Update existing book 
                DialogResult dlgResult = MessageBox.Show($"A book 
                with the same name has been found in Storage Space 
                {existingSpace.Name}. 
                Do you want to replace the existing book
                entry with this one?", 
                "Duplicate Title", MessageBoxButtons.YesNo,
                 MessageBoxIcon.Warning,
                 MessageBoxDefaultButton.Button2); 
                if (dlgResult == DialogResult.Yes) 
                { 
                    Document existingBook = (from b in ebooks 
                      where $"
                      {b.FileName}".Equals($"
                      {txtFileName.Text.Trim()}") 
                       select b).First(); 

                    existingBook.FileName = txtFileName.Text; 
                    existingBook.Extension = txtExtension.Text; 
                    existingBook.LastAccessed = 
                    dtLastAccessed.Value; 
                    existingBook.Created = dtCreated.Value; 
                    existingBook.FilePath = txtFilePath.Text; 
                    existingBook.FileSize = txtFileSize.Text; 
                    existingBook.Title = txtTitle.Text; 
                    existingBook.Author = txtAuthor.Text; 
                    existingBook.Publisher = txtPublisher.Text; 
                    existingBook.Price = txtPrice.Text; 
                    existingBook.ISBN = txtISBN.Text; 
                    existingBook.PublishDate = 
                    dtDatePublished.Value; 
                    existingBook.Category = txtCategory.Text; 
               } 
            } 
            else 
            { 
                // Insert new book 
                Document newBook = new Document(); 
                newBook.FileName = txtFileName.Text; 
                newBook.Extension = txtExtension.Text; 
                newBook.LastAccessed = dtLastAccessed.Value; 
                newBook.Created = dtCreated.Value; 
                newBook.FilePath = txtFilePath.Text; 
                newBook.FileSize = txtFileSize.Text; 
                newBook.Title = txtTitle.Text; 
                newBook.Author = txtAuthor.Text; 
                newBook.Publisher = txtPublisher.Text; 
                newBook.Price = txtPrice.Text; 
                newBook.ISBN = txtISBN.Text; 
                newBook.PublishDate = dtDatePublished.Value; 
                newBook.Category = txtCategory.Text; 

                if (ebooks == null) 
                    ebooks = new List<Document>(); 
                ebooks.Add(newBook); 
                existingSpace.BookList = ebooks; 
            } 
        } 
        spaces.WriteToDataStore(_jsonPath); 
        PopulateStorageSpacesList(); 
        MessageBox.Show("Book added"); 
    } 
    catch (Exception ex) 
    { 
        MessageBox.Show(ex.Message); 
    } 
} 
```

最后，作为一种整理的方式，`ImportBooks`表单包含以下代码，用于根据`btnCancelNewStorageSpace`和`btnAddNewStorageSpace`按钮的单击事件显示和启用控件：

```cs
private void btnCancelNewStorageSpaceSave_Click(object sender, EventArgs e) 
{ 
    txtNewStorageSpaceName.Clear(); 
    txtNewStorageSpaceName.Visible = false; 
    lblStorageSpaceDescription.Visible = false; 
    txtStorageSpaceDescription.ReadOnly = true; 
    txtStorageSpaceDescription.Clear(); 
    btnSaveNewStorageSpace.Visible = false; 
    btnCancelNewStorageSpaceSave.Visible = false; 
    dlVirtualStorageSpaces.Enabled = true; 
    btnAddNewStorageSpace.Enabled = true; 
} 

private void btnAddNewStorageSpace_Click(object sender, EventArgs e) 
{ 
    txtNewStorageSpaceName.Visible = true; 
    lblStorageSpaceDescription.Visible = true; 
    txtStorageSpaceDescription.ReadOnly = false; 
    btnSaveNewStorageSpace.Visible = true; 
    btnCancelNewStorageSpaceSave.Visible = true; 
    dlVirtualStorageSpaces.Enabled = false; 
    btnAddNewStorageSpace.Enabled = false; 
} 
```

现在我们只需要完成`Form1.cs`表单中的代码，这是启动表单。

# 主 eBookManager 表单

首先将`Form1.cs`重命名为`eBookManager.cs`。这是应用程序的启动表单，它将列出之前保存的所有现有存储空间：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/14ca97f5-07c7-4913-9561-0dbda876b642.png)

设计您的`eBookManager`表单如下：

+   用于现有存储空间的`ListView`控件

+   用于所选存储空间中包含的电子书的`ListView`

+   打开电子书文件位置的按钮

+   菜单控件以导航到`ImportBooks.cs`表单

+   各种只读字段用于显示所选电子书信息

当您添加了控件后，您的 eBook Manager 表单将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a01fb98a-4c0b-4b4e-8952-19a51e4dfa7c.png)

查看我们之前使用的代码，您需要确保导入以下`using`语句：

```cs
using eBookManager.Engine; 
using eBookManager.Helper; 
using System; 
using System.Collections.Generic; 
using System.IO; 
using System.Windows.Forms; 
using System.Linq; 
using System.Diagnostics; 
```

构造函数与`ImportBooks.cs`表单的构造函数非常相似。它读取任何可用的存储空间，并使用先前保存的存储空间填充存储空间列表视图控件：

```cs
private string _jsonPath; 
private List<StorageSpace> spaces; 

public eBookManager() 
{ 
    InitializeComponent(); 
    _jsonPath = Path.Combine(Application.StartupPath, 
    "bookData.txt"); 
    spaces = spaces.ReadFromDataStore(_jsonPath); 
} 

private void Form1_Load(object sender, EventArgs e) 
{             
    PopulateStorageSpaceList(); 
} 

private void PopulateStorageSpaceList() 
{ 
    lstStorageSpaces.Clear(); 
    if (!(spaces == null)) 
    { 
        foreach (StorageSpace space in spaces) 
        { 
            ListViewItem lvItem = new ListViewItem(space.Name, 0); 
            lvItem.Tag = space.BookList; 
            lvItem.Name = space.ID.ToString(); 
            lstStorageSpaces.Items.Add(lvItem); 
        } 
    } 
} 
```

如果用户点击了一个存储空间，我们需要能够读取该选定空间中包含的书籍：

```cs
private void lstStorageSpaces_MouseClick(object sender, MouseEventArgs e) 
{ 
    ListViewItem selectedStorageSpace = 
    lstStorageSpaces.SelectedItems[0]; 
    int spaceID = selectedStorageSpace.Name.ToInt(); 

    txtStorageSpaceDescription.Text = (from d in spaces 
                                       where d.ID == spaceID 
                                       select 
                                       d.Description).First(); 

    List<Document> ebookList = 
     (List<Document>)selectedStorageSpace.Tag; 
     PopulateContainedEbooks(ebookList); 
}
```

现在我们需要创建一个方法，该方法将使用所选存储空间中包含的书籍填充`lstBooks`列表视图：

```cs
private void PopulateContainedEbooks(List<Document> ebookList) 
{ 
    lstBooks.Clear(); 
    ClearSelectedBook(); 

    if (ebookList != null) 
    { 
        foreach (Document eBook in ebookList) 
        { 
            ListViewItem book = new ListViewItem(eBook.Title, 1); 
            book.Tag = eBook; 
            lstBooks.Items.Add(book); 
        } 
    } 
    else 
    { 
        ListViewItem book = new ListViewItem("This storage space 
        contains no eBooks", 2); 
        book.Tag = ""; 
        lstBooks.Items.Add(book); 
    } 
} 
```

你会注意到每个`ListViewItem`都填充了电子书的标题和我添加到表单的`ImageList`控件中的图像的索引。要在 GitHub 存储库中找到这些图像，请浏览以下路径：

[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/eBookManager/eBookManager/img`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/eBookManager/eBookManager/img)

查看图像集编辑器，你会看到我已经添加了它们如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/547c25ea-5ae0-4e34-954c-b8499f87f77d.png)

当所选存储空间更改时，我们还需要清除所选书籍的详细信息。我在文件和书籍详细信息周围创建了两个组控件。这段代码只是循环遍历所有子控件，如果子控件是文本框，则清除它。

```cs
private void ClearSelectedBook() 
{ 
    foreach (Control ctrl in gbBookDetails.Controls) 
    { 
        if (ctrl is TextBox) 
            ctrl.Text = ""; 
    } 

    foreach (Control ctrl in gbFileDetails.Controls) 
    { 
        if (ctrl is TextBox) 
            ctrl.Text = ""; 
    } 

    dtLastAccessed.Value = DateTime.Now; 
    dtCreated.Value = DateTime.Now; 
    dtDatePublished.Value = DateTime.Now; 
} 
```

添加到表单的 MenuStrip 上有一个点击事件，点击`ImportEBooks`菜单项。它只是打开`ImportBooks`表单：

```cs
private void mnuImportEbooks_Click(object sender, EventArgs e) 
{ 
    ImportBooks import = new ImportBooks(); 
    import.ShowDialog(); 
    spaces = spaces.ReadFromDataStore(_jsonPath); 
    PopulateStorageSpaceList(); 
} 
```

以下方法总结了选择特定电子书并在`eBookManager`表单上填充文件和电子书详细信息的逻辑：

```cs
private void lstBooks_MouseClick(object sender, MouseEventArgs e) 
{ 
    ListViewItem selectedBook = lstBooks.SelectedItems[0]; 
    if (!String.IsNullOrEmpty(selectedBook.Tag.ToString())) 
    { 
        Document ebook = (Document)selectedBook.Tag; 
        txtFileName.Text = ebook.FileName; 
        txtExtension.Text = ebook.Extension; 
        dtLastAccessed.Value = ebook.LastAccessed; 
        dtCreated.Value = ebook.Created; 
        txtFilePath.Text = ebook.FilePath; 
        txtFileSize.Text = ebook.FileSize; 
        txtTitle.Text = ebook.Title; 
        txtAuthor.Text = ebook.Author; 
        txtPublisher.Text = ebook.Publisher; 
        txtPrice.Text = ebook.Price; 
        txtISBN.Text = ebook.ISBN; 
        dtDatePublished.Value = ebook.PublishDate; 
        txtCategory.Text = ebook.Category; 
    } 
} 
```

最后，当所选的书是您想要阅读的书时，请点击“阅读电子书”按钮以打开所选电子书的文件位置：

```cs
private void btnReadEbook_Click(object sender, EventArgs e) 
{ 
    string filePath = txtFilePath.Text; 
    FileInfo fi = new FileInfo(filePath); 
    if (fi.Exists) 
    { 
        Process.Start(Path.GetDirectoryName(filePath)); 
    } 
} 
```

这完成了`eBookManager`应用程序中包含的代码逻辑。

您可以进一步修改代码，以打开所选电子书所需的应用程序，而不仅仅是文件位置。换句话说，如果您点击 PDF 文档，应用程序可以启动加载了文档的 PDF 阅读器。最后，请注意，此版本的应用程序中尚未实现分类。

是时候启动应用程序并测试一下了。

# 运行 eBookManager 应用程序

当应用程序第一次启动时，将没有可用的虚拟存储空间。要创建一个，我们需要导入一些书籍。点击“导入电子书”菜单项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e0cd2007-0d91-4246-b9c2-7eae31b6aa48.png)

打开导入电子书屏幕，您可以添加新的存储空间并选择电子书的源文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a9a81038-8899-4d89-adbe-b83353339422.png)

一旦你选择了一本电子书，添加有关该书的适用信息并将其保存到存储空间：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/379bc6c2-2c03-493f-85e9-4c4ce9ddf0a1.png)

添加了所有存储空间和电子书后，您将看到列出的虚拟存储空间。当您点击一个存储空间时，它包含的书籍将被列出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5603e606-0f2e-406d-88d5-97661ff24a51.png)

选择一本电子书并点击“阅读电子书”按钮将打开包含所选电子书的文件位置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3ba21d09-586c-4186-a98c-f4bc693b9673.png)

最后，让我们看一下为`eBook Manager`应用程序生成的**JSON**文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/cc28c3c6-53d3-45de-9ae2-04ccc777f562.png)

正如你所看到的，JSON 文件排列得很好，很容易阅读。

# 摘要

C# 7 是语言的一个很棒的版本。在本章中，我们看了`out`变量。您会记得，使用 C# 7，我们现在可以在作为 out 参数传递的地方声明变量。然后，我们看了元组，它提供了一种优雅的方式从方法中返回多个值。

接下来，我们看了“表达式体”属性，这是一种更简洁的编写代码的方式。然后，我们讨论了本地函数（我最喜欢的功能之一）及其在另一个函数中创建辅助函数的能力。如果使用本地函数的函数是唯一使用它的代码，这是有道理的。

接下来是模式匹配，它是一种语法元素，用于查看特定值是否具有特定的“形状”。这使得使用`switch`语句（例如）更加方便。最后，我们看了抛出表达式。这使得我们可以将异常抛出到我们的`expression-bodied`成员、条件和空值合并表达式中。

随着您继续使用 C# 7，您将发现更多使用这些新功能的机会。起初（至少对我来说），我不得不刻意训练自己使用新功能来编写代码（out 变量就是一个完美的例子）。

过了一会儿，这样做的便利性就变得很自然。您很快就会开始自动使用可用的新功能来编写代码。


# 第二章：板球比分计算器和跟踪器

**面向对象编程**（**OOP**）是编写.NET 应用程序的关键要素。正确的面向对象编程确保开发人员可以在项目之间轻松共享代码。你不必重写已经编写过的代码。这就是**继承**。

多年来关于面向对象编程的话题已经写了很多。事实上，在互联网上搜索面向对象编程的好处将返回无数的结果。然而，面向对象编程的基本好处是编写代码的模块化方法，代码共享的便利性以及扩展共享代码的功能。

这些小构建块（或类）是自包含的代码单元，每个都执行一个功能。开发人员在使用它时不需要知道类内部发生了什么。他们可以假设类将自行运行并始终工作。如果他们实现的类没有提供特定功能，开发人员可以自由扩展类的功能。

我们将看一下定义面向对象编程的特性，它们是：

+   继承

+   抽象

+   封装

+   多态

我们还将看一下：

+   单一职责

+   开闭原则

在本章中，我们将玩得开心。我们将创建一个 ASP.NET Bootstrap Web 应用程序，用于跟踪你两个最喜欢的球队的板球比分。正是通过这个应用程序，面向对象编程的原则将变得明显。

*板球比分跟踪器*应用程序可以在 GitHub 上找到，我鼓励你下载源代码并将其作为你自己的应用程序。GitHub 存储库的 URL 是-[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/cricketScoreTrack`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/cricketScoreTrack)。

在这样的应用程序中，一个人可以构建很多功能，但是关于面向对象编程的话题在本书中只有一个章节来传达这个话题。因此，重点是面向对象编程（而不是板球的硬性规则），并且对某些功能进行了一些自由处理。

让游戏开始！

# 设置项目

使用 Visual Studio 2017，我们将创建一个 ASP.NET Web 应用程序项目。你可以给应用程序起任何你喜欢的名字，但我把我的叫做`cricketScoreTrack`。当你点击新的 ASP.NET Web 应用程序模板时，你将看到一些 ASP.NET 模板。

ASP.NET 模板有：

+   空

+   Web Forms

+   MVC

+   Web API

+   单页应用程序

+   Azure API 应用

+   Azure 移动应用程序

我们只会选择 Web Forms 模板。对于这个应用程序，我们不需要身份验证，所以不要更改这个设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6620368d-7a9f-4d12-a455-f8799ff7d0e4.png)

我假设你也已经从 GitHub 下载了本章的应用程序，因为在讨论架构时你会需要它。URL 是-[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/cricketScoreTrack`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/cricketScoreTrack)。

点击确定创建 Web 应用程序。项目将被创建，并将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6294d3c4-b08d-41e6-9398-b510fd9e7ad0.png)

为了让你了解我们正在构建的东西，UI 将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/bc166801-1c83-4a73-90e6-ada22b17a5cb.png)

各个部分如下：

+   击球手选择（**1**在上面的截图中）

+   投手选择（**2**在上面的截图中）

+   击球手比赛统计-得分、球数、4 分、6 分、打击率（**3**在上面的截图中）

+   投手比赛统计-投掷数、无得分局数、得分、击球、经济（**4**在上面的截图中）

+   击球手得分（**5**在上面的截图中）

+   游戏动作（**6**在上面的截图中）

+   比赛得分和球队（**7**在上面的截图中）

+   当前击球手详情（**8**在上面的截图中）

+   每球和每局的得分（**9**在上面的截图中）

正如你所看到的，这里有很多事情。显然还有很多地方可以继续扩展。另一个有趣的想法是添加一个游戏统计面板，甚至是 Duckworth-Lewis 计算，如果你有时间去尝试实现的话。我说尝试，因为实际的计算算法是一个秘密。

然而，在网上有很多实现，我特别感兴趣的是 Sarvashrestha Paliwal 的文章，他是*微软印度的 Azure 业务负责人*。他们使用机器学习来分析历史板球比赛，从而提供不断改进的 Duckworth-Lewis 计算。

你可以在以下链接阅读他的文章-[`azure.microsoft.com/en-us/blog/improving-the-d-l-method-using-machine-learning/`](https://azure.microsoft.com/en-us/blog/improving-the-d-l-method-using-machine-learning/)。

让我们更仔细地看一下应用程序结构。展开`Scripts`文件夹，你会注意到应用程序使用了 jQuery 和 Bootstrap：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/473de118-1184-455a-9a14-86930a820014.png)

展开`Content`文件夹，你会看到正在使用的 CSS 文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/62e33e7b-96ef-42a3-8da5-5689289bd1bb.png)

请注意，这个文件夹中有一个我添加的`custom.css`文件：

```cs
.score { 
    font-size: 40px; 
} 
.team { 
    font-size: 30px; 
} 
.player { 
    font-size: 16.5px; 
} 
.info { 
    font-size: 18px; 
} 
.btn-round-xs { 
    border-radius: 11px; 
    padding-left: 10px; 
    padding-right: 10px; 
    width: 100%; 
} 
.btn-round { 
    border-radius: 17px; 
} 
.navbar-top-links { 
    margin-right: 0; 
} 
.nav { 
    padding-left: 0; 
    margin-bottom: 0; 
    list-style: none; 
} 
```

这个 CSS 文件基本上是为表单上的按钮和一些其他文本字体设置样式。这个 CSS 并不复杂。Bootstrap、jQuery、JavaScript 和 CSS 文件的原因是为了在网页上启用 Bootstrap 功能。

为了看到 Bootstrap 的效果，我们将使用 Chrome 来运行 Web 应用程序。

本书使用的 Chrome 版本是 Version 60.0.3112.90 (Official Build) (64-bit)。

通过在菜单上点击 Debug 并点击 Start Without Debugging 或按*Ctrl* + *F5*来运行板球比分跟踪器 Bootstrap Web 应用程序。当 Web 应用程序在 Chrome 中加载后，按*Ctrl* + *Shift* + *I*打开开发者工具：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6931fb6e-bc77-4d29-8e6b-0bcb05c5bdc4.png)

在屏幕左上角，点击切换设备工具栏按钮或按*Ctrl* + *Shift* + *M*。

Chrome 然后会将应用程序呈现为在移动设备上看到的样子。从工具栏到顶部，你会看到应用程序已经呈现为在 iPhone 6 Plus 上的样子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f16a8689-f7ad-4465-b426-72538c93894b.png)

点击设备类型，你可以改变你想要呈现页面的设备。将其改为 iPad Pro 会相应地呈现页面。你也可以模拟设备的旋转：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f466ea4f-806e-41b5-81de-c3696caf128b.png)

这个功能非常强大，允许现代 Web 开发人员测试他们的 Web 应用程序的响应性。如果在为特定设备呈现应用程序后，发现有些地方看起来不太对劲，你需要去调查你哪里出错了。

在撰写本文时，支持的设备有：

+   BlackBerry Z30 和 PlayBook

+   Galaxy Note 3，Note II，S3 和 S5

+   Kindle Fire HDX

+   LG Optimus L70

+   带有 HiDPI 屏幕和 MDPI 屏幕的笔记本电脑

+   带触摸的笔记本电脑

+   Microsoft Lumina 550 和 950

+   Nexus 7, 6, 5, 4, 10, 5X 和 6P

+   Nokia Lumina 520

+   Nokia N9

+   iPad Mini

+   iPhone 4, 5, 6 和 6 Plus

+   iPad 和 iPad Pro

要添加设备，转到设备菜单底部。在分隔符之后，有一个 Edit...菜单项。点击它将带你到模拟设备屏幕。

查看模拟设备屏幕，你会注意到表单右侧有额外的设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/816cbc41-8bdd-4247-b941-06be608bb54a.png)

对于开发人员来说，一个突出的设置应该是 Throttling 设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0430460b-e316-4064-813a-dff88ef69e44.png)

正如名字所示，Throttling 允许你测试你的应用程序，就好像它在一个较慢的连接上运行一样。然后你可以测试功能，并确保你的 Web 应用程序尽可能地优化，以确保它在较慢的连接上能够良好运行。

回到 Visual Studio 2017 中的解决方案资源管理器，看看名为`BaseClasses`、`Classes`和`Interfaces`的文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/252af8f1-e776-45f9-9554-3497d45a8f46.png)

这些文件夹包含了整个章节的精髓。在这里，我们将看到面向对象编程的本质以及面向对象编程如何提供更好的方法来在代码中建模现实世界的场景（板球比赛）。

# 面向对象编程

正如前面简要提到的，面向对象编程提供了一种模块化的方法来编写自包含的代码单元。面向对象编程的概念围绕着我们所说的**面向对象编程的四大支柱**。

它们如下：

+   抽象

+   多态性

+   继承

+   封装

顺序并不重要，但我总是按照这个顺序写四大支柱，因为我使用**A PIE**这个记忆法来记住每一个。让我们更详细地讨论每个概念。

# 抽象

抽象描述了某件事应该做什么，而不实际展示如何做。根据微软文档：

“抽象是描述合同但不提供合同完整实现的类型。”

作为抽象的示例包括**抽象类**和**接口**。.NET Framework 中的抽象示例包括`Stream`、`IEnumerable<T>`和`Object`。如果抽象主题现在看起来有点模糊，不要担心。我将在封装和封装与抽象之间的区别部分中更详细地讨论。

# 多态性

你可能听说过多态性被称为面向对象编程的第三支柱。但如果我按照上面的顺序写，我的记忆法就不再起作用了！

多态性是一个希腊词，指的是具有许多形状或形式的东西。我们将在稍后的*板球比分跟踪*应用中看到这一点的例子。只需记住它有两个明显的方面：

+   在运行时，从基类派生的类可以被视为继承的类的对象。这在参数、集合和数组中都可以看到。

+   基类可以定义派生类将覆盖的**虚拟方法**。派生类然后提供它们自己对被覆盖方法的实现。

多态性是面向对象编程中非常强大的特性。

# 编译时多态性与运行时多态性

在我们继续之前，让我停顿一分钟，解释一下前面两个关于多态性的要点。

当我们说**编译时多态**时，我们是说我们将声明具有相同名称但不同签名的方法。因此，相同的方法可以根据接收到的签名（参数）执行不同的功能。这也被称为早期绑定、重载或静态绑定。

当我们说**运行时多态**时，我们是说我们将声明具有相同名称和相同签名的方法。例如，在基类中，该方法被派生类中的方法覆盖。这是通过我们所谓的继承和使用`virtual`或`override`关键字实现的。运行时多态也被称为*延迟绑定*、*覆盖*或*动态绑定*。

# 继承

能够创建自己的类，重用、扩展和修改基类定义的行为的能力被称为**继承**。另一个重要的方面是理解派生类只能直接继承单个基类。

这是否意味着你只能继承单个基类中定义的行为？是的，也不是。继承是具有传递性的。

为了解释这一点，想象一下你有三个类：

+   `Person`

+   `Pedestrian`

+   `Driver`

`Person`类是基类。`Pedestrian`继承自`Person`类，因此`Pedestrian`继承了`Person`类中声明的成员。`Driver`类继承自`Pedestrian`类，因此`Driver`继承了`Pedestrian`和`Person`中声明的成员：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7e123f4c-baf2-4cb9-af71-e25b62f56cb4.png)

这就是我们所说的继承是传递的意思。您只能从一个类继承，但您会得到从您继承的类本身继承的所有成员。 换句话说，`Driver`类只能从一个基类继承（在前面的图像中，`Pedestrian`类）。这意味着因为`Pedestrian`类继承自`Person`类，而`Driver`类继承自`Pedestrian`类，所以`Driver`类也继承了`Person`类中的成员。

# 封装

简而言之，这意味着类的内部工作（实现细节）不一定与外部代码共享。请记住，我们之前提到过类是您只想要使用并期望它能够工作的东西。类向调用代码公开它需要的内容，但它对实现的内部工作保持严格控制。

因此，您可以通过将变量、属性和方法作用域设置为`private`来隐藏它们。这样，您可以保护类内部包含的数据免受意外损坏。

# 封装与抽象

让我们再次停下来看看这个概念，因为它会让开发人员感到困惑（而且有点令人困惑，所以例子会帮助很多）。问题的一部分源于定义：

+   **抽象**：只显示必要的内容

+   **封装**：隐藏复杂性

如果我们必须考虑一个基本的类来加密一些文本，我们需要花一点时间来决定这个类必须做什么。我想象这个类需要：

+   为文本获取一个字符串值

+   有一种方法可以加密文本

因此，让我们编写代码：

```cs
public class EncryptionHelper
{
  public string TextToEncrypt = "";
  public void Encrypt()
  {
  }
}
```

我也知道，如果我想要加密一些文本，我需要一个随机生成的字节数组来给要加密的文本加盐。让我们添加这个方法：

```cs
public class EncryptionHelper
{
  public string TextToEncrypt = "";
  public void Encrypt()
  {
  }
  public string GenerateSalt()
  {
    Return "";
  }
}
```

现在再看一下类，我意识到加密文本需要保存在数据库中。所以，我添加了一个方法来做到这一点：

```cs
public class EncryptionHelper
{
  public string TextToEncrypt = "";
  public void Encrypt()
  {
  }
  public string GenerateSalt()
  {
    return "";
  }
  public void SaveToDatabase()
  {
  }
}
```

如果我们必须实现这个类，它会看起来像这样：

```cs
EncryptionHelper encr = new EncryptionHelper();
encr.TextToEncrypt = "Secret Text";
string salt = encr.GenerateSalt();
encr.Encrypt();
encr.SaveToDatabase();
```

好吧，但现在我们看到有一个问题。`salt`需要被加密方法使用，所以自然我们会想要在`Encrypt()`方法中添加一个参数来接受`salt`。因此，我们会这样做：

```cs
public void Encrypt(string salt)
{
}
```

在这里，代码开始变得有点模糊。我们在类上调用一个方法来生成一个`salt`。然后我们将从类中生成的`salt`传回类。想象一个有许多方法的类。哪些方法需要在何时调用，以及以什么顺序？

所以，让我们退一步思考。我们到底想要做什么？我们想要加密一些文本。因此，我们只想要以下内容：

```cs
public class EncryptionHelper
{
  public string TextToEncrypt = "";
  public void Encrypt()
  {
  }
}
```

这就是我们所说的**抽象**。回顾抽象的定义，我们在代码中所做的与定义相符，因为我们只显示必要的内容。

那么类中的其他方法呢？很简单地说...将它们设为`private`。实现您的类的开发人员不需要知道如何加密文本字符串。实现您的类的开发人员只想要加密字符串并将其保存。代码可以这样**封装**：

```cs
public class EncryptionHelper
{
  public string TextToEncrypt = "";
  public void Encrypt()
  {
    string salt = GenerateSalt();
    // Encrypt the text in the TextToEncrypt variable
    SaveToDatabase();
  }
  private string GenerateSalt()
  {
    return "";
  }
  private void SaveToDatabase()
  {
  }
}
```

调用加密类的代码现在也简单得多。它看起来像这样：

```cs
EncryptionHelper encr = new EncryptionHelper();
encr.TextToEncrypt = "Secret Text";
encr.Encrypt();
```

再次，这符合**封装**的定义，即隐藏复杂性。

请注意，前面加密示例中的代码没有任何实现。我只是在这里阐述一个概念。如果您愿意，您可以自由添加自己的实现。

最后，不要将抽象与抽象类混淆。这些是不同的东西。抽象是一种思维方式。我们将在下一节中看看抽象类。

因此，请休息 5 分钟，呼吸新鲜空气或喝杯咖啡，然后回来，做好准备！事情即将变得有趣。

# 板球比分跟踪器中的类

根据我们已经学到的面向对象编程的四大支柱，我们将看看我们的应用程序中使用这些概念提供*板球比分跟踪器*的构建模块的领域。

# 抽象类

打开`BaseClasses`文件夹，双击`Player.cs`文件。您将看到以下代码：

```cs
namespace cricketScoreTrack.BaseClasses 
{ 
    public abstract class Player 
    { 
        public abstract string FirstName { get; set; } 
        public abstract string LastName { get; set; } 
        public abstract int Age { get; set; } 
        public abstract string Bio { get; set; } 
    } 
} 
```

这是我们的**抽象类**。类声明中的`abstract`修饰符和属性告诉我们，我们将要修改的东西具有缺失或不完整的实现。因此，它只用作基类。任何标记为抽象的成员必须由派生自我们的`Player`抽象类的类实现。

抽象修饰符与以下内容一起使用：

+   类

+   方法

+   属性

+   索引器

+   事件

如果我们在抽象的`Player`类中包含一个名为`CalculatePlayerRank()`的方法，那么我们需要在任何从`Player`派生的类中提供该方法的实现。

因此，在`Player`抽象类中，该方法将被定义如下：

```cs
abstract public int CalculatePlayerRank(); 
```

在任何派生类中，Visual Studio 2017 将运行代码分析器，以确定抽象类的所有成员是否已被派生类实现。当您让 Visual Studio 2017 在派生类中实现抽象类时，方法主体默认为`NotImplementedException()`：

```cs
public override int CalculatePlayerRank() 
{ 
  throw new NotImplementedException(); 
} 
```

这是因为您尚未为`CalculatePlayerRank()`方法提供任何实现。要做到这一点，您需要用实际的工作代码替换`throw new NotImplementedException();`来计算当前球员的排名。

有趣的是，虽然`NotImplementedException()`在`CalculatePlayerRank()`方法的主体内部，但它并没有警告您该方法没有返回 int 值。

抽象类可以被视为需要完成的蓝图。如何完成由开发人员决定。

# 接口

打开`Interfaces`文件夹，查看`IBatter.cs`和`IBowler.cs`文件。`IBatter`接口如下所示：

```cs
namespace cricketScoreTrack.Interfaces 
{ 
    interface IBatter 
    { 
        int BatsmanRuns { get; set; }         
        int BatsmanBallsFaced { get; set; }         
        int BatsmanMatch4s { get; set; }         
        int BatsmanMatch6s { get; set; }         
        double BatsmanBattingStrikeRate { get; }             
    } 
} 
```

查看`IBowler`接口，您将看到以下内容：

```cs
namespace cricketScoreTrack.Interfaces 
{ 
    interface IBowler 
    { 
        double BowlerSpeed { get; set; } 
        string BowlerType { get; set; }  
        int BowlerBallsBowled { get; set; } 
        int BowlerMaidens { get; set; }         
        int BowlerWickets { get; set; }         
        double BowlerStrikeRate { get; }         
        double BowlerEconomy { get; }  
        int BowlerRunsConceded { get; set; } 
        int BowlerOversBowled { get; set; } 
    } 
} 
```

接口将仅包含方法、属性、事件或索引器的签名。如果我们需要向接口添加一个计算球旋转的方法，它将如下所示：

```cs
void CalculateBallSpin(); 
```

在实现上，我们会看到以下代码实现：

```cs
void CalculateBallSpin()
{
}
```

下一个合乎逻辑的问题可能是**抽象类**和**接口**之间的区别是什么。让我们转向微软的优秀文档网站—[`docs.microsoft.com/en-us/`](https://docs.microsoft.com/en-us/)。

打开微软文档后，尝试使用深色主题。主题切换在页面右侧，评论、编辑和分享链接的下方。对于夜猫子来说，这真的很棒。

微软用以下语句简洁地总结了接口：

接口就像抽象基类。实现接口的任何类或结构都必须实现其所有成员。

将接口视为动词；也就是说，接口描述某种动作。板球运动员所做的事情。在这种情况下，动作是击球和投球。因此，在*板球比分跟踪器*中，接口分别是`IBatter`和`IBowler`。请注意，约定规定接口以字母`I`开头。

另一方面，抽象类充当告诉您某物是什么的名词。我们有击球手和全能选手。我们可以说这两位板球运动员都是球员。这是描述板球比赛中板球运动员的普通名词。因此，在这里使用`Player`抽象类是有意义的。

# 类

*Cricket Score Tracker*应用程序中使用的类都在`Classes`文件夹中创建。在这里，你会看到一个`Batsman`类和一个`AllRounder`类。为了简单起见，我只创建了这两个类。在板球中，所有投手都必须击球，但并非所有击球手都必须投球。然后你会得到能够击球和投球同样出色的投手，他们被定义为全能手。这就是我在这里建模的内容。

首先让我们看一下`Batsman`类。我们希望击球手具有球员的抽象属性，但他也必须是击球手。因此，我们的类继承了`Player`基类（记住，我们只能继承自一个类），并实现了`IBatter`接口的属性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/831a0232-6c6d-4224-b12e-78c3279d9347.png)

因此，类定义读作`Batsman`公共类，继承自`Player`，并实现`IBatter`接口。因此，`Batsman`类如下所示：

```cs
using cricketScoreTrack.BaseClasses; 
using cricketScoreTrack.Interfaces; 

namespace cricketScoreTrack.Classes 
{ 
    public class Batsman : Player, IBatter 
    { 
        #region Player 
        public override string FirstName { get; set; } 
        public override string LastName { get; set; } 
        public override int Age { get; set; } 
        public override string Bio { get; set; } 
        #endregion 

        #region IBatsman 
        public int BatsmanRuns { get; set; } 
        public int BatsmanBallsFaced { get; set; } 
        public int BatsmanMatch4s { get; set; } 
        public int BatsmanMatch6s { get; set; } 

        public double BatsmanBattingStrikeRate => (BatsmanRuns * 100) 
         / BatsmanBallsFaced;  

        public override int CalculatePlayerRank() 
        { 
            return 0; 
        } 
        #endregion 
    } 
} 
```

请注意，`Batsman`类实现了抽象类和接口的属性。同时，请注意，此时我不想为`CalculatePlayerRank()`方法添加实现。

现在让我们看一下`AllRounder`类。我们希望全能手也具有球员的抽象属性，但他们也必须是击球手和投球手。因此，我们的类继承了`Player`基类，但现在实现了`IBatter`和`IBowler`接口的属性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e3e9d4d8-759e-4f37-985a-6deca302a550.png)

因此，类定义读作`AllRounder`公共类，继承自`Player`，并实现`IBatter`和`IBowler`接口。因此，`AllRounder`类如下所示：

```cs
using cricketScoreTrack.BaseClasses; 
using cricketScoreTrack.Interfaces; 
using System; 

namespace cricketScoreTrack.Classes 
{ 
    public class AllRounder : Player, IBatter, IBowler         
    { 
        #region enums 
        public enum StrikeRate { Bowling = 0, Batting = 1 } 
        #endregion 

        #region Player 
        public override string FirstName { get; set; } 
        public override string LastName { get; set; } 
        public override int Age { get; set; } 
        public override string Bio { get; set; } 
        #endregion 

        #region IBatsman 
        public int BatsmanRuns { get; set; } 
        public int BatsmanBallsFaced { get; set; } 
        public int BatsmanMatch4s { get; set; } 
        public int BatsmanMatch6s { get; set; } 
        public double BatsmanBattingStrikeRate => 
         CalculateStrikeRate(StrikeRate.Batting);  
        #endregion 

        #region IBowler 
        public double BowlerSpeed { get; set; } 
        public string BowlerType { get; set; }  
        public int BowlerBallsBowled { get; set; } 
        public int BowlerMaidens { get; set; } 
        public int BowlerWickets { get; set; } 
        public double BowlerStrikeRate => 
         CalculateStrikeRate(StrikeRate.Bowling);  
        public double BowlerEconomy => BowlerRunsConceded / 
         BowlerOversBowled;  
        public int BowlerRunsConceded  { get; set; } 
        public int BowlerOversBowled { get; set; } 
        #endregion 

        private double CalculateStrikeRate(StrikeRate strikeRateType) 
        { 
            switch (strikeRateType) 
            { 
                case StrikeRate.Bowling: 
                    return (BowlerBallsBowled / BowlerWickets); 
                case StrikeRate.Batting: 
                    return (BatsmanRuns * 100) / BatsmanBallsFaced; 
                default: 
                    throw new Exception("Invalid enum"); 
            } 
        } 

        public override int CalculatePlayerRank() 
        { 
            return 0; 
        } 
    } 
} 
```

你会再次注意到，我没有为`CalculatePlayerRank()`方法添加任何实现。因为抽象类定义了这个方法，所有继承自抽象类的类都必须实现这个方法。

现在你也看到`AllRounder`类必须实现`IBowler`和`IBatter`的属性。

# 把所有东西放在一起

现在，让我们看一下如何使用这些类来创建*Cricket Score Tracker*应用程序。在击球手部分和投球手部分下面的按钮用于选择特定局的击球手和投球手。

虽然每个按钮都由自己的点击事件处理，但它们都调用完全相同的方法。我们稍后将看一下是如何实现的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/24028b13-060e-4243-a892-b968a5e3f407.png)

点击 Batsmen 部分下的任一按钮将显示一个带有填充有该队伍中击球手的下拉列表的模态对话框：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/56998740-9ac9-4b01-a6cc-f02e7f824cb1.png)

同样，当我们点击选择投球手按钮时，我们将看到完全相同的模态对话框屏幕显示。不过这次，它将显示可供选择的投球手列表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/1d699c73-6536-43c9-bc12-bd70d4f5b03d.png)

从下拉列表中选择球员将填充按钮点击时显示的文本为该球员的名字。然后设置当前局的参与球员。

请注意，我们在这里谈论的是类。我们有球员，但他们可以是击球手或全能手（投球手）。

每个球员都是击球手或投球手（`AllRounder`类）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/bd46254e-7dde-40a7-b76a-eb1e22968cbd.png)

那么我们是如何让一个方法返回两个不同的球员的呢？我使用了一个叫做`GeneratePlayerList()`的方法。这个方法负责在弹出的模态对话框中创建球员列表。这就是这个方法的全部责任。换句话说，它除了生成球员列表之外不执行任何其他功能。

让我们来看一下`Default.aspx.cs`文件是如何创建的。为了简单起见，我只为每个队伍创建了两个列表。我还创建了一个用于选择球员的`enum`。代码如下：

```cs
public enum SelectedPlayer { Batsman1 = 1, Batsman2 = 2, Bowler = 3 } 
List<Player> southAfrica; 
List<Player> india; 
```

然而，实际上，你可能会将列表名称命名为`team1`和`team2`，并允许用户从设置屏幕上选择这场比赛的队伍。我没有添加这个功能，因为我只是想在这里说明面向对象编程的概念。

在`Page_Load`中，我用以下方法填充列表：

```cs
protected void Page_Load(object sender, EventArgs e) 
{ 
    southAfrica = Get_SA_Players(); 
    india = Get_India_Players(); 
} 
```

再次为了简单起见，我已经将球员的名字硬编码并手动添加到列表中。

`Get_India_Players()`方法与`Get_SA_Players()`方法是相同的。然后你可以复制这个方法，将名字改成你最喜欢的板球运动员或最喜欢的板球队。

实际上，你可能会从一个团队和球员的数据库中读取这些信息。所以，你不会有`Get_SA_Players()`和`Get_India_Players()`，而是会有一个单一的`Get_Players()`方法，负责将球员读入列表中。

现在，看看`Get_SA_Players()`方法，我们只是做以下操作：

```cs
private List<Player> Get_SA_Players() 
{ 
    List<Player> players = new List<Player>(); 

    #region Batsmen 
    Batsman b1 = new Batsman(); 
    b1.FirstName = "Faf"; 
    b1.LastName = "du Plessis"; 
    b1.Age = 33; 
    players.Add(b1); 
    // Rest omitted for brevity 
    #endregion 

    #region All Rounders 
    AllRounder ar1 = new AllRounder(); 
    ar1.FirstName = "Farhaan"; 
    ar1.LastName = "Behardien"; 
    ar1.Age = 33; 
    players.Add(ar1); 
    // Rest omitted for brevity 
    #endregion 

    return players; 
} 
```

现在注意到`players`列表的类型是`List<Player>`，我们正在向其中添加`Batsman`和`AllRounder`类型。这就是**多态性**的含义。记住我们之前提到的多态性的一个方面是：

在运行时，从基类派生的类可以被视为它继承的类的对象。这在参数、集合或数组中可以看到。

因此，因为`Batsman`和`AllRounder`都继承自`Player`抽象类，它们被视为`List<Player>`的对象。

如果你回到本章前面关于多态性的部分，你会发现这是运行时多态性的一个例子。

回到选择击球手或投球手的逻辑，我们寻找一个生成球员列表的方法，称为`GeneratePlayerList()`：

```cs
private void GeneratePlayerList(List<Player> team, Type type) 
{ 
    List<string> players = new List<string>(); 

    if (type == typeof(Batsman)) 
        players = (from r in team.OfType<Batsman>() 
                   select $"{r.FirstName} {r.LastName}").ToList(); 

    if (type == typeof(AllRounder)) 
        players = (from r in team.OfType<AllRounder>() 
                   select $"{r.FirstName} {r.LastName}").ToList(); 

    int liVal = 0; 
    if (ddlPlayersSelect.Items.Count > 0) 
        ddlPlayersSelect.Items.Clear(); 

    foreach (string player in players) 
    { 
        ListItem li = new ListItem(); 
        li.Text = player.ToString(); 
        li.Value = liVal.ToString(); 
        ddlPlayersSelect.Items.Add(li); 

        liVal += 1; 
    } 
} 
```

你会注意到这个方法接受一个`List<Player>`参数和一个`Type`。该方法检查`type`是`Batsman`还是`AllRounder`，并基于此读取列表中球员的名字。

我相信这种方法甚至可以进一步简化，但我想说明多态性的概念。

实际目标是尽量用最少的代码实现最大的效果。作为一个经验法则，一些开发人员认为，如果一个方法的长度超过了你在 IDE 中看到的代码页，你需要进行一些重构。

更少的代码和更小的方法使得代码更易于阅读和理解。它还使得代码更易于维护，因为更小的代码段更容易调试。事实上，你可能会遇到更少的 bug，因为你正在编写更小、更易管理的代码片段。

许多年前，我曾是开普敦一家大公司项目团队的一员。他们有一个名叫*乌斯曼·亨德里克斯*的系统架构师。我永远不会忘记这个家伙。他是我见过的最谦逊的家伙。他为我们所做系统的文档简直令人难以置信。几乎所有的思考工作都已经包含在我们需要编写的代码中。开发人员根本不需要决定如何设计项目。

这个项目实现了 SOLID 原则，理解代码真的很容易。我现在还有那份文档的副本。我时不时地会参考它。不幸的是，并不是所有的开发人员都有幸在他们所工作的项目中有一个专门的系统架构师。然而，开发人员了解 SOLID 设计原则是很有好处的。

# SOLID 设计原则

这引出了面向对象编程中另一个有趣的概念，叫做**SOLID**设计原则。这些设计原则适用于任何面向对象的设计，旨在使软件更易于理解、更灵活和更易于维护。

SOLID 是一个记忆术，代表：

+   单一职责原则

+   开放/封闭原则

+   里氏替换原则

+   接口隔离原则

+   依赖反转原则

在本章中，我们只会看一下前两个原则——**单一责任原则**和**开闭原则**。让我们接下来看一下单一责任原则。

# 单一责任原则

简而言之，一个模块或类应该只具有以下特征：

+   它应该只做一件事情，并且只有一个改变的原因

+   它应该很好地完成它的单一任务

+   提供的功能需要完全由该类或模块封装

说一个模块必须负责一件事情是什么意思？谷歌对模块的定义是：

“一组标准化的部分或独立单元，可以用来构建更复杂的结构，比如家具或建筑物。”

由此，我们可以理解模块是一个简单的构建块。当与其他模块一起使用时，它可以被使用或重复使用来创建更大更复杂的东西。因此，在 C#中，模块确实与类非常相似，但我会说模块也可以扩展为一个方法。

类或模块执行的功能只能是一件事情。也就是说，它有一个**狭窄的责任**。它只关心它被设计来做的那一件事情，而不关心其他任何事情。

如果我们必须将单一责任原则应用于一个人，那么这个人只能是一个软件开发人员，例如。但如果一个软件开发人员也是医生、机械师和学校老师呢？那这个人在任何一个角色中都会有效吗？这将违反单一责任原则。对于代码也是如此。

看一下我们的`AllRounder`和`Batsman`类，你会注意到在`AllRounder`中，我们有以下代码：

```cs
private double CalculateStrikeRate(StrikeRate strikeRateType) 
{ 
    switch (strikeRateType) 
    { 
        case StrikeRate.Bowling: 
            return (BowlerBallsBowled / BowlerWickets); 
        case StrikeRate.Batting: 
            return (BatsmanRuns * 100) / BatsmanBallsFaced; 
        default: 
            throw new Exception("Invalid enum"); 
    } 
} 

public override int CalculatePlayerRank() 
{ 
    return 0; 
} 

```

在`Batsman`中，我们有以下代码：

```cs
public double BatsmanBattingStrikeRate => (BatsmanRuns * 100) / BatsmanBallsFaced;  

public override int CalculatePlayerRank() 
{ 
    return 0; 
} 
```

利用我们对单一责任原则的了解，我们注意到这里存在一个问题。为了说明问题，让我们将代码并排比较：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/25126aec-6d16-4015-be30-41596360896f.png)

在`Batsman`和`AllRounder`类中，我们实际上在重复代码。这对于单一责任来说并不是一个好兆头，对吧？我的意思是，一个类只能有一个功能。目前，`Batsman`和`AllRounder`类都负责计算击球率。它们也都负责计算球员排名。它们甚至都有完全相同的代码来计算击球手的击球率！

问题出现在击球率计算发生变化时（虽然不太容易发生，但让我们假设它发生了）。我们现在知道我们必须在两个地方改变计算。一旦开发人员只改变了一个计算而没有改变另一个，就会在我们的应用程序中引入一个 bug。

让我们简化我们的类。在`BaseClasses`文件夹中，创建一个名为`Statistics`的新的抽象类。代码应该如下所示：

```cs
namespace cricketScoreTrack.BaseClasses 
{ 
    public abstract class Statistics 
    { 
        public abstract double CalculateStrikeRate(Player player); 
        public abstract int CalculatePlayerRank(Player player); 
    } 
} 
```

在`Classes`文件夹中，创建一个名为`PlayerStatistics`的新派生类（也就是它继承自`Statistics`抽象类）。代码应该如下所示：

```cs
using cricketScoreTrack.BaseClasses; 
using System; 

namespace cricketScoreTrack.Classes 
{ 
    public class PlayerStatistics : Statistics 
    { 
        public override int CalculatePlayerRank(Player player) 
        { 
            return 1; 
        } 

        public override double CalculateStrikeRate(Player player) 
        {             
            switch (player) 
            { 
                case AllRounder allrounder: 
                    return (allrounder.BowlerBallsBowled / 
                     allrounder.BowlerWickets); 

                case Batsman batsman: 
                    return (batsman.BatsmanRuns * 100) / 
                     batsman.BatsmanBallsFaced; 

                default: 
                    throw new ArgumentException("Incorrect argument 
                     supplied"); 
            } 
        } 
    } 
} 
```

你会看到`PlayerStatistics`类现在完全负责计算球员的排名和击球率的统计数据。

你会看到我没有包括计算球员排名的实现。我在 GitHub 上简要评论了这个方法，说明了球员排名是如何确定的。这是一个相当复杂的计算，对于击球手和投球手是不同的。因此，我在这一章关于面向对象编程的目的上省略了它。

你的解决方案现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/61d01824-3ddf-4b48-b0bb-9888f267f147.png)

回到你的`Player`抽象类，从类中移除`abstract public int CalculatePlayerRank();`。在`IBowler`接口中，移除`double BowlerStrikeRate { get; }`属性。在`IBatter`接口中，移除`double BatsmanBattingStrikeRate { get; }`属性。

在`Batsman`类中，从类中移除`public double BatsmanBattingStrikeRate`和`public override int CalculatePlayerRank()`。现在`Batsman`类的代码如下：

```cs
using cricketScoreTrack.BaseClasses; 
using cricketScoreTrack.Interfaces; 

namespace cricketScoreTrack.Classes 
{ 
    public class Batsman : Player, IBatter 
    { 

        #region Player 
        public override string FirstName { get; set; } 
        public override string LastName { get; set; } 
        public override int Age { get; set; } 
        public override string Bio { get; set; } 
        #endregion 

        #region IBatsman 
        public int BatsmanRuns { get; set; } 
        public int BatsmanBallsFaced { get; set; } 
        public int BatsmanMatch4s { get; set; } 
        public int BatsmanMatch6s { get; set; } 
        #endregion 
    } 
} 
```

看看`AllRounder`类，移除`public enum StrikeRate { Bowling = 0, Batting = 1 }`枚举，以及`public double BatsmanBattingStrikeRate`和`public double BowlerStrikeRate`属性。

最后，移除`private double CalculateStrikeRate(StrikeRate strikeRateType)`和`public override int CalculatePlayerRank()`方法。现在`AllRounder`类的代码如下：

```cs
using cricketScoreTrack.BaseClasses; 
using cricketScoreTrack.Interfaces; 
using System; 

namespace cricketScoreTrack.Classes 
{ 
    public class AllRounder : Player, IBatter, IBowler 
    { 
        #region Player 
        public override string FirstName { get; set; } 
        public override string LastName { get; set; } 
        public override int Age { get; set; } 
        public override string Bio { get; set; } 
        #endregion 

        #region IBatsman 
        public int BatsmanRuns { get; set; } 
        public int BatsmanBallsFaced { get; set; } 
        public int BatsmanMatch4s { get; set; } 
        public int BatsmanMatch6s { get; set; } 
        #endregion 

        #region IBowler 
        public double BowlerSpeed { get; set; } 
        public string BowlerType { get; set; }  
        public int BowlerBallsBowled { get; set; } 
        public int BowlerMaidens { get; set; } 
        public int BowlerWickets { get; set; } 
        public double BowlerEconomy => BowlerRunsConceded / 
         BowlerOversBowled;  
        public int BowlerRunsConceded  { get; set; } 
        public int BowlerOversBowled { get; set; } 
        #endregion         
    } 
} 
```

回顾一下我们的`AllRounder`和`Batsman`类，代码显然更简化了。它肯定更灵活，开始看起来像一组构建良好的类。重新构建你的解决方案，确保一切正常运行。

# 开闭原则

之前，我们已经看过**单一职责原则**。与此相辅相成的是**开闭原则**。

Bertrand Meyer 说过，软件实体（类、模块、函数等）：

+   应该对扩展开放

+   应该对修改关闭

这到底意味着什么？让我们以`PlayerStatistics`类为例。在这个类中，你知道我们有一个方法来计算特定球员的击球率。这是因为它继承自`Statistics`抽象类。这是正确的，但`CalculateStrikeRate(Player player)`方法为两种球员类型（全能选手和击球手）提供服务，这已经是一个问题的暗示。

假设我们引入了新的球员类型——不同的投球手类型（例如快速投球手和旋转投球手）。为了适应新的球员类型，我们必须改变`CalculateStrikeRate()`方法中的代码。

如果我们想要传递一组击球手来计算他们之间的平均击球率，我们需要再次修改`CalculateStrikeRate()`方法来适应这一点。随着时间的推移和复杂性的增加，为不同需要击球率计算的球员类型提供服务将变得非常困难。这意味着我们的`CalculateStrikeRate()`方法是**对修改开放**但**对扩展关闭**。这违反了之前列出的原则。

那么，我们该怎么做才能解决这个问题呢？事实上，我们已经走了一半的路。首先，在`Classes`文件夹中创建一个新的`Bowler`类：

```cs
using cricketScoreTrack.BaseClasses; 
using cricketScoreTrack.Interfaces; 

namespace cricketScoreTrack.Classes 
{ 
    public class Bowler : Player, IBowler 
    { 
        #region Player 
        public override string FirstName { get; set; } 
        public override string LastName { get; set; } 
        public override int Age { get; set; } 
        public override string Bio { get; set; } 
        #endregion 

        #region IBowler 
        public double BowlerSpeed { get; set; } 
        public string BowlerType { get; set; }  
        public int BowlerBallsBowled { get; set; } 
        public int BowlerMaidens { get; set; } 
        public int BowlerWickets { get; set; } 
        public double BowlerEconomy => BowlerRunsConceded / 
         BowlerOversBowled;  
        public int BowlerRunsConceded { get; set; } 
        public int BowlerOversBowled { get; set; } 
        #endregion 
    } 
} 
```

你可以看到构建新的球员类型有多么容易——我们只需要告诉类它需要继承`Player`抽象类并实现`IBowler`接口。

接下来，我们需要创建新的球员统计类，即`BatsmanStatistics`、`BowlerStatistics`和`AllRounderStatistics`。`BatsmanStatistics`类的代码如下：

```cs
using cricketScoreTrack.BaseClasses; 
using System; 

namespace cricketScoreTrack.Classes 
{ 
    public class BatsmanStatistics : Statistics 
    { 
        public override int CalculatePlayerRank(Player player) 
        { 
            return 1; 
        } 

        public override double CalculateStrikeRate(Player player) 
        { 
            if (player is Batsman batsman) 
            { 
                return (batsman.BatsmanRuns * 100) / 
                 batsman.BatsmanBallsFaced; 
            } 
            else 
                throw new ArgumentException("Incorrect argument 
                 supplied"); 
        } 
    } 
} 

```

接下来，我们添加`AllRounderStatistics`类：

```cs
using cricketScoreTrack.BaseClasses; 
using System; 

namespace cricketScoreTrack.Classes 
{ 
    public class AllRounderStatistics : Statistics 
    { 
        public override int CalculatePlayerRank(Player player) 
        { 
            return 1; 
        } 

        public override double CalculateStrikeRate(Player player) 
        { 
            if (player is AllRounder allrounder) 
            { 
                return (allrounder.BowlerBallsBowled / 
                 allrounder.BowlerWickets); 
            } 
            else 
                throw new ArgumentException("Incorrect argument 
                 supplied");             
        } 
    } 
} 
```

最后，我们添加了名为`BowlerStatistics`的新球员类型统计类：

```cs
using cricketScoreTrack.BaseClasses; 
using System; 

namespace cricketScoreTrack.Classes 
{ 
    public class BowlerStatistics : Statistics 
    { 
        public override int CalculatePlayerRank(Player player) 
        { 
            return 1; 
        } 

        public override double CalculateStrikeRate(Player player) 
        { 
            if (player is Bowler bowler) 
            { 
                return (bowler.BowlerBallsBowled / 
                 bowler.BowlerWickets); 
            } 
            else 
                throw new ArgumentException("Incorrect argument 
                 supplied"); 
        } 
    } 
} 
```

将计算所有球员击球率的责任从`PlayerStatistics`类中移开，使我们的代码更清晰、更健壮。事实上，`PlayerStatistics`类已经几乎过时了。

通过添加另一种球员类型，我们能够通过实现正确的接口轻松定义这个新球员的逻辑。我们的代码更小，更容易维护。通过比较我们之前编写的`CalculateStrikeRate()`的代码和新代码，我们可以看到这一点。

为了更清楚地说明，看一下下面的代码：

```cs
public override double CalculateStrikeRate(Player player) 
{             
    switch (player) 
    { 
        case AllRounder allrounder: 
            return (allrounder.BowlerBallsBowled / 
             allrounder.BowlerWickets); 

        case Batsman batsman: 
            return (batsman.BatsmanRuns * 100) / 
             batsman.BatsmanBallsFaced; 

        case Bowler bowler: 
            return (bowler.BowlerBallsBowled / bowler.BowlerWickets); 

        default: 
            throw new ArgumentException("Incorrect argument 
             supplied"); 
    } 
} 

```

前面的代码比下面的代码复杂得多，难以维护：

```cs
public override double CalculateStrikeRate(Player player) 
{ 
    if (player is Bowler bowler) 
    { 
        return (bowler.BowlerBallsBowled / bowler.BowlerWickets); 
    } 
    else 
        throw new ArgumentException("Incorrect argument supplied"); 
} 
```

例如，创建一个`BowlerStatistics`类的好处是，你知道在整个类中我们只处理球员，没有别的东西……一个单一的责任，可以在不修改代码的情况下进行扩展。

# 总结

虽然 SOLID 编程原则是很好的指导方针，但你遇到的很少有系统会在整个应用程序中实际实现它们。特别是如果你继承了一个已经投入生产多年的系统。

我必须承认，我遇到过一些以 SOLID 为设计理念的应用程序。这些应用程序非常容易操作，对团队中的其他开发人员设定了很高的代码质量标准。

同行代码审查和团队中每个开发人员对 SOLID 原则的深入理解，确保了保持相同水平的代码质量。

这一章内容非常丰富。除了为一个非常好的*板球比分跟踪*应用程序奠定基础外，我们还深入了解了面向对象编程的真正含义。

我们研究了抽象和封装之间的区别。我们讨论了多态性，并了解了运行时多态性与编译时多态性的区别。我们还研究了继承，即通过继承基类来创建派生类。

然后我们讨论了类、抽象类（不要与抽象混淆）和接口。希望清楚地解释了抽象类和接口之间的区别。记住，接口充当动词或行为，而抽象类充当名词，说明某物是什么。

在最后一节中，我们简要讨论了 SOLID 设计原则，并强调了单一责任和开闭原则。

在下一章中，我们将深入探讨使用.NET Core 进行跨平台开发。你会发现.NET Core 是一个非常重要的技能，它将伴随我们很长一段时间。随着.NET Core 和.NET 标准的发展，开发人员将有能力创造——好吧，我会留给你来想象。天空是极限。
