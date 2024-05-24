# C#7 和 .NET Core 2.0 蓝图（三）

> 原文：[`zh.annas-archive.org/md5/7C3D5DACD7BE632FD426A045B35F94C4`](https://zh.annas-archive.org/md5/7C3D5DACD7BE632FD426A045B35F94C4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Entity Framework Core 的 Web 研究工具

“我对自己说的最大谎言是我不需要把它写下来，我会记住的。”

- 未知

所以，你有几分钟时间来赶上你的动态。当你浏览时，你看到有人分享了一篇关于记住吉他和弦的新方法的文章。你真的想读它，但现在没有足够的时间。"*我以后再读"，*你告诉自己，以后变成了永远。主要是因为你没有把它写下来。

现在有各种应用程序可以满足您保存链接以供以后使用的需求。但我们是开发人员。让我们写一些有趣的东西。

在本章中，我们将看到以下内容：

+   **Entity Framework**（**EF**）Core 历史

+   代码优先与模型优先与数据库优先方法

+   开发数据库设计

+   设置项目

+   安装 EF Core

+   创建模型

+   配置服务

+   创建数据库

+   使用测试数据填充数据库

+   创建控制器

+   运行应用程序

+   部署应用程序

这是相当多的内容，但不要担心，我们会一步一步来。让我们散步一下。

# Entity Framework（EF）Core 历史

开发应用程序时最令人沮丧的部分之一是尝试建立代码和数据库之间的通信层。

至少曾经是这样。

# 进入 Entity Framework

Entity Framework 是一个**对象关系映射器**（**ORM**）。它将您的.NET 代码对象映射到关系数据库实体。就是这么简单。现在，您不必担心为了处理普通的 CRUD 操作而搭建所需的数据访问代码。

当 Entity Framework 的第一个版本于 2008 年 8 月发布时，随着.NET 3.5 SP1 的发布，最初的反应并不是很好，以至于一群开发人员签署了一份关于该框架的*不信任投票*。幸运的是，大部分提出的问题得到了解决，随着 Entity Framework 4.0 的发布，以及.NET 4.0，许多关于框架稳定性的批评得到了解决。

微软随后决定使用.NET Core 使.NET 跨平台，这意味着 Entity Framework Core 进行了完全重写。显然，这有其利弊，因为 EF Core 和 EF6 之间的比较表明，虽然 EF Core 引入了新功能和改进，但它仍然是一个新的代码库，因此还没有 EF6 中的所有功能。

# 代码优先与模型优先与数据库优先方法

使用 Entity Framework，您可以选择三种实现方法，总是很好能够有选择。让我们快速看看它们之间的区别。

# 代码优先方法

对于硬核程序员来说，这是首选的方法，这种方法让您完全控制数据库，从代码开始。数据库被视为简单的存储位置，很可能不包含任何逻辑或业务规则。一切都由代码驱动，因此任何所需的更改也需要在代码中完成：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/623d8338-835f-4e91-b0f1-a4e1daf8d007.png)

# 模型优先方法

如果您更喜欢绘画而不是诗歌，那么您可能更喜欢模型优先方法。在这种方法中，您创建或绘制您的模型，工作流将生成一个数据库脚本。如果有必要添加特定逻辑或业务规则，您还可以使用部分类扩展模型，但这可能会变得复杂，如果有太多具体内容，最好考虑代码优先方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/35e7c4b9-3092-4064-9af2-d675ff1959b0.png)

# 数据库优先方法

数据库优先方法适用于需要从事设计和维护数据库的专职 DBA 的大型项目。Entity Framework 将根据数据库设计为您创建实体，并且您可以在数据库更改时运行模型更新：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/181149a6-fa39-48bd-a2be-6f0649df9b43.png)

# 开发数据库设计

在我们开始创建具有数据库、模型和控制器的解决方案之前，我们需要首先弄清楚我们想要如何设计数据库。

根据微软的 TechNet，有五个基本步骤可以遵循来规划数据库：

1.  收集信息

1.  识别对象

1.  对对象建模

1.  确定每个对象的信息类型

1.  确定对象之间的关系

我们的要求非常简单。我们只需要保存一个网站链接以便以后导航，因此我们不会有多个对象之间的关系。

然而，我们需要澄清我们想要为对象（网站链接）保存的信息类型。显然，我们需要 URL，但我们还需要什么？确保您了解解决方案所需的信息以及如何使用它。

以日常术语来考虑——如果您为朋友的房子写地址，您可能希望除了街道之外还有一些东西，可能是您朋友的名字或某种备注。

在我们的解决方案中，我们想知道 URL 是什么，但我们还想知道我们何时保存它，并且有一个地方可以记录笔记，以便我们可以为条目添加更多个人细节。因此，我们的模型将包含以下内容：

+   `URL`

+   `DateSaved`

+   `Notes`

我们将在开始创建模型时详细介绍，但让我们不要急于行动。我们仍然需要创建我们的项目。

# 设置项目

使用 Visual Studio 2017，创建一个 ASP.NET Core Web 应用程序。请注意，我们将采用代码优先方法来进行此项目。

1.  让我们将应用程序称为`WebResearch`。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f1925976-6f5b-4cb8-977f-8c40b65a57c2.png)

1.  在下一个屏幕上，选择 Web 应用程序（模型-视图-控制器）作为项目模板。为了保持简单，将身份验证保持为无身份验证。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7de7611b-2a21-4bb5-8f52-e02ffb0dd723.png)

1.  创建的项目将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6a272af2-966b-4321-8147-869e9ea6930c.png)

# 安装所需的包

我们需要将三个 NuGet 包安装到我们的解决方案中，这将帮助我们完成我们的任务。这是通过包管理器控制台完成的。

转到工具 | NuGet 包管理器 | 包管理器控制台：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/647dd034-8efb-4e28-bca1-7ff2ae009837.png)

# 实体框架核心 SQL Server

EF Core 提供了各种数据库提供程序，包括 Microsoft SQL Server、PostgreSQL、SQLite 和 MySQL。我们将使用 SQL Server 作为数据库提供程序。

有关数据库提供程序的完整列表，请参阅官方微软文档：[`docs.microsoft.com/en-us/ef/core/providers/index`](https://docs.microsoft.com/en-us/ef/core/providers/index)。

在控制台窗口中，输入以下命令并按*Enter*：

```cs
    Install-Package Microsoft.EntityFrameworkCore.SqlServer  
```

您应该看到几行响应显示成功安装的项目。

# 实体框架核心工具

接下来，我们将安装一些实体框架核心工具，这些工具将帮助我们根据我们的模型创建数据库。

在控制台窗口中，输入以下命令并按*Enter*：

```cs
    Install-Package Microsoft.EntityFrameworkCore.Tools  
```

再次，您应该看到几行响应显示成功安装的项目。

# 代码生成设计

我们可以使用一些 ASP.Net Core 代码生成工具来帮助我们进行脚手架搭建，而不是自己编写所有代码。

接下来在控制台窗口中，输入以下命令并按*Enter*：

```cs
    Install-Package Microsoft.VisualStudio.Web.CodeGeneration.Design
```

像往常一样，检查一下是否获得了“成功安装”的项目。

如果安装任何 NuGet 包时出现问题，可能是访问控制问题。一般来说，我会将我的 Visual Studio 设置为以管理员身份运行，这样就可以解决大部分问题。

安装完成后，我们的解决方案将在“依赖项”部分反映出添加的 NuGet 包，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/63a62d37-ed0f-4822-b3bf-c7d3bfefeeda.png)

# 创建模型

右键单击项目中的 Models 文件夹，添加一个名为`ResearchModel.cs`的类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0131dbbd-9c06-4737-8048-19aeb0fd9fdc.png)

实际上，我们需要两个类——一个是`Research`类，它是我们`entity`对象的表示，另一个是`ResearchContext`，它是`DbContext`的子类。为了简化，我们可以将这两个类都放在我们的`ResearchModel`文件中。

这是代码：

```cs
using Microsoft.EntityFrameworkCore; 
using System; 

namespace WebResearch.Models 
{ 
    public class Research 
    { 
        public int Id { get; set; } 
        public string Url { get; set; } 
        public DateTime DateSaved { get; set; } 
        public string Note { get; set; } 
    } 

    public class ResearchContext : DbContext 
    { 
        public ResearchContext(DbContextOptions<ResearchContext> 
        options) : base(options) 
        { 
        } 

        public DbSet<Research> ResearchLinks { get; set; } 
    } 
} 
```

让我们分解如下：

首先，我们有我们的`Research`类，这是我们的`entity`对象表示。如前面的*开发数据库设计*部分所述，对于每个链接，我们将保存 URL、日期和备注。ID 字段是保存信息的数据库表的标准做法。

我们的第二个类`ResearchContext`是`DbContext`的子类。这个类将有一个以`DbContextOptions`为参数的空构造函数和一个用于我们数据集合的`DbSet<TEntity>`属性。

我可以在这里给您一个关于`DbSet<Entity>`的简要概述，但我宁愿让 Visual Studio 来帮助我们。如果您将鼠标悬停在`DbSet`上，您将得到一个信息弹出窗口，其中包含您需要了解的一切：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2fe5e304-43bc-4f12-86cc-5a208cd543f6.png)

# 配置服务

在`Startup.cs`类中，在`ConfigureServices`方法中，添加以下代码的`DbContext`服务：

```cs
string connection = Configuration.GetConnectionString("LocalDBConnection"); 
services.AddDbContext<ResearchContext>(options => options.UseSqlServer(connection)); 
```

如您所见，我们从配置中设置了一个连接字符串变量，然后将其作为`DbContext`的`SqlServer`选项参数传递。

但是等等。`LocalDBConnection`是从哪里来的？我们还没有在配置中设置任何东西。现在还没有。让我们现在就搞定。

打开项目根目录中的`appsettings.json`文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b8d8d7aa-4cb9-43b9-bf9c-264d4552e09f.png)

默认情况下，您应该看到一个日志记录条目。在`Logging`部分之后添加您的`ConnectionStrings`部分，其中包含`LocalDBConnection`属性。

完整文件应该看起来像这样：

```cs
{ 
  "Logging": { 
    "IncludeScopes": false, 
    "LogLevel": { 
      "Default": "Warning" 
    } 
  }, 

  "ConnectionStrings": { 
    "LocalDBConnection": "Server=(localdb)\mssqllocaldb; 
     Database=WebResearch;  
     Trusted_Connection=True" 
  } 
} 
```

稍后，我们将看看如何连接到现有数据库，但现在我们只是连接到本地的`db`文件。

# 创建数据库

在任何应用程序的开发阶段，您的数据模型很有可能会发生变化。当这种情况发生时，您的 EF Core 模型与数据库架构不同，您必须删除过时的数据库，并根据更新后的模型创建一个新的数据库。

这都是一件有趣的事情，直到您完成了第一个实时实现，并且您的应用程序在生产环境中运行。那时，您不能去删除数据库来更改一些列。您必须确保在进行任何更改时，实时数据保持不变。

Entity Framework Core Migrations 是一个很棒的功能，它使我们能够对数据库架构进行更改，而不是重新创建数据库并丢失生产数据。`Migrations`具有很多功能和灵活性，这是一个值得花时间的话题，但现在我们只涵盖一些基础知识。

我们可以在`Package Manager Console`中使用 EF Core Migration 命令来设置、创建，并在需要时更新我们的数据库。

在`Package Manager Console`中，我们将执行以下两个命令：

1.  `Add-Migration InitialCreate`

1.  `Update-Database`

第一条命令将在项目的`Migrations`文件夹中生成用于创建数据库的代码。这些文件的命名约定是`<timestamp>_InitialCreate.cs`。

第二条命令将创建数据库并运行`Migrations`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/006032db-d6e0-4bf9-b8fd-9df901d2bb48.png)

在`InitialCreate`类中有`Note`的两种方法，`Up`和`Down`。简单地说，`Up`方法代码在升级应用程序时执行，`Down`方法代码在降级应用程序时运行。

假设我们想要向我们的`Research`模型添加一个名为`Read`的布尔属性。为了持久化该值，我们显然需要将该列添加到我们的表中，但我们不希望删除表来添加字段。使用`Migrations`，我们可以更新表而不是重新创建它。

我们将从修改我们的模型开始。在`Research`类中，添加`Read`属性。我们的类将如下所示：

```cs
public class Research 
{ 
    public int Id { get; set; } 
    public string Url { get; set; } 
    public DateTime DateSaved { get; set; } 
    public string Note { get; set; } 
    public bool Read { get; set; } 
} 
```

接下来，我们将添加一个`Migration`。我们将使用`Migration`名称来指示我们正在做什么。在`Package Manager Console`中执行以下命令：

```cs
    Add-Migration AddReseachRead
```

您会注意到我们的`Migrations`文件夹中有一个新的类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6a2d1a48-a841-4613-9de2-20cc2394b020.png)

让我们来看看底层。您会看到我们的`Up`和`Down`方法并不像`InitialCreate`类中那样为空：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7d2ffb13-fdcf-4b15-bb87-c5c4cb691038.png)

如前所述，`Up`方法在升级期间执行，`Down`方法在降级期间执行。现在我们可以看到代码，这个概念更清晰了。在`Up`方法中，我们正在添加`Read`列，在`Down`方法中，我们正在删除该列。

如果需要，我们可以对这段代码进行更改。例如，我们可以更改`Read`列的`nullable`属性，但更新代码如下所示：

```cs
protected override void Up(MigrationBuilder migrationBuilder) 
{ 
    migrationBuilder.AddColumn<bool>( 
        name: "Read", 
        table: "ResearchLinks", 
        nullable: true, 
        defaultValue: false); 
} 
```

我们还可以添加一个自定义的 SQL 查询，将所有现有条目更新为`Read`：

```cs
migrationBuilder.Sql( 
    @" 
        UPDATE Research 
        SET Read = 'true'; 
    "); 
```

我知道这不是一个很好的例子，因为你不希望每次更新数据库时都将所有的`Research`条目标记为`Read`，但希望你能理解这个概念。

但是，这段代码尚未执行。因此，当前时刻，我们的模型和数据库架构仍然不同步。

再次执行以下命令，我们就更新完毕了：

```cs
    Update-Database
```

# 用测试数据填充数据库

现在我们有一个空数据库，让我们用一些测试数据填充它。为此，我们需要创建一个在数据库创建后调用的方法：

1.  在项目中创建一个名为`Data`的文件夹。在文件夹中，添加一个名为`DbInitializer.cs`的类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2b63b0ba-d7ba-45ac-ae61-4608c3ede9b3.png)

该类有一个`Initialize`方法，该方法以我们的`ResearchContext`作为参数：

```cs
public static void Initialize(ResearchContext context) 
```

1.  在`Initialize`方法中，我们首先调用`Database.EnsureCreated`方法，确保数据库存在并在不存在时创建它：

```cs
context.Database.EnsureCreated(); 
```

1.  接下来，我们进行一个快速的`Linq`查询，检查`ResearchLinks`表是否有任何记录。论点是，如果表为空，我们希望添加一些测试数据：

```cs
if (!context.ResearchLinks.Any()) 
```

1.  然后，我们创建一个`Research`模型的数组，并添加一些测试条目。URL 可以是任何你喜欢的东西。我只是选择了一些最常见的网站：

```cs
var researchLinks = new Research[] 
{ 
 new Research{Url="www.google.com", DateSaved=DateTime.Now, 
  Note="Generated Data", Read=false}, 
       new Research{Url="www.twitter.com", DateSaved=DateTime.Now,  
  Note="Generated Data", Read=false}, 
       new Research{Url="www.facebook.com", DateSaved=DateTime.Now, 
  Note="Generated Data", Read=false}, 
       new Research{Url="www.packtpub.com", DateSaved=DateTime.Now, 
  Note="Generated Data", Read=false}, 
       new Research{Url="www.linkedin.com", DateSaved=DateTime.Now,  
  Note="Generated Data", Read=false}, 
}; 
```

1.  填充了我们的数组后，我们循环遍历它，并将条目添加到我们的上下文中，最后调用`SaveChanges`方法将数据持久化到数据库中：

```cs
foreach (Research research in researchLinks) 
{ 
 context.ResearchLinks.Add(research); 
} 
 context.SaveChanges();
```

1.  将所有内容放在一起如下所示：

```cs
using System; 
using System.Linq; 
using WebResearch.Models; 

namespace WebResearch.Data 
{ 
    public static class DbInitializer 
    { 
        public static void Initialize(ResearchContext context) 
        { 
            context.Database.EnsureCreated(); 

            if (!context.ResearchLinks.Any()) 
            { 
                var researchLinks = new Research[] 
                { 
                    new Research{Url="www.google.com", 
                     DateSaved=DateTime.Now, Note="Generated Data", 
                      Read=false}, 
                    new Research{Url="www.twitter.com", 
                      DateSaved=DateTime.Now, Note="Generated
                      Data", 
                       Read=false}, 
                    new Research{Url="www.facebook.com", 
                     DateSaved=DateTime.Now, Note="Generated Data", 
                      Read=false}, 
                    new Research{Url="www.packtpub.com", 
                     DateSaved=DateTime.Now, Note="Generated Data", 
                      Read=false}, 
                    new Research{Url="www.linkedin.com", 
                     DateSaved=DateTime.Now, Note="Generated Data", 
                      Read=false}, 
                }; 
                foreach (Research research in researchLinks) 
                { 
                    context.ResearchLinks.Add(research); 
                } 
                context.SaveChanges(); 
            } 
        } 
    } 
} 
```

# 创建控制器

控制器是 ASP.NET Core MVC 应用程序构建的基本构件。控制器内的方法称为操作。因此，我们可以说控制器定义了一组操作。这些操作处理请求，这些请求通过路由映射到特定的操作。

要了解有关控制器和操作的更多信息，请参阅 Microsoft 文档：[`docs.microsoft.com/en-us/aspnet/core/mvc/controllers/actions`](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/actions)。要了解有关路由的更多信息，请参阅 Microsoft 文档：[`docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing`](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing)。按照以下步骤：

1.  右键单击 Controllers 文件夹，然后选择添加|控制器。

1.  在脚手架屏幕上，选择使用 Entity Framework 和单击添加的 MVC 控制器视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fbe44f31-f1e7-4d04-b83e-38d436526add.png)

1.  在下一个屏幕上，选择我们的 Research 模型作为`Model`类，ResearchContext 作为`Data`上下文类。你可以将其余部分保持不变，除非你想要更改控制器名称：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/550c21a5-5226-43fa-bab6-9d734e177543.png)

简要查看创建的控制器，我们现在已经有了基本的**创建、读取、更新和删除**（**CRUD**）任务。现在，是主要事件的时候了。

# 运行应用程序

在我们开始运行应用程序之前，让我们确保我们的新页面很容易访问。最简单的方法就是将它设置为默认主页：

1.  看一下`Startup.cs`中的`Configure`方法。你会注意到默认路由被指定为`Home`控制器。

1.  简单地将控制器更改为你的`Research`控制器如下：

```cs
app.UseMvc(routes => 
{ 
    routes.MapRoute( 
        name: "default", 
        template: "{controller=Researches}/{action=Index}/{id?}"); 
});
```

1.  最后，确保你的`Main`方法如下所示：

```cs
public static void Main(string[] args)
{
  var host = BuildWebHost(args);
  using (var scope = host.Services.CreateScope())
  {
    var services = scope.ServiceProvider;
    try
    {
      var context = services.GetRequiredService<ResearchContext>();
      DbInitializer.Initialize(context);
    }
    catch (Exception ex)
    {
      var logger = services.GetRequiredService<ILogger<Program>>
       ();logger.LogError(ex, "An error occurred while seeding the 
        database.");
    }
  }host.Run();
}
```

1.  现在，按下*Ctrl* + *F5*来运行应用程序，看看你的劳动成果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/8a2e80a8-dbe2-46fa-84df-b0131fc6b20e.png)

1.  如你所见，我们的测试条目可以供我们使用。让我们快速看一下可用的功能：

+   点击“创建新”以查看我们链接的条目表单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6710c483-2ce0-44e6-ae0d-e21ea64ab2c8.png)

1.  输入一些有趣的数据，然后点击“创建”按钮。你将被重定向回列表视图，并看到我们的新条目被添加到列表底部：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/365b3bf5-25e0-4309-a067-292f5d89442b.png)

在每个项目旁边，你可以选择编辑、详情或删除。随便玩玩这些功能。有很多可以做来改善用户体验，比如自动填写日期字段。我将把改善用户体验的创意留给你自己来完成。

# 部署应用程序

一旦你的应用程序准备部署，你可以使用一些可用的选项：

1.  Microsoft Azure 应用服务

1.  自定义目标（IIS、FTP）

1.  文件系统

1.  导入配置文件

在 Visual Studio 的“构建”菜单项下，点击“发布 WebResearch”（或者你决定给你的项目起的名字）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a754b01a-0589-4940-9be3-51b77c082c24.png)

你将看到一个屏幕显示可用的发布选项。让我们仔细看一下。

# Microsoft Azure 应用服务

Microsoft Azure 负责创建和维护 Web 应用程序所需的所有基础设施。这意味着我们开发人员不需要担心诸如服务器管理、负载平衡或安全性等问题。随着平台几乎每天都在改进和扩展，我们也可以相当有信心地认为我们将拥有最新和最好的功能。

我们不会详细介绍 Azure 应用服务，因为它本身可以成为一本书，但我们当然可以看一下将我们的 Web 应用程序发布到这个云平台所需的步骤：

1.  选择 Microsoft Azure 应用服务作为你的发布目标。如果你有一个现有的站点需要发布，你可以选择“选择现有”。现在，我假设你需要“创建新”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6679cfcf-e321-4982-9717-8260071d4cd7.png)

1.  点击“确定”按钮后，Visual Studio 将使用你登录的 Microsoft 账户联系 Azure，然后 Azure 将检查你是否有 Azure 账户，并返回可用的服务详情。

我为这个蓝图创建了一个试用账户，没有事先设置具体细节，正如你从下面的截图中看到的，Azure 会为你推荐一个可用的应用名称和应用服务计划。

1.  资源组是可选的，如果你没有指定任何内容，它将获得一个唯一的组名：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/97ddd007-6866-4051-acee-7513d341a6b4.png)

1.  你可以在“更改类型”选项下更改要发布的应用程序类型。在我们的情况下，我们显然会选择 Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3bd00331-f7b3-4184-9254-904fa2e15c6b.png)

1.  点击左侧的“服务”以查看将与你的发布一起设置的服务。

第一个框显示了您的应用程序可能受益的任何推荐资源类型。在我们的情况下，推荐了一个 SQL 数据库，我们确实需要它，因此我们将通过单击添加（+）按钮来简单地添加它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f2dd708e-0062-4717-98c4-78b6fd209fbd.png)

Azure 将负责 SQL 安装，但我们需要提供所需的信息，例如如果您已经在您的配置文件中有一个服务器，则使用哪个服务器，或者如果您还没有，则创建一个新的服务器。

1.  在这种情况下，我们将配置一个新的 SQL 服务器。单击 SQL 服务器下拉菜单旁边的新按钮以打开配置 SQL 服务器表单。Azure 将为服务器提供一个推荐的名称。虽然您可以提供自己的名称，但服务器名称很可能不可用，因此我建议您只使用他们推荐的名称。

1.  为服务器提供管理员用户名和管理员密码，然后点击确定：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/17a77621-ba4d-4b85-8d29-f3df9a849bb0.png)

1.  这样做将带您回到配置 SQL 数据库表单，在那里您需要指定数据库名称以及连接字符串名称：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/af3e06cd-b9b6-41bb-bb13-a3d2f49639e3.png)

1.  再次查看创建应用服务表单。您会注意到 SQL 数据库已添加到您选择和配置的资源部分：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/270f697b-ced5-4bb0-9851-396cf1df6ba8.png)

1.  现在我们可以返回到托管选项卡，它将向您显示单击创建按钮时会发生什么的概述。

1.  如下图所示，将创建以下三个 Azure 资源：

1.  应用服务

1.  应用服务计划

1.  SQL 服务器

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/221417e4-4eaa-4d99-a967-e96bb1b27c0d.png)

1.  创建后，我们可以通过单击发布按钮将其发布到我们的新 Azure 配置文件。

1.  您将在输出窗口中看到一些构建消息，并最终会得到以下结果：

```cs
   Publish Succeeded.
   Web App was published successfully 
   http://webresearch20180215095720.azurewebsites.net/
   ========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped 
   ==========
   ========== Publish: 1 succeeded, 0 failed, 0 skipped ==========

```

1.  您可以查看 Azure 门户上的仪表板（[portal.azure.com](http://portal.azure.com)），该仪表板将显示由于我们的服务创建而启用在您的帐户上的资源：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fc0ef22f-1575-43a1-a14c-c7b200546a93.png)

1.  发布的应用程序将在浏览器中打开，您很可能会看到错误消息。默认情况下，您不会看到有关错误的详细信息，但至少 Azure 会通过将您的`ASPNETCORE_ENVIRONMENT`环境变量设置为`Development`并重新启动应用程序来提供一些指针以获取错误详细信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/9e080081-484d-49ce-a907-f62bd608ec35.png)

1.  当您登录到 Azure 门户时，可以导航到您的应用服务，然后在应用程序设置中，添加值为`Development`的 ASPNETCORE_ENVIRONMENT 设置，并重新启动您的应用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d4f6b70f-748c-4076-8c3a-6843c677f5a4.png)

1.  现在，我们可以刷新网站，我们应该看到关于底层错误的更多细节：

>![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d7ca2155-3f60-4f21-b193-c03bc5ac7b92.png)

1.  啊，是的！我们仍然指向我们的本地数据库，并且我们无法从发布环境访问它。让我们更新我们的`appsettings.json`指向我们的 Azure 数据库。

1.  导航到 Azure 仪表板上的 SQL 服务器，然后到属性。在右侧窗格上，您应该会看到一个显示数据库连接字符串的选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/97d0b1e4-52a7-48a3-be6f-52f04569964d.png)

1.  复制 ADO.NET 连接字符串，返回到您的代码，并在`appsettings.json`文件中更新 CONNECTION STRINGS 条目。

1.  重新发布应用程序，然后您应该可以开始了。

# 自定义目标

下一个发布选项通常称为自定义目标。

此选项基本上包括任何不是 Azure 或本地文件系统的内容。单击确定按钮后，您可以选择发布方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0347a6c8-3b70-48ff-b933-6f8656fc5ee8.png)

有四种发布方法或自定义目标，每种方法都有自己的要求：

1.  FTP

1.  Web 部署

1.  Web 部署包

1.  文件系统

我们还有一个设置选项卡，适用于所有四种方法。让我们快速看看那里的选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/08e44580-1306-4231-aeb8-52481aa5781c.png)

配置选项可以设置为 Debug 或 Release。

使用 Debug，您生成的文件是可调试的，这意味着可以命中指定的断点。但这也意味着性能会下降。

使用 Release，您将无法实时调试，但由于应用程序已完全优化，性能将有所提高。

在我们的情况下，唯一可用的目标框架是**netcoreapp2.0**，但在标准.NET 应用程序中，这是您可以将目标设置为.NET 3.5 或.NET 4.5，或者其他可用的地方。

然后，您还可以指定**目标运行时**，选择让 Visual Studio 清理目标文件夹，并为运行时指定连接字符串。

如前所述，这些设置适用于所有四种发布方法，我们现在将看一下。

# FTP

FTP 发布方法使您能够发布到托管的 FTP 位置。对于此选项，您需要提供以下内容：

+   服务器 URL

+   站点路径

+   用户名

+   密码

+   目标 URL

它还允许您验证从输入的详细信息的连接：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fe6fae52-9c71-4413-98d0-20d74f83bf7b.png)

# Web Deploy

看看 Web Deploy 和 FTP 的形式，您可能会原谅自己认为它们是同一回事。嗯，两者都基本上会导致同样的结果，即直接发布到托管站点，但是使用 Web Deploy，您将获得一些额外的好处，包括以下内容：

+   Web Deploy 会将源与目标进行比较，并仅同步所需的更改，从而大大减少了与 FTP 相比的发布时间

+   即使 FTP 也有其安全的表亲 SFTP 和 FTPS，Web Deploy 始终支持安全传输

+   适当的数据库支持，使您能够在同步过程中应用 SQL 脚本

发布屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2e807d75-8688-447d-b711-fe265de0ff5d.png)

# Web Deploy Package

Web Deploy Package 选项用于创建部署包，您可以在之后选择的任何位置安装您的应用程序。请参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/44899422-b9ad-4999-a323-d0cea6f988d1.png)

# 文件系统

被全球老派开发人员使用，主要是因为我们仍然不太信任一些可用工具，此选项允许您发布到您选择的文件夹位置，然后手动将其复制到发布环境：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ddc5b330-fa64-46b4-852b-07584b6f2fb3.png)

# 文件夹

只是为了向您展示开发人员仍然控制发布代码的流行程度，我们有两条路径最终都会发布到文件夹位置。

再次，只需指定文件夹位置，然后点击“确定”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/54b6e731-3e2d-47b7-a692-2e5baf0f5c38.png)

# 导入配置文件

导入配置文件方法不是实际的发布方法，而是一个简单的选项，用于导入先前保存的配置文件，可以是从备份中导入，也可以用于在开发团队之间共享发布配置文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c102484f-1420-449e-a608-483b228adf10.png)

# 总结

在本章中，我们在 Entity Framework Core 领域进行了一次引导式的导览。我们从博物馆开始，了解了 Entity Framework 的历史，然后访问学区，讨论了 Code-First、Model-First 和 Database-First 实现方法之间的一些区别。甚至还有 TechNet 的快速访问，提供了一些关于设计数据库的想法。

之后，我们花了一些时间构建自己的 EF Core 解决方案，并研究了部署应用程序的各种方式。我们还研究了如何用一些测试数据填充我们的新建筑，以查看一旦向公众开放，它将如何保持稳定。

导览结束时，我们参观了分发区，以了解可用的部署选项。

这次访问时间太短，无法涵盖 Entity Framework Core 世界中所有可用和可能的内容，因为它是一个拥有庞大社区不断努力改进和扩展其功能的框架。

了解开发社区不满足于任何平庸，不断努力改进和扩展功能，比如 Entity Framework，尽管它似乎已经非常成熟和广泛。


# 第七章：一个无服务器的电子邮件验证 Azure 函数

本章将带我们进入无服务器计算的领域。我听到你问无服务器计算到底是什么？事实上，一旦你理解了“无服务器计算”这个术语与缺乏服务器无关的概念，答案就非常简单了。事实上恰恰相反。

在本章中，我们将看一下：

+   创建 Azure 函数

+   在浏览器中测试您的 Azure 函数

+   从 ASP.NET Core MVC 应用程序调用 Azure 函数

我们将创建一个简单的 Azure 函数，使用正则表达式来验证电子邮件地址。您需要记住 Azure 函数是云中的小代码片段。不要把它们看作复杂代码的大部分。越小越好。

# 从无服务器计算开始

传统上，公司花费时间和金钱来管理服务器的计算资源。这些代表了公司的固定和重复成本。无论服务器是空闲还是正在执行某种计算任务，都会产生费用。底线是，它只是因为存在而花费了金钱。

使用无服务器计算，计算资源是可扩展的云服务。这意味着它是一个事件驱动的应用程序设计。基本上，使用无服务器计算，您只支付您使用的部分。这对 Azure 函数也是如此。

**Azure 函数**是驻留在云中的小代码片段。您的应用程序可以根据需要简单地使用这些函数，您只需支付所使用的计算能力。无论是一个人还是一百万人访问您的应用程序都无所谓。Azure 函数将自动扩展以处理额外的负载。当您的应用程序的使用量下降时，Azure 函数会自动缩小规模。

# 无服务器计算的重要性

想象一下，您的应用程序使用频繁（但不是持续）出现峰值。因为处理来自您的应用程序的请求的服务器不是无服务器的，它需要升级（作为您或您的公司的成本）以处理额外的负载。在低使用率时，服务器并没有更少的资源。您升级它以处理特定的用户负载。它将始终以这个性能水平运行，正如您所知，性能是有代价的。

使用无服务器计算，资源会随着需求的增加和减少而自动扩展和缩小。这是一种更有效的使用服务器的方式，因为您不必为未充分利用的计算能力付费。

# Azure 函数的特性

Azure 函数为开发人员提供了丰富的功能。请参考微软文档，了解更多关于 Azure 函数的信息-[`docs.microsoft.com/en-us/azure/azure-functions/`](https://docs.microsoft.com/en-us/azure/azure-functions/)。现在，我们将看一下其中的一些功能。

# 语言选择

Azure 函数的好处是您可以使用自己选择的语言创建它们。有关支持的语言列表，请浏览以下网址：

[`docs.microsoft.com/en-us/azure/azure-functions/supported-languages`](https://docs.microsoft.com/en-us/azure/azure-functions/supported-languages)。

在本章中，我们将使用 C#编写 Azure 函数。

# 按使用付费

如前所述，您只需支付 Azure 函数运行的实际时间。按秒计费的消耗计划。微软在以下网址上有一份关于 Azure 函数定价的文档：

[`azure.microsoft.com/en-us/pricing/details/functions/`](https://azure.microsoft.com/en-us/pricing/details/functions/)。

# 灵活的开发

您可以直接在 Azure 门户中创建 Azure 函数。您还可以使用 Visual Studio Team Services 和 GitHub 设置持续集成。

# 我可以创建什么类型的 Azure 函数？

您可以使用 Azure 函数作为集成解决方案，处理数据，与物联网，API 和微服务一起工作。Azure 函数还可以很好地触发，因此您甚至可以安排任务。这些是提供给您的一些 Azure 函数模板：

+   `HTTPTrigger`

+   `TimerTrigger`

+   `GitHub webhook`

+   `Generic webhook`

+   `BlobTrigger`

+   `CosmosDBTrigger`

+   `QueueTrigger`

+   `EventHubTrigger`

+   `ServiceBusQueueTrigger`

+   `ServiceBusTopicTrigger`

要了解有关这些模板和 Azure 函数的更多信息，请阅读微软文档*Azure 函数简介*，网址如下：

[`docs.microsoft.com/en-us/azure/azure-functions/functions-overview`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-overview)。

# 创建 Azure 函数

让我们毫不拖延地创建我们自己的 Azure 函数。我们要创建的函数将使用正则表达式验证电子邮件地址。这是一个非常标准的开发任务。它也是一个将在许多应用程序中广泛使用的功能：

您需要拥有 Azure 帐户。如果没有，您可以在[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)上设置免费试用帐户。

1.  将浏览器指向[`portal.azure.com`](https://portal.azure.com)并登录到您的 Azure 门户。

1.  登录后，寻找“创建资源”链接。单击该链接，然后在 Azure Marketplace 部分下查找“计算”链接。请参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5cd2ce05-5cd4-4a7d-aa69-6a21f641e064.png)

1.  在“特色”部分下方，您将看到“函数应用”作为一个选项。单击该链接：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/731176f3-ffb0-466b-ac39-26699a5ad811.png)

1.  现在，您将看到“函数应用设置”屏幕。需要输入以下选项：

+   应用名称：这是您的 Azure 函数的全局唯一名称。

+   订阅：这是您的函数将在其中创建的订阅。

+   资源组：为您的函数创建一个新的资源组。

+   操作系统：您可以选择 Windows 或 Linux。我选择了 Windows。

+   托管计划：这将定义资源如何分配给您的函数。

+   位置：最好选择地理位置最接近您的位置。

+   存储：保持默认设置。

1.  您还可以选择将应用程序洞察切换到打开或关闭状态。您还可以选择“固定到仪表板”选项。

我们称之为 Azure 函数核心邮件验证。

1.  添加所有必需的设置后，单击“创建”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/31b46271-09a2-4101-a3fb-6805ce937eba.png)

1.  单击“创建”按钮后，您将看到一个“正在验证...”的消息。这可能需要几秒钟时间！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/1fd053a8-3d11-4da8-91d9-322c9c6f613e.png)

1.  请注意 Azure 门户右上角的通知部分（小铃铛图标）。新通知将显示在那里，并以数字表示未读通知的数量！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7e1a442c-69fc-47d7-a800-af7f81c07dfd.png)

1.  如果单击通知，您将看到 Azure 正在部署您创建的 Azure 函数的进度！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5e90e6a5-74d6-4f1c-9b4e-586758a3c53a.png)

1.  当部署您的 Azure 函数时，您将在“通知”部分看到“部署成功”消息。从那里，您可以单击“固定到仪表板”或“转到资源”按钮。

将您的函数固定到仪表板只是为了以后更容易访问它。将经常使用的服务固定到仪表板是一个好主意。

1.  要访问您的 Azure 函数，请单击“转到资源”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d5e0d3c8-8b12-496d-b7e9-89505ec5449a.png)

1.  然后，您将进入 Azure 门户的“函数应用”部分。您将在“函数应用”部分下看到“核心邮件验证”函数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/17187b97-ab49-437b-9b62-15f25a4ac3c3.png)

1.  在“core-email-validation”下，单击“函数”选项。然后，在右侧面板中单击“新建函数”选项。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a84a8210-4e1b-4dca-bfcd-629181f2ff9d.png)

1.  现在，您将看到一系列可以帮助您入门的模板。向下滚动以查看所有可用的模板（不仅仅是以下截图中显示的四个）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ed48aacc-bc68-4219-b965-b0b861c9acd8.png)

1.  我们不会浏览所有可用的模板。我们将保持简单，只选择“转到快速入门”选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f3f0d31e-69ea-4060-a551-c4e199120464.png)

1.  对于我们的目的，我们将简单地选择“Webhook + API”，并选择“C#”作为我们的语言。还有其他可供选择的语言，因此请选择您最熟悉的语言。

1.  要创建该函数，请单击“创建此函数”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5cee9e17-9d25-4e14-854e-4312609e06f2.png)

1.  已创建 Azure 函数，并为您自动添加了一些样板代码，以便您了解函数内部代码的外观。所有这些代码所做的就是在查询字符串中查找名为`name`的变量，并在找到时在浏览器中显示它：

```cs
      using System.Net; 
      public static async Task<HttpResponseMessage> 
       Run(HttpRequestMessage req, TraceWriter log) 
      { 
        log.Info("C# HTTP trigger function processed a request."); 

        // parse query parameter 
        string name = req.GetQueryNameValuePairs() 
        .FirstOrDefault(q => string.Compare(q.Key, "name", true) == 0) 
        .Value; 

        if (name == null) 
        { 
          // Get request body 
          dynamic data = await req.Content.ReadAsAsync<object>(); 
          name = data?.name; 
        } 

        return name == null 
        ? req.CreateResponse(HttpStatusCode.BadRequest,
        "Please pass a name on the query string or in the request body") 
          : req.CreateResponse(HttpStatusCode.OK, "Hello " + name); 
      }  
```

1.  查看屏幕右上角。您将看到一个“</>获取函数 URL”链接。单击以下链接：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fb682bf7-6e37-405c-95f6-d44084e10faf.png)

1.  这将显示一个弹出屏幕，其中包含访问您刚创建的 Azure 函数的 URL。单击“复制”按钮将 URL 复制到剪贴板：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/dd77a3b9-9a19-4a39-9004-ce7f22906713.png)

1.  您复制的 URL 将如下所示：

```cs
https://core-mail-validation.azurewebsites.net/api/HttpTriggerCSharp1?code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ== 
```

1.  要运行我们的函数，我们需要在 URL 的查询字符串中添加一个`name`参数。继续在 URL 中添加`&name==[YOUR_NAME]`，其中`[YOUR_NAME]`是您自己的名字。在我的情况下，我在 URL 的末尾添加了`&name=Dirk`：

```cs
https://core-mail-validation.azurewebsites.net/api/HttpTriggerCSharp1?code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ==&name=Dirk
```

1.  将此 URL 粘贴到浏览器地址栏中，然后点击返回按钮。浏览器中将显示一条消息（在我的情况下）“Hello Dirk”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/db969b84-aeed-4fe2-8a1d-64b576f77d53.png)

请注意，在 Chrome 和 Firefox 中，您可能会看到消息“此 XML 文件似乎没有与其关联的任何样式信息”。要查看输出，请使用 Microsoft Edge。

1.  回到 Azure 门户，在 Azure 函数屏幕的底部，您将看到“日志”窗口。如果没有显示，请单击“Λ”箭头展开面板。在这里，您将看到 Azure 触发器已成功运行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3ebdcb87-5b5a-4b4f-a6eb-d43967c36eeb.png)

恭喜，您刚刚运行了新的 Azure 函数。

# 修改 Azure 函数代码

虽然这一切都很令人兴奋（应该是的，这真是很酷的技术），但我们需要对 Azure 函数进行一些更改以满足我们的要求：

1.  在 Azure 函数中找到`return`语句。它将如下所示：

```cs
      return name == null 
        ? req.CreateResponse(HttpStatusCode.BadRequest,
         "Please pass a name on the query string or in the request 
          body") 
        : req.CreateResponse(HttpStatusCode.OK, "Hello " + name); 
```

让我们简化一下代码，如果电子邮件地址不为空，只需返回`true`。将`return`语句替换为以下代码：

```cs
      if (email == null) 
      { 
        return req.CreateResponse(HttpStatusCode.BadRequest,
         "Please pass an email address on the query string or
          in the request body"); 
      } 
      else 
      { 
        bool blnValidEmail = false; 
        if (email.Length > 0) 
        { 
            blnValidEmail = true; 
        } 

        return req.CreateResponse(HttpStatusCode.OK,
         "Email status: " + blnValidEmail); 
      } 
```

1.  您的 Azure 函数中的代码现在应该如下所示：

```cs
      using System.Net; 

      public static async Task<HttpResponseMessage>
       Run(HttpRequestMessage req, TraceWriter log) 
      { 
        log.Info("C# HTTP trigger function processed a new email 
         validation request."); 

        // parse query parameter 
        string email = req.GetQueryNameValuePairs() 
          .FirstOrDefault(q => string.Compare(q.Key, "email", true) == 
          0) 
          .Value; 

        if (email == null) 
        { 
          // Get request body 
          dynamic data = await req.Content.ReadAsAsync<object>(); 
          email = data?.email; 
        } 

        if (email == null) 
        { 
          return req.CreateResponse(HttpStatusCode.BadRequest,
           "Please pass an email address on the query string or
            in the request body"); 
        } 
        else 
        { 
          bool blnValidEmail = false; 
          if (email.Length > 0) 
          { 
            blnValidEmail = true; 
          } 

          return req.CreateResponse(HttpStatusCode.OK,
           "Email status: " + blnValidEmail); 
        }    

      }
```

1.  确保单击“保存”按钮以保存对 Azure 函数的更改。然后，您将看到函数已编译，并在“日志”窗口中显示“编译成功”消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/65abe5ba-1d6e-4653-ae83-8165173dbf1b.png)

1.  与以前一样，通过单击</>获取函数 URL 链接来复制 URL：

```cs
https://core-mail-validation.azurewebsites.net/api/HttpTriggerCSharp1?code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ==
```

不过，这次我们要将其作为电子邮件地址传递。您可以看到参数名称已更改为`email`，并且值可以是您选择输入的任何电子邮件地址。因此，我在 URL 的末尾添加了`&email=dirk@email.com`：

```cs
https://core-mail-validation.azurewebsites.net/api/HttpTriggerCSharp1?code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ==&email=dirk@email.com
```

1.  将 URL 粘贴到浏览器中，然后点击返回按钮，以在浏览器中查看结果显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/cad93eb1-ffef-46c7-86ae-39823faf11ff.png)

1.  我们现在有信心 Azure Function 正在对我们的电子邮件地址进行基本验证（即使只是检查它是否存在）。然而，我们需要函数做更多的事情。为了验证电子邮件地址，我们将使用正则表达式。为此，将以下命名空间添加到 Azure Function 中：

```cs
      using System.Text.RegularExpressions; 
```

在进行验证的代码部分，输入代码来匹配电子邮件与正则表达式模式。

互联网上有成千上万种不同的正则表达式模式。正则表达式是一个完全不同的话题，超出了本书的范围。如果您的应用程序需要匹配文本模式，可以搜索一下，看看是否有可用的正则表达式模式。如果你真的很勇敢，你可以自己写。

1.  正则表达式已经内置到.NET Framework 中，代码非常简单：

```cs
blnValidEmail = Regex.IsMatch(email, 
                @"^(?("")("".+?(?<!\)""@)|((0-9a-z)|[-!#$%&'*+/=?^`{}|~w])*)(?<=[0-9a-z])@))" + 
                @"(?([)([(d{1,3}.){3}d{1,3}])|(([0-9a-z][-0-9a-z]*[0-9a-z]*.)+[a-z0-9][-a-z0-9]{0,22}[a-z0-9]))$", 
                RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250)); 
```

1.  在添加了所有代码之后，您的 Azure Function 将如下所示：

```cs
      using System.Net; 
      using System.Text.RegularExpressions; 

      public static async Task<HttpResponseMessage>
       Run(HttpRequestMessage req, TraceWriter log) 
      { 
        log.Info("C# HTTP trigger function processed a new email 
         validation request."); 

        // parse query parameter 
        string email = req.GetQueryNameValuePairs() 
          .FirstOrDefault(q => string.Compare(q.Key, "email", true) == 
           0) 
          .Value; 

        if (email == null) 
        { 
          // Get request body 
          dynamic data = await req.Content.ReadAsAsync<object>(); 
          email = data?.email; 
        } 

        if (email == null) 
        { 
          return req.CreateResponse(HttpStatusCode.BadRequest,
          "Please pass an email address on the query string or in
           the request body"); 
        } 
        else 
        { 
          bool blnValidEmail = false; 

          blnValidEmail = Regex.IsMatch(email, 
                @"^(?("")("".+?(?<!\)""@)|((0-9a-z)|
                [-!#$%&'*+/=?^`{}|~w])*)(?<=[0-9a-z])@))" + 
                @"(?([)([(d{1,3}.){3}d{1,3}])|(([0-9a-z][-0-9a-z]*
                [0-9a-z]*.)+[a-z0-9][-a-z0-9]{0,22}[a-z0-9]))$", 
                RegexOptions.IgnoreCase, 
                TimeSpan.FromMilliseconds(250)); 

          return req.CreateResponse(HttpStatusCode.OK,
          "Email status: " + blnValidEmail); 
        }    

      } 
```

1.  使用之前复制的相同 URL 粘贴到浏览器窗口中，然后点击*返回*或*输入*键：

```cs
https://core-mail-validation.azurewebsites.net/api/HttpTriggerCSharp1?code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ==&email=dirk@email.com
```

1.  电子邮件地址`dirk@email.com`已经验证，并且在浏览器中显示了消息“电子邮件状态：True”。这里发生的是电子邮件地址被传递给 Azure Function。然后函数从查询字符串中读取`email`参数的值，并将其传递给正则表达式。

电子邮件地址与正则表达式模式匹配，如果找到匹配，则认为电子邮件地址是有效的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/cb0be1a7-8065-4be3-8882-bdbff4461acf.png)

1.  让我们将相同的 URL 输入到浏览器中，只是这次输入一个你知道将是无效的电子邮件地址。例如，电子邮件地址只能包含一个`@`符号。然后我添加到 URL 的参数如下：

```cs
https://core-mail-validation.azurewebsites.net/api/HttpTriggerCSharp1?code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ==&email=dirk@@email.com
```

然后您可以看到，当我们点击*返回*或*输入*键时，无效的电子邮件地址`dirk@@email.com`被验证，并且不匹配正则表达式。因此在浏览器中显示文本“电子邮件状态：False”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/efb296c4-25e9-4bdb-984f-b0bc11690251.png)

太棒了！我们已经看到我们创建的 Azure Function 使用了我们添加的正则表达式来验证它接收到的电子邮件地址。根据正则表达式验证的结果，函数返回 true 或 false。

最后，在继续之前，我们希望 Azure Function 返回一个单一的`True`或`False`值给调用应用程序。修改函数的`return`语句来实现这一点：

```cs
  return req.CreateResponse(HttpStatusCode.OK, blnValidEmail); 
```

我们已经看到了这个函数是如何工作的，通过逐步修改代码并直接从浏览器窗口运行。然而，除非我们可以从应用程序调用这个 Azure Function，否则这对我们没有任何好处。

让我们看看如何创建一个 ASP.NET Core MVC 应用程序，调用我们的 Azure Function 来验证在登录屏幕上输入的电子邮件地址。

# 从 ASP.NET Core MVC 应用程序调用 Azure Function

在上一节中，我们看了一下我们的 Azure Function 是如何工作的。现在，我们想创建一个 ASP.NET Core MVC 应用程序，将调用我们的 Azure Function 来验证应用程序登录屏幕中输入的电子邮件地址：

这个应用程序根本不进行任何身份验证。它所做的只是验证输入的电子邮件地址。ASP.NET Core MVC 身份验证是一个完全不同的话题，不是本章的重点。

1.  在 Visual Studio 2017 中，创建一个新项目，并从项目模板中选择 ASP.NET Core Web 应用程序。单击“确定”按钮创建项目。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e2a98857-ae4f-42f6-8514-b2f3ac97b1ce.png)

1.  在下一个屏幕上，确保从表单的下拉选项中选择.NET Core 和 ASP.NET Core 2.0。选择 Web 应用程序（模型-视图-控制器）作为要创建的应用程序类型。

不要费心进行任何身份验证或启用 Docker 支持。只需单击“确定”按钮创建项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/22c47a80-9256-4d49-a5bd-77031ad83531.png)

1.  创建项目后，您将在 Visual Studio 的解决方案资源管理器中看到熟悉的项目结构：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/99c956fc-b4b7-4133-b05f-4193e4922ce3.png)

# 创建登录表单

在接下来的部分中，我们可以创建一个简单的普通登录表单。为了有点乐趣，让我们稍微调整一下。在互联网上寻找一些免费的登录表单模板：

1.  我决定使用一个名为**colorlib**的网站，该网站在最近的博客文章中提供了 50 个免费的 HTML5 和 CSS3 登录表单。文章的网址是：[`colorlib.com/wp/html5-and-css3-login-forms/`](https://colorlib.com/wp/html5-and-css3-login-forms/)。

1.  我决定使用**Colorlib**网站上的**Login Form 1**。将模板下载到您的计算机并解压缩 ZIP 文件。在解压缩的 ZIP 文件中，您将看到我们有几个文件夹。将此解压缩的 ZIP 文件中的所有文件夹复制（保留`index.html`文件，因为我们将在一分钟内使用它）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/930634ba-19aa-40c0-9d18-ac53cbd80b55.png)

1.  接下来，转到 Visual Studio 应用程序的解决方案。在`wwwroot`文件夹中，移动或删除内容，并将从解压缩的 ZIP 文件中的文件夹粘贴到 ASP.NET Core MVC 应用程序的`wwwroot`文件夹中。您的`wwwroot`文件夹现在应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a7da7042-7001-4296-9b7f-40ea9a4c06d6.png)

1.  回到 Visual Studio，展开 CoreMailValidation 项目中的 wwwroot 节点时，您将看到文件夹。

1.  我还想让您注意`Index.cshtml`和`_Layout.cshtml`文件。我们将修改这些文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/65f2d69e-e6da-4e23-9e45-12cc7aa2868b.png)

1.  打开`Index.cshtml`文件，并从该文件中删除所有标记（大括号中的部分除外）。将之前从 ZIP 文件中提取的`index.html`文件中的 HTML 标记粘贴到该文件中。

不要复制`index.html`文件中的所有标记。只复制`<body></body>`标记内的标记。

1.  您的`Index.cshtml`文件现在应如下所示：

```cs
@{ 
    ViewData["Title"] = "Login Page";     
} 

<div class="limiter"> 
    <div class="container-login100"> 
        <div class="wrap-login100"> 
            <div class="login100-pic js-tilt" data-tilt> 
                <img src="img/img-01.png" alt="IMG"> 
            </div> 

            <form class="login100-form validate-form"> 
                <span class="login100-form-title"> 
                    Member Login 
                </span> 

                <div class="wrap-input100 validate-input" 
                 data-validate="Valid email is required: 
                  ex@abc.xyz"> 
                    <input class="input100" type="text" 
                     name="email" placeholder="Email"> 
                    <span class="focus-input100"></span> 
                    <span class="symbol-input100"> 
                        <i class="fa fa-envelope"
                         aria-hidden="true"></i> 
                    </span> 
                </div> 

                <div class="wrap-input100 validate-input" 
                 data-validate="Password is required"> 
                    <input class="input100" type="password" 
                     name="pass" 
                     placeholder="Password"> 
                    <span class="focus-input100"></span> 
                    <span class="symbol-input100"> 
                        <i class="fa fa-lock"
                         aria-hidden="true"></i> 
                    </span> 
                </div> 

                <div class="container-login100-form-btn"> 
                    <button class="login100-form-btn"> 
                        Login 
                    </button> 
                </div> 

                <div class="text-center p-t-12"> 
                    <span class="txt1"> 
                        Forgot 
                    </span> 
                    <a class="txt2" href="#"> 
                        Username / Password? 
                    </a> 
                </div> 

                <div class="text-center p-t-136"> 
                    <a class="txt2" href="#"> 
                        Create your Account 
                        <i class="fa fa-long-arrow-right m-l-5" 
                         aria-hidden="true"></i> 
                    </a> 
                </div> 
            </form> 
        </div> 
    </div> 
</div> 
```

本章的代码可在 GitHub 上的以下链接找到：

[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/Serverless`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints/tree/master/Serverless)。

1.  接下来，打开`Layout.cshtml`文件，并将我们之前复制到`wwwroot`文件夹中的所有链接添加到文件中。使用`index.html`文件作为参考。您将注意到`_Layout.cshtml`文件包含以下代码片段—`@RenderBody()`。这是一个占位符，指定了`Index.cshtml`文件内容应该注入的位置。如果您来自 ASP.NET Web Forms，请将`_Layout.cshtml`页面视为主页面。您的`Layout.cshtml`标记应如下所示：

```cs
<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>@ViewData["Title"] - CoreMailValidation</title>
    <link rel="icon" type="image/png" href="~/images/icons/favicon.ico" />
    <link rel="stylesheet" type="text/css" href="~/vendor/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" type="text/css" href="~/fonts/font-awesome-4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" type="text/css" href="~/vendor/animate/animate.css">
    <link rel="stylesheet" type="text/css" href="~/vendor/css-hamburgers/hamburgers.min.css">
    <link rel="stylesheet" type="text/css" href="~/vendor/select2/select2.min.css">
    <link rel="stylesheet" type="text/css" href="~/css/util.css">
    <link rel="stylesheet" type="text/css" href="~/css/main.css">
</head>

<body>
    <div class="container body-content">
        @RenderBody()
        <hr />
        <footer>
            <p>&copy; 2018 - CoreMailValidation</p>
        </footer>
    </div>
    <script src="img/jquery-3.2.1.min.js"></script>
    <script src="img/popper.js"></script>
    <script src="img/bootstrap.min.js"></script>
    <script src="img/select2.min.js"></script>
    <script src="img/tilt.jquery.min.js"></script>
    <script>
        $('.js-tilt').tilt({
            scale: 1.1
        })
    </script>
    <script src="img/main.js"></script>
    @RenderSection("Scripts", required: false)
</body>

</html>
```

1.  如果一切顺利，当您运行 ASP.NET Core MVC 应用程序时，您将看到以下页面。登录表单显然是完全无效的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3ce9788c-496a-42f5-89a9-4ba813bb7053.png)

但是，登录表单是完全响应的。如果您需要缩小浏览器窗口的大小，您会看到表单随着浏览器大小的减小而缩放。这就是您想要的。如果您想探索 Bootstrap 提供的响应式设计，请访问[`getbootstrap.com/`](https://getbootstrap.com/)并查看文档中的示例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2c66e960-5633-4e52-b698-14eed1d81cc5.png)

我们接下来要做的事情是将此登录表单连接到我们的控制器，并调用我们创建的 Azure 函数来验证我们输入的电子邮件地址。

让我们来看看下一步该怎么做。

# 连接所有内容

为了简化事情，我们将创建一个模型传递给我们的控制器：

1.  在应用程序的`Models`文件夹中创建一个名为`LoginModel`的新类，并单击“添加”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/73408275-7afa-4639-979e-4007aa418f89.png)

1.  您的项目现在应该如下所示。您将看到`model`添加到`Models`文件夹中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7c04fef2-90eb-4453-ad15-c2f8490ee76d.png)

1.  接下来，我们要做的是在我们的`model`中添加一些代码，以表示登录表单上的字段。添加两个名为`Email`和`Password`的属性：

```cs
      namespace CoreMailValidation.Models 
      { 
        public class LoginModel 
        { 
          public string Email { get; set; } 
          public string Password { get; set; } 
        } 
      }
```

1.  回到`Index.cshtml`视图，在页面顶部添加`model`声明。这使得`model`可以在我们的视图中使用。请务必指定`model`存在的正确命名空间：

```cs
      @model CoreMailValidation.Models.LoginModel 
      @{ 
        ViewData["Title"] = "Login Page"; 
      } 
```

1.  接下来的代码部分需要在`HomeController.cs`文件中编写。目前，它应该只有一个名为`Index()`的操作：

```cs
      public IActionResult Index() 
      { 
        return View(); 
      } 
```

1.  添加一个名为`ValidateEmail`的新的`async`函数，它将使用我们之前复制的 Azure Function URL 的基本 URL 和参数字符串，并使用 HTTP 请求调用它。我不会在这里详细介绍，因为我认为代码非常简单。我们所做的就是使用我们之前复制的 URL 调用 Azure Function 并读取返回的数据：

```cs
      private async Task<string> ValidateEmail(string emailToValidate) 
      { 
        string azureBaseUrl = "https://core-mail-
         validation.azurewebsites.net/api/HttpTriggerCSharp1"; 
        string urlQueryStringParams = $"?
         code=/IS4OJ3T46quiRzUJTxaGFenTeIVXyyOdtBFGasW9dUZ0snmoQfWoQ
          ==&email={emailToValidate}"; 

        using (HttpClient client = new HttpClient()) 
        { 
          using (HttpResponseMessage res = await client.GetAsync(
           $"{azureBaseUrl}{urlQueryStringParams}")) 
          { 
            using (HttpContent content = res.Content) 
            { 
              string data = await content.ReadAsStringAsync(); 
              if (data != null) 
              { 
                return data; 
              } 
              else 
                return ""; 
            } 
          } 
        } 
      }  
```

1.  创建另一个名为`ValidateLogin`的`public async`操作。在操作内部，继续之前检查`ModelState`是否有效。

有关`ModelState`的详细解释，请参阅以下文章-[`www.exceptionnotfound.net/asp-net-mvc-demystified-modelstate/`](https://www.exceptionnotfound.net/asp-net-mvc-demystified-modelstate/)。

1.  然后，我们在`ValidateEmail`函数上进行`await`，如果返回的数据包含单词`false`，则我们知道电子邮件验证失败。然后将失败消息传递给控制器上的`TempData`属性。

`TempData`属性是一个存储数据的地方，直到它被读取。它由 ASP.NET Core MVC 在控制器上公开。`TempData`属性默认使用基于 cookie 的提供程序在 ASP.NET Core 2.0 中存储数据。要在不删除的情况下检查`TempData`属性中的数据，可以使用`Keep`和`Peek`方法。要了解有关`TempData`的更多信息，请参阅 Microsoft 文档：[`docs.microsoft.com/en-us/aspnet/core/fundamentals/app-state?tabs=aspnetcore2x`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/app-state?tabs=aspnetcore2x)。

如果电子邮件验证通过，那么我们知道电子邮件地址是有效的，我们可以做其他事情。在这里，我们只是说用户已登录。实际上，我们将执行某种身份验证，然后路由到正确的控制器。

另一个有趣的事情是在控制器上的`ValidateLogin`操作上包含`ValidateAntiForgeryToken`属性。这确保了表单是从我们的站点提交的，并防止我们的站点受到跨站请求伪造攻击的欺骗。

如果我们必须检查应用程序运行时页面的呈现标记，我们将看到 ASP.NET Core 已自动生成了防伪标记。

通过浏览器的开发者工具检查标记。在 Chrome 中，按*Ctrl* + *Shift* + *I*或者如果您使用 Edge，则按*F12*。

1.  您将看到 __RequestVerificationToken 和生成的值如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/44aea025-3fe9-495e-9050-2d7ef231ef83.png)

1.  `HomeController`上的完整`ValidateLogin`操作应如下所示：

```cs
      [HttpPost, ValidateAntiForgeryToken] 
      public async Task<IActionResult> ValidateLogin(LoginModel model) 
      { 
        if (ModelState.IsValid) 
        { 
          var email = model.Email; 
          string azFuncReturn = await ValidateEmail(model.Email); 

          if (azFuncReturn.Contains("false")) 
          { 
            TempData["message"] = "The email address entered is 
             incorrect. Please enter again."; 
            return RedirectToAction("Index", "Home"); 
          } 
          else 
          { 
            return Content("You are logged in now."); 
          }                 
        } 
        else 
        { 
          return View(); 
        } 

      } 
```

回到我们的`Index.cshtml`视图，仔细查看`form`标记。我们已经明确定义了使用`asp-action`（指定要调用的操作）和`asp-controller`（指定要去哪个控制器查找指定操作）来调用哪个控制器和操作：

```cs
<form class="login100-form validate-form" asp-action="ValidateLogin" asp-controller="Home"> 
```

这将`ValidateLogin`操作映射到`HomeController`类上，`Index.cshtml`表单将提交到该操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/284058f0-d4c6-497d-87a6-6d0493a1b7b3.png)

1.  然后，稍微往下，确保您的按钮的`type`指定为`submit`：

```cs
      <div class="container-login100-form-btn"> 
        <button class="login100-form-btn" type="submit"> 
          Login 
        </button> 
      </div> 
```

我们的`Index.cshtml`视图几乎完成了。当输入的电子邮件无效时，我们希望得到某种通知。这就是 Bootstrap 派上用场的地方。添加以下标记以显示`modal`对话框，通知用户输入的电子邮件地址无效。

您将注意到页面末尾包含`@section Scripts`块。我们基本上是在说，如果`TempData`属性不为空，那么我们希望通过 jQuery 脚本显示模态对话框：

```cs
<div id="myModal" class="modal" role="dialog"> 
    <div class="modal-dialog"> 

        <!-- Modal content--> 
        <div class="modal-content"> 
            <div class="modal-header alert alert-danger"> 
                <button type="button" class="close"
                 data-dismiss="modal">&times;</button> 
                <h4 class="modal-title">Invalid Email</h4> 
            </div> 
            <div class="modal-body"> 
                <p>@TempData["message"].</p> 
            </div> 
            <div class="modal-footer"> 
                <button type="button" class="btn btn-default"
                 data-dismiss="modal">Close</button> 
            </div> 
        </div> 

    </div> 
</div> 

@section Scripts 
    { 
    @if (TempData["message"] != null) 
    { 
        <script> 
            $('#myModal').modal(); 
        </script> 
    } 
} 
```

运行您的应用程序，并在登录页面上输入一个无效的电子邮件地址。在我的示例中，我只是添加了一个包含两个`@`符号的电子邮件地址：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ca7ec133-c219-4f00-9d70-7beef1236e38.png)

当按下登录按钮时，表单将回传到控制器，然后调用 Azure 函数，对输入的电子邮件地址进行验证。

结果是一个相当单调的模态对话框通知弹出，通知用户电子邮件地址不正确：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/76e6cf59-c83b-4986-b635-549c1882bc33.png)

输入有效的电子邮件地址并单击登录按钮将导致对输入的电子邮件进行成功验证：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f3479fd2-d5b7-4a57-a160-eca11940d5d5.png)

如前所述，电子邮件验证与身份验证不同。如果电子邮件经过验证，那么可以进行身份验证过程。如果此身份验证过程成功验证登录的用户，那么他们才会被重定向到已登录页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/21b083bf-c5be-42d6-a8fa-4a396598ad85.png)

# 摘要

在本章中，我们看到了如何在 Azure 门户上创建 Azure 函数。我们了解到 Azure 函数是云中使用的应用程序的小代码片段。由于它们是按使用量付费的模式定价，因此您只需支付实际使用的计算能力。当您的 Web 应用程序的用户负载很高时，该函数会根据需要自动扩展以满足访问它的应用程序的需求。

我们通过手动将 URL 发布到浏览器来了解了在 Azure 函数中了解代码的过程。然后，我们创建了一个由单个登录页面组成的 ASP.NET Core MVC 应用程序。然后，我们看了如何使用 Azure 函数来验证登录屏幕上输入的电子邮件地址。 Azure 函数是一种令人兴奋的技术。还有很多东西要学习，这一章剩下的内容不足以讨论这种无服务器技术。如果您对此技术感兴趣，请探索其他可用的 Azure 服务模板。

在下一章中，我们将学习如何使用 ASP.NET Core MVC 应用程序和名为`Tweetinvi`的 C#库创建 Twitter 克隆。请继续关注，还有很多令人兴奋的内容等着您。


# 第八章：使用 OAuth 创建 Twitter 克隆

在本章中，我们将看看使用 ASP.NET Core MVC 创建一个基本的 Twitter 克隆是多么容易。我们将执行以下任务：

+   在 Twitter 上使用 Twitter 的应用程序管理创建你的应用

+   创建一个 ASP.NET Core MVC 应用程序

+   阅读你的主页时间线

+   发布一条推文

你可以想象，Twitter 功能在.NET（更不用说.NET Core）中并不是标准配置。

请注意，你需要创建一个 Twitter 账户才能在本章中执行任务。你可以通过访问[`twitter.com/`](https://twitter.com/)进行注册。

幸运的是，有很多专注和热情的开发者愿意免费分享他们的代码。你通常会在 GitHub 上找到他们的代码，而这正是我们将要寻找一些代码集成到我们的 ASP.NET Core MVC 应用程序中，以赋予它 Twitter 的功能。这一章并不是对我们将要使用的特定 Twitter 库的认可。然而，这个库是我用过的最好的之一。而且（在撰写本文时）它还在不断更新。

让我们来看看 Tweetinvi。

# 使用 Tweetinvi

将你的浏览器指向[`github.com/linvi/tweetinvi`](https://github.com/linvi/tweetinvi)。这个库的描述已经说明了一切：

Tweetinvi，最好的 Twitter C#库，适用于 REST 和 Stream API。它支持.NET、.NETCore、UAP 和便携式类库（Xamarin）...

换句话说，这个库正是我们创建 Twitter 克隆应用所需要的。Tweetinvi 文档非常完善，并且有一个支持它的活跃社区。

# ASP.NET Core MVC Twitter 克隆应用程序

创建一个完整的 Twitter 克隆应用是一项艰巨的工作——比这一章节允许的工作还要多，恐怕我只能说明如何读取你主要的推文流（你在 Twitter 上关注的人的推文）。我还会向你展示如何从应用程序发布一条推文。

在这个应用程序中，我将放弃所有花哨的 UI 元素，而是给你一个绝佳的基础，让你继续开发一个完整的 Twitter 克隆。你可以考虑添加以下功能：

+   删除推文

+   转推

+   关注某人

+   取消关注某人

+   发送私信

+   搜索

+   查看个人资料

你可以添加很多额外的功能；随意添加你想要看到的任何缺失功能。我个人希望有更好的方式来整理和保存我发现有趣的推文。

我知道你们中的一些人可能会想知道为什么点赞一条推文不够，这就是我的原因。点赞推文最近已经成为了一种简便的方式，让别人知道他们已经看到了这条推文。当你在一条推文中被提到时，这一点尤其正确。在不回复的情况下（尤其是对于反问），Twitter 用户只是简单地点赞推文。

点赞一条推文也不是一个整理工具。你点赞的一切都可以在你的点赞下找到。没有办法区分。啊哈！我听到你们中的一些人说，“那时时刻呢？”再次强调，时刻存在于 Twitter 上。

想象一下时刻，但是那些时刻是来到你身边的。无论如何，我们可以对这样一个自定义的 Twitter 克隆应用进行很多改进，真正让它成为你自己的。现在，让我们从基础开始。

# 在 Twitter 上创建你的应用程序

在我们开始创建 Twitter 克隆之前，我们需要在 Twitter 应用管理控制台上注册它。

要访问应用程序管理控制台，请将你的浏览器指向[`apps.twitter.com`](https://apps.twitter.com)：

1.  点击登录链接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b1c9c978-2f75-45c7-8715-45b3c2f095d2.jpg)

1.  在登录界面上使用你的 Twitter 凭据登录：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/22c606a1-74a5-4827-9963-efe62080246c.jpg)

1.  如果您以前创建过任何应用程序，您将看到它们列在下面。您创建的所有应用程序都列在 Twitter 应用程序部分下。点击“创建新应用”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/9d7eb52c-076c-4a7d-935f-d4b8495724cc.jpg)

1.  现在您将看到创建应用程序表单。为您的应用程序提供一个合适的名称和描述。为您的应用程序提供一个网站，并最后提供一个回调 URL 值。我只是使用了`http://localhost:50000/`，稍后将向您展示如何在应用程序中配置此项。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/92af6414-677f-436c-86cf-015bebd7a280.jpg)

如果在回调期间 localhost 出现问题，请尝试改用`127.0.0.1`。

1.  勾选您理解的 Twitter 开发者协议选项，然后点击创建 Twitter 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5df80045-da9a-437f-9f7f-7af9c50f89f5.jpg)

1.  接下来，您将看到刚刚创建的应用程序设置的摘要。在屏幕顶部，点击“密钥和访问令牌”选项卡：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/87dd3be5-a457-40ef-9817-72f388a910ee.jpg)

1.  这将带您到您的应用程序设置，其中提供了消费者密钥和消费者密钥。一定要记下这些密钥：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/77855b94-ce50-4fa7-8c31-6711470f6aa7.jpg)

1.  在页面底部，您将看到一个名为“创建我的访问令牌”的按钮。点击此按钮。这将创建一个令牌，使您能够进行 API 调用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/54daa0fb-d530-48b0-bccb-bbb4db1cf460.jpg)

1.  生成令牌后，将显示访问令牌和访问令牌密钥。也要记下这些：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5404e2dc-a57b-47cf-82db-c9c2ac6f079d.jpg)

这就是在 Twitter 的应用程序管理控制台上注册您的应用程序所需的全部内容。接下来我们需要做的是创建我们的 ASP.NET Core MVC 应用程序。

# 创建 ASP.NET Core MVC 应用程序并添加 NuGet 包

现在让我们开始创建 ASP.NET Core MVC 应用程序并向其添加 Twitter 功能：

1.  在 Visual Studio 2017 中，创建一个新的 ASP.NET Core Web 应用程序。我只是在 Twitter 上注册时将我的应用程序命名为相同的名称。点击“确定”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d4c2185b-49f0-4bc4-9a45-66f6060b0404.jpg)

1.  在下一个屏幕上，确保您选择了 Web 应用程序（模型-视图-控制器）模板，并且您已从下拉菜单中选择了 ASP.NET Core 2.0。我特别提到这一点，因为我收到读者的反馈，他们从来没有选择过 ASP.NET Core 2.0。点击“确定”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/023ecb2a-d397-4638-9e79-044f588fa480.jpg)

创建项目后，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d3f46e8e-0d10-4635-895c-dd17082fac13.jpg)

1.  现在我们要去获取 Tweetinvi NuGet 包，因此请右键单击项目，然后从上下文菜单中选择“管理 NuGet 包”，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0de4387c-d49e-44df-9c0d-5d8b202505bc.jpg)

1.  在“浏览”选项卡中，搜索`tweetinvi`，并选择开发人员 Linvi 的项目。点击“安装”按钮将其添加到您的应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ca830e52-68f5-4bf3-9da2-7e3370071284.jpg)

1.  不久后，进度将在 Visual Studio 的输出窗口中显示为已完成：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a1551d6a-9c59-4e23-8b26-e89cc659f32f.jpg)

1.  接下来要做的是将我们的 URL 设置为之前在 Twitter 应用程序管理控制台中设置的回调 URL。为此，请右键单击项目，然后从上下文菜单中单击“属性”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/92027103-c226-424b-b6ae-37f7a05d41fe.jpg)

1.  选择“调试”选项卡，然后在“应用程序 URL”字段中输入回调 URL：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5d68b5fc-75e7-4702-88d2-a0b4f0aae335.jpg)

如果您在应用程序管理控制台中将回调 URL 的`localhost`部分设置为`127.0.0.1`，则在此处也需要将其设置为`127.0.0.1`。

1.  保存您的设置并返回到代码窗口。

从设置的角度来看，这应该是您开始编写代码并连接一切所需的全部内容。让我们开始下一步。

# 让我们开始编码

此项目的所有代码都可以在 GitHub 上找到。将浏览器指向[`github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints`](https://github.com/PacktPublishing/CSharp7-and-.NET-Core-2.0-Blueprints)，并在阅读本章的其余部分时，获取代码并进行操作。

# 设置类和设置

我想要做的第一件事是创建一个将存储我的设置的类。为此，请执行以下步骤：

1.  创建一个名为`Classes`的文件夹，在该文件夹中创建一个名为`CoreTwitterSettings`的类。然后，在`Classes`文件夹中添加一个名为`TweetItem`的第二个类（我们稍后将使用此类）。在此过程中，创建另一个名为`css`的文件夹，我们稍后将使用它。

1.  完成后，您的项目将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/aadebeb3-b567-4a58-bdfe-eb62b292f4ed.jpg)

1.  打开`CoreTwitterSettings`类，并向其中添加以下代码：

```cs
public class CoreTwitterConfiguration 
{ 
    public string ApplicationName { get; set; } 
    public int TweetFeedLimit { get; set; } = 1; 

    public TwitterSettings TwitterConfiguration { get; set; } = new 
    TwitterSettings(); 
} 

public class TwitterSettings 
{ 
    public string Consumer_Key { get; set; } 
    public string Consumer_Secret { get; set; } 
    public string Access_Token { get; set; } 
    public string Access_Secret { get; set; } 
} 
```

1.  我们要做的下一件事是找到我们的`appsettings.json`文件。该文件将位于您的项目根目录中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a68f93de-f0da-4575-a7bf-5179b708fdee.jpg)

1.  双击`appsettings.json`文件以打开进行编辑。文件的默认内容应如下所示：

```cs
{ 
  "Logging": { 
    "IncludeScopes": false, 
    "LogLevel": { 
      "Default": "Warning" 
    } 
  } 
} 
```

1.  修改文件以包含您想要存储的设置。`appsettings.json`文件的目的是存储您应用程序的所有设置。

1.  将您的 Consumer Key 和 Consumer Secret 密钥添加到文件中。还要注意，我已经使用了一个基本 URL 的设置，这是之前设置的回调 URL。这在设置中有时很方便。我还创建了一个名为`TweetFeedLimit`的设置，以限制返回到主页时间线的推文。

您的 Consumer Key 和 Consumer Secret 肯定与我的示例中的值不同。因此，请确保相应地更改这些值。

1.  修改您的`appsettings.json`文件后，它将如下所示：

```cs
{ 
  "Logging": { 
    "IncludeScopes": false, 
    "LogLevel": { 
      "Default": "Warning" 
    } 
  }, 

  "CoreTwitter": { 
    "ApplicationName": "Twitter Core Clone (local)", 
    "TweetFeedLimit": 10, 
    "BaseUrl": "http://localhost:50000/", 
    "TwitterConfiguration": { 
      "Consumer_Key": "[YOUR_CONSSUMER_KEY]", 
      "Consumer_Secret": "[YOUR_CONSUMER_SECRET]", 
      "Access_Token": "", 
      "Access_Secret": "" 
    } 
  } 
} 
```

1.  如果您查看`CoreTwitterSettings`类，您会发现它与`appsettings.json`文件中的 JSON 略有相似。

1.  在您的 Visual Studio 解决方案中，找到`Startup.cs`文件并打开进行编辑。您会看到 Visual Studio 2017 已经为您的这个类添加了很多样板代码。特别注意`ConfigureServices`方法。它应该看起来像这样：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 
    services.AddMvc(); 
} 
```

1.  自 ASP.NET Core 1.1 以来，我们已经能够使用`Get<T>`，它可以与整个部分一起使用。要使设置在我们的 ASP.NET Core MVC 应用程序中可用，请将此方法中的代码更改如下：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 
    services.AddMvc(); 

    var section = Configuration.GetSection("CoreTwitter"); 
    services.Configure<CoreTwitterConfiguration>(section);             
} 
```

您会注意到我们正在获取`appsettings.json`文件中定义的`CoreTwitter`部分。

# 创建`TweetItem`类

`TweetItem`类只是简单地包含特定推文的 URL。它并不是一个非常复杂的类，但它的用处将在本章后面变得清晰。现在，只需向其中添加以下代码：

```cs
public class TweetItem 
{ 
    public string Url { get; set; } 
} 
```

它将存储的 URL 将是特定推文的 URL。

# 设置 CSS

为了在推文中使用`<blockquote>` HTML 标签，您将希望向您的`CSS`文件夹中添加一个 CSS 文件。在我们的示例中，我们将不使用它，但随着您进一步构建应用程序，您将希望使用此 CSS 来为您的`<blockquote>`推文设置样式。

如果您现在只是玩玩，完成本章后不打算进一步构建此应用程序，可以跳过添加 CSS 文件的部分。如果您想进一步使用此应用程序，请继续阅读：

1.  右键单击解决方案中的`css`文件夹，并向其中添加一个新项。将文件命名为`site.css`，然后单击“添加”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/160d4c0c-075c-4e35-a9dd-5a2538fb490a.jpg)

1.  删除`site.css`文件的内容，并向其中添加以下`css`：

```cs
blockquote.twitter-tweet { 
    display: inline-block; 
    font-family: "Helvetica Neue", Roboto, "Segoe UI", Calibri,   
    sans-serif; 
    font-size: 12px; 
    font-weight: bold; 
    line-height: 16px; 
    border-color: #eee #ddd #bbb; 
    border-radius: 5px; 
    border-style: solid; 
    border-width: 1px; 
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15); 
    margin: 10px 5px; 
    padding: 0 16px 16px 16px; 
    max-width: 468px; 
} 

blockquote.twitter-tweet p { 
    font-size: 16px; 
    font-weight: normal; 
    line-height: 20px; 
} 

blockquote.twitter-tweet a { 
    color: inherit; 
    font-weight: normal; 
    text-decoration: none; 
    outline: 0 none; 
} 

blockquote.twitter-tweet a:hover, 
blockquote.twitter-tweet a:focus { 
    text-decoration: underline; 
} 
```

为了补充这一部分，你可以阅读 Twitter 开发者文档[`dev.twitter.com/web/overview/css`](https://dev.twitter.com/web/overview/css)，并查看 CSS 概述。

# 添加控制器

现在我们需要开始添加我们的控制器。控制器负责响应应用程序发出的请求：

1.  在`Controllers`文件夹中，添加另一个名为`TwitterController`的控制器。这个控制器将负责撰写新推文和发布新推文。稍后我们会回到这个控制器。现在，只需创建这个类。添加完后，你的解决方案应该如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/bf5d9ef8-381a-4114-b7dd-ddfc01a724b4.jpg)

1.  默认情况下，当你创建 ASP.NET Core MVC 应用程序时，Visual Studio 会为你添加`HomeController`。打开`HomeController`并查看类的内容。确保在`HomeController`类中添加以下`using`语句：

```cs
using Tweetinvi; 
using Tweetinvi.Models; 
```

1.  我想要做的第一件事是让我的应用程序设置存储在`appsettings.json`文件中在我的类中可用。你会记得我们修改了`Startup.cs`文件，在启动时注入了这些设置。

1.  在`HomeController`类的顶部，添加以下代码行：

```cs
CoreTwitterConfiguration config;
```

1.  在那行的下面，添加一个构造函数，将`CoreTwitterConfiguration`类引入我们控制器的范围内：

```cs
public HomeController(IOptions<CoreTwitterConfiguration> options) 
{ 
    config = options.Value; 
} 
```

1.  现在我们将修改`HomeController`类的`Index`动作，检查我们是否有访问令牌或访问密钥。你会记得我们之前在`appsettings.json`文件中将它们留空。如果它们为空，那么用户就没有被认证，然后我们将重定向用户到`HomeController`的`AuthenticateTwitter`动作：

```cs
public IActionResult Index() 
{ 
    try 
    { 
        if (String.IsNullOrWhiteSpace(config.TwitterConfiguration.Access_Token)) throw new Tweetinvi.Exceptions.TwitterNullCredentialsException(); 
        if (String.IsNullOrWhiteSpace(config.TwitterConfiguration.Access_Secret)) throw new Tweetinvi.Exceptions.TwitterNullCredentialsException();                                 
    } 
    catch (Tweetinvi.Exceptions.TwitterNullCredentialsException ex) 
    { 
        return RedirectToAction("AuthenticateTwitter"); 
    } 
    catch (Exception ex) 
    { 
        // Redirect to your error page here 
    } 
    return View(); 
} 
```

1.  现在让我们去创建`AuthenticateTwitter`动作。为此，我们需要消费者凭证，这些凭证我们之前从 Twitter 应用管理控制台复制并添加到我们的`appsettings.json`文件中。然后我们使这些设置在整个应用程序中可用；现在我们可以看到将设置存储在`appsettings.json`文件中的好处。

1.  在`AuthenticateTwitter`动作中，我们只需将`ConsumerCredentials`对象传递给消费者密钥和消费者密钥。当我们验证通过时，我们将路由到`ValidateOAuth`动作，接下来我们将创建这个动作：

```cs
public IActionResult AuthenticateTwitter() 
{ 
    var coreTwitterCredentials = new ConsumerCredentials( 
        config.TwitterConfiguration.Consumer_Key 
        , config.TwitterConfiguration.Consumer_Secret); 
         var callbackURL = "http://" + Request.Host.Value + 
         "/Home/ValidateOAuth"; 
    var authenticationContext = 
    AuthFlow.InitAuthentication(coreTwitterCredentials,  
    callbackURL); 

    return new 
    RedirectResult(authenticationContext.AuthorizationURL); 
} 
```

1.  在这一点上，我们已经被重定向到 Twitter 进行 OAuth 用户认证，并通过回调 URL 被重定向回我们的 ASP.NET Core 应用程序。代码非常简单。需要注意的一点是`userCredentials.AccessToken`和`userCredentials.AccessTokenSecret`是从`userCredentials`对象返回的。我只是把它们添加到了应用程序的配置设置中，但实际上，你可能希望将它们存储在其他地方（比如加密在数据库中）。这样就可以让你在不需要每次都进行身份验证的情况下使用应用程序：

```cs
public ActionResult ValidateOAuth() 
{ 
    if (Request.Query.ContainsKey("oauth_verifier") &&  
    Request.Query.ContainsKey("authorization_id")) 
    { 
        var oauthVerifier = Request.Query["oauth_verifier"]; 
        var authId = Request.Query["authorization_id"]; 

        var userCredentials =  
        AuthFlow.CreateCredentialsFromVerifierCode(oauthVerifier, 
        authId); 
        var twitterUser = 
        Tweetinvi.User.GetAuthenticatedUser(userCredentials); 

        config.TwitterConfiguration.Access_Token = 
        userCredentials.AccessToken; 
        config.TwitterConfiguration.Access_Secret = 
        userCredentials.AccessTokenSecret; 

        ViewBag.User = twitterUser; 
    } 

    return View(); 
} 
```

由于这个控制器动作被称为`ValidateOAuth`，让我们去创建一个同名的视图，这样我们就可以路由到一个页面，通知用户他们已经成功认证。

# 创建视图

视图和传统的 HTML 页面并不是同一回事。ASP.NET Core MVC 应用程序的页面由视图表示。正如我之前指出的，控制器接收请求并处理该请求。控制器可以将你重定向到另一个控制器动作，但也可以返回一个视图：

1.  现在我们将继续创建应用程序的视图。展开`Home`文件夹，并在`Home`文件夹中添加一个名为`ValidateOAuth`的新视图。只需创建这些视图而不需要模型：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/93d5351d-0ec7-4612-bab1-9243680d8d64.jpg)

1.  在`Views`文件夹中添加一个名为`Twitter`的文件夹，并在该文件夹中添加两个视图，分别为`ComposeTweet`和`HomeTimeline`。完成后，你的应用程序将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0176b51a-53c5-4631-8feb-6a76996d894d.jpg)

1.  打开`ValidateOAuth`视图，并向其添加以下标记：

```cs
@if (@ViewBag.User != null) 
{ 
    <h2>OAuth Authentication Succeeded!</h2> 
    <p>Welcome to the CoreTwitter Demo Application <b>@ViewBag.User.Name</b>. You have been successfully authenticated via Twitter.</p> 

    <div class="row"> 
        <div class="col-md-4"> 
            <h2>Go to your home feed</h2> 
            <p> 
                See what's new on your home feed. 
            </p> 
            <p> 
                <a class="btn btn-default" 
                 href="/Home/GetHomeTimeline">Home &raquo;</a> 
            </p> 
        </div> 
    </div> 
} 
else 
{ 
    <h2>OAuth Authentication failed!</h2> 
    <p>An error occurred during authentication. Try <a  
     href="/Home/TwitterAuth">authenticating</a> again.</p> 
} 
```

看一下标记，你会注意到它只是通知用户认证状态。如果经过认证，用户可以查看他们的主页动态，这是他们在 Twitter 上关注的人的所有推文。

我想在这里提醒你一下，我是如何在`Home`控制器上调用`GetHomeTimeline`动作的。你会在按钮链接中看到以下`href`存在：

```cs
href="/Home/GetHomeTimeline" 
```

这是将用户路由到控制器上的一个方法。稍后，我会向你展示另一种更好的方法来做到这一点。

因此，我们允许成功认证的用户通过点击`Home`链接查看他们关注的人的推文。这调用了一个名为`GetHomeTimeline`的动作。让我们去修改`HomeController`以添加这个动作。

# 修改 HomeController

回到`HomeController`，并添加另一个名为`GetHomeTimeline`的动作。然后，使用用户凭据查找经过认证用户的主页时间线推文。用户凭据包括以下内容：

+   消费者密钥

+   消费者密钥

+   访问令牌

+   访问密钥

你会注意到这些都来自`CoreTwitterConfiguration`对象。推特动态只包括在设置中设置的限制。我将我的设置为`10`，所以这应该只包含 10 条推文。对于动态中的每条推文，我提取推文的 URL 并将其添加到`TweetItem`类型的列表中（我们之前创建的类）。如果一切顺利，我就路由到`HomeTimeline`视图。

将以下代码添加到你的`GetHomeTimeline`动作中。

你应该在引用名为`homeView`的`TwitterViewModel`实例的代码上得到一个错误。我们接下来将纠正这个错误。

你的动作应该如下所示：

```cs
public IActionResult GetHomeTimeline() 
{ 
    TwitterViewModel homeView = new TwitterViewModel(); 

    try 
    { 
        if (config.TwitterConfiguration.Access_Token == null) throw new 
        Tweetinvi.Exceptions.TwitterNullCredentialsException(); 
        if (config.TwitterConfiguration.Access_Secret == null) throw 
        new Tweetinvi.Exceptions.TwitterNullCredentialsException(); 

        var userCredentials = Auth.CreateCredentials( 
            config.TwitterConfiguration.Consumer_Key 
            , config.TwitterConfiguration.Consumer_Secret 
            , config.TwitterConfiguration.Access_Token 
            , config.TwitterConfiguration.Access_Secret); 

        var authenticatedUser =  
        Tweetinvi.User.GetAuthenticatedUser(userCredentials); 

        IEnumerable<ITweet> twitterFeed = 
        authenticatedUser.GetHomeTimeline(config.TweetFeedLimit); 

        List<TweetItem> tweets = new List<TweetItem>(); 
        foreach(ITweet tweet in twitterFeed) 
        { 
            TweetItem tweetItem = new TweetItem();                     

            tweetItem.Url = tweet.Url; 
            tweets.Add(tweetItem); 
        } 

        homeView.HomeTimelineTweets = tweets;                 
    } 
    catch (Tweetinvi.Exceptions.TwitterNullCredentialsException ex) 
    { 
        return RedirectToAction("AuthenticateTwitter"); 
    } 
    catch (Exception ex) 
    { 

    } 

    return View("Views/Twitter/HomeTimeline.cshtml", homeView); 
} 
```

如前所述，你会看到一些错误。这是因为我们还没有一个名为`TwitterViewModel`的模型。让我们接下来创建它。

# 创建 TwitterViewModel 类

`TwitterViewModel`类只是一个非常简单的类，它将`TweetItem`的集合作为名为`HomeTimelineTweets`的属性。

让我们首先向我们的项目添加一个模型：

1.  右键单击`Models`文件夹，然后在文件夹中添加一个名为`TwitterViewModel`的类。然后，将以下代码添加到该类中：

```cs
public class TwitterViewModel 
{ 
    public List<TweetItem> HomeTimelineTweets { get; set; } 
}
```

1.  还要向类添加`using`语句`using CoreTwitter.Classes;`。

这就是所需要的一切。当你稍后扩展`TweetItem`类（如果你决定为这个应用添加功能），这个模型将负责将这些信息传递给我们的视图，以便在 Razor 中使用。

# 创建 HomeTimeline 视图

回想一下我们之前创建的`HomeController`动作`GetHomeTimeline`，你会记得我们路由到一个名为`HomeTimeline`的视图。我们已经创建了这个视图，但现在我们需要向它添加一些逻辑来呈现我们主页时间线中的推文。

因此，我们需要为我们的主页时间线添加一个视图，接下来我们将添加：

1.  打开`HomeTimeline.cshtml`文件，并向视图添加以下标记：

```cs
@model TwitterViewModel 
@{ 
    ViewBag.Title = "What's happening?"; 
} 

<h2>Home - Timeline</h2> 

<div class="row"> 
    <div class="col-md-8"> 

        @foreach (var tweet in Model.HomeTimelineTweets) 
        { 
            <blockquote class="twitter-tweet"> 
                <p lang="en" dir="ltr"> 
                    <a href="@Html.DisplayFor(m => tweet.Url)"></a> 
            </blockquote> 
            <script async 
             src="img/widgets.js" 
             charset="utf-8"></script> 
        } 
    </div> 

    <div class="col-md-4"> 
        <h2>Tweet</h2> 
        <p>What's happening?</p> 
        <a class="btn btn-default" asp-controller="Twitter" asp-
         action="ComposeTweet">Tweet &raquo;</a>   
    </div> 

</div> 
```

你需要注意的第一件事是文件顶部的`@model TwitterViewModel`语句。这允许我们在视图中使用模型中存储的值。我们的视图循环遍历模型的`HomeTimelineTweets`属性中包含的推文集合，并构建一个要在页面上显示的推文列表。

我想要引起你的注意的另一件事是 Tweet 链接上的标签助手`asp-controller`和`asp-action`。这是一种更干净的方式，可以路由到特定控制器上的特定动作（而不是像我们之前在`ValidateOAuth`视图中看到的那样在`href`中进行路由）。

最后，你可能想知道`widgets.js`引用是做什么的。好吧，我不想自己设计我的推文样式，所以我决定让 Twitter 为我做。

1.  要获取标记，请转到[`publish.twitter.com/#`](https://publish.twitter.com/#)：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/62b13e2c-04bd-441d-9a90-355c75e29b6e.jpg)

1.  从下拉菜单中，选择“A Tweet”作为您要嵌入的内容的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/4b4af95e-1794-4878-a582-d45f1ebc3fbf.jpg)

1.  然后您将获得一些示例代码供使用。 您只需单击复制代码按钮。 这只是我做的方式，但欢迎您在不经过此步骤的情况下自行前进：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/eb2c4055-8b95-41f4-8ce2-2c0c8ef713cc.jpg)

1.  您复制的代码可能看起来像以下内容：

```cs
<blockquote class="twitter-tweet"> 
        <p lang="en" dir="ltr">Sunsets don't get much better than 
         this one over <a href="https://twitter.com/GrandTetonNPS?
         ref_src=twsrc%5Etfw">@GrandTetonNPS</a>. 
        <a href="https://twitter.com/hashtag/nature?
         src=hash&amp;ref_src=twsrc%5Etfw">#nature</a> 
        <a href="https://twitter.com/hashtag/sunset?
         src=hash&amp;ref_src=twsrc%5Etfw">#sunset</a> 
    <a href="http://t.co/YuKy2rcjyU">pic.twitter.com/YuKy2rcjyU</a> 
            </p>&mdash; US Department of the Interior (@Interior) 
    <a href="https://twitter.com/Interior/status/463440424141459456?
     ref_src=twsrc%5Etfw">May 5, 2014</a> 
    </blockquote> 
    <script async src="img/widgets.js" 
     charset="utf-8"></script> 
```

1.  将其修改为根据您的页面进行样式设置。 在循环中执行此操作，以便您可以单独输出所有推文。 您最终应该得到的代码只是：

```cs
<blockquote class="twitter-tweet"> 
    <p lang="en" dir="ltr"> 
        <a href="@Html.DisplayFor(m => tweet.Url)"></a> 
</blockquote> 
<script async src="img/widgets.js" charset="utf-8"></script> 
```

它只包含指向 Twitter URL 的链接。

# 修改 TwitterController 类

现在我们来到了允许用户发送推文的部分。

打开`TwitterController`类并添加名为`ComposeTweet`和`PublishTweet`的两个操作。 `TwitterController`类非常简单。 它只包含以下代码：

```cs
public class TwitterController : Controller 
{         
    public IActionResult ComposeTweet() 
    {             
        return View(); 
    } 

    public IActionResult PublishTweet(string tweetText) 
    { 
        var firstTweet = Tweet.PublishTweet(tweetText); 

        return RedirectToAction("GetHomeTimeline", "Home");  
    } 
} 
```

`ComposeTweet`操作只是简单地将用户返回到一个视图，他们可以在其中撰写推文。 您会记得我们之前创建了`ComposeTweet`视图。 `PublishTweet`操作同样简单。 它获取我要发推文的文本，并将其传递给`Tweetinvi.Tweet`类的`PublishTweet`方法。 之后，将重定向回主页时间线，我们期望在那里看到我们刚刚创建的推文。

我们需要完成的最后一个任务是修改`ComposeTweet`视图。 让我们接下来做这件事。

# 完成-ComposeTweet 视图

最后，我们使用`ComposeTweet`视图。

打开`ComposeTweet`视图并向视图添加以下标记：

```cs
@{ 
    ViewData["Title"] = "Tweet"; 
} 

<h2>Tweet</h2> 

<form method="post" asp-controller="Twitter" asp-action="PublishTweet"> 

    <div class="form-group"> 
        <label for="tweet">Tweet : </label> 
        <input type="text" class="form-control" name="tweetText" 
         id="tweetText" value="What's happening?" /> 
    </div> 

    <div class="form-group"> 
        <input type="submit" class="btn btn-success" /> 
    </div> 
</form> 
```

您会注意到，我再次使用标签助手来定义要调用的控制器和操作。 只是这一次，我是在`<form>`标签上这样做的。 在这一点上，您已经准备好首次运行应用程序了。 让我们看看它的表现如何。

# 运行 CoreTwitter 应用程序

对项目进行构建，以确保一切构建正确。 然后，开始调试您的应用程序。 因为您尚未经过身份验证，所以将被重定向到 Twitter 进行身份验证。

这是一个您肯定习惯看到的页面：

1.  许多网络应用程序使用 OAuth 进行身份验证。 要继续，请点击授权应用程序按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7c31e5d1-519d-4726-a8f2-996748b2be0b.jpg)

1.  然后您将看到一个重定向通知。 这可能需要一些时间来重定向您。 这完全取决于您的互联网连接速度：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/16d5aebc-76d9-43e1-b267-30d566c50e9c.jpg)

1.  一旦您被重定向到您的 CoreTwitter 应用程序，您将看到 OAuth 身份验证成功的消息。 之后，点击主页按钮转到“主页时间线”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ae259f22-b22d-4cef-b8f6-4e87510b8b07.jpg)

1.  `HomeController`开始执行，因为调用`GetHomeTimeline`操作并将您重定向到`HomeTimeline`视图。 您将在页面中看到加载的推文：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ee698277-a488-4be4-a2f5-1246e1641e58.jpg)

1.  当您滚动浏览推文时（记住，我只返回了 10 条），您将看到包含视频的推文，当您单击播放按钮时将播放：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/8a119557-0548-44a6-a578-f49a8673137b.jpg)

1.  富媒体推文还会为您提供文章预览，并且您还将在时间轴中看到普通的文本推文。 所有链接都是完全活动的，您可以单击它们以查看文章：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b8d90cfd-55c3-4dcf-84e5-3637faca8b6a.jpg)

1.  如果您向右滚动到时间轴的底部（这应该在顶部，但我告诉过您我不打算在 UI 周围做太多事情），您将看到“推文”按钮。 单击它以撰写新推文：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fe82dbad-3609-4813-95ea-095decbb86f8.jpg)

1.  在`ComposeTweet`视图上，您可以在推文字段中输入任何内容，然后单击“提交查询”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/1ddd9137-2214-4353-8c49-cae23fbc20b2.jpg)

1.  你的推文随后会发布在 Twitter 上，然后你会被重定向到主页时间轴，你会在那里看到你新发布的推文：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/4e99f2e9-4d04-448f-badb-dba999404f06.jpg)

而且，仅仅为了这个缘故，你可以通过访问以下 URL 来查看特定的推文：[`twitter.com/DirkStrauss/status/973002561979547650`](https://twitter.com/DirkStrauss/status/973002561979547650)。

是的，现在真的是凌晨 3:07。`#就是这样`。

# 总结

回顾这一章，我们确实做了很多。我鼓励你去 GitHub 上查看代码，以及在[`github.com/linvi/tweetinvi`](https://github.com/linvi/tweetinvi)上可用的 Tweetinvi 文档。在这一章中，我们看到了如何在 Twitter 的应用程序管理控制台上注册我们的应用程序。我们看到我们可以通过使用一个叫做 Tweetinvi 的 NuGet 包，轻松地为我们的 ASP.NET Core MVC 应用程序添加 Twitter 功能。我们看了一下路由，以及控制器、模型、视图，以及将设置存储在`appsetting.json`文件中。

我们能够通过 OAuth 进行身份验证，并从我们的主页时间轴中读取最后 10 条推文。最后，我们能够发布一条推文，并在我们的主页时间轴中查看它。

在我们的 Twitter 克隆应用程序中仍然有很多工作可以做。我希望你觉得这是一个有趣的章节，并希望你继续努力改进它，以适应你特定的工作流程，并使其成为你自己的。

在下一章中，我们将看一下 Docker 以及作为软件开发人员对你意味着什么。我们还将看到如何在 Docker 容器中运行我们的 ASP.NET Core MVC 应用程序。
