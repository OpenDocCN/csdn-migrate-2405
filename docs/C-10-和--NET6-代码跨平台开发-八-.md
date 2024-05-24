# C#10 和 .NET6 代码跨平台开发（八）

> 原文：[`zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF`](https://zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：使用模型-视图-控制器模式构建网站

本章介绍使用 Microsoft ASP.NET Core MVC 在服务器端构建具有现代 HTTP 架构的网站，包括启动配置、身份验证、授权、路由、请求和响应管道、模型、视图和构成 ASP.NET Core MVC 项目的控制器。

本章将涵盖以下主题：

+   设置 ASP.NET Core MVC 网站

+   探索 ASP.NET Core MVC 网站

+   自定义 ASP.NET Core MVC 网站

+   查询数据库并使用显示模板

+   通过使用异步任务提高可扩展性

# 设置 ASP.NET Core MVC 网站

ASP.NET Core Razor Pages 非常适合简单的网站。对于更复杂的网站，最好有一个更正式的结构来管理这种复杂性。

这就是**模型-视图-控制器**（**MVC**）设计模式发挥作用的地方。它使用 Razor Pages 等技术，但允许技术关注点之间有更清晰的分离，如下所示：

+   **模型**：表示网站上使用的数据实体和视图模型的类。

+   **视图**：Razor 文件，即`.cshtml`文件，将视图模型中的数据渲染成 HTML 网页。Blazor 使用`.razor`文件扩展名，但不要将其与 Razor 文件混淆！

+   **控制器**：HTTP 请求到达 Web 服务器时执行代码的类。控制器方法通常创建一个可能包含实体模型的视图模型，并将其传递给视图以生成 HTTP 响应，发回给 Web 浏览器或其他客户端。

理解使用 MVC 设计模式进行 Web 开发的最佳方式是查看一个实际示例。

## 创建一个 ASP.NET Core MVC 网站

您将使用项目模板创建一个具有用于身份验证和授权用户的数据库的 ASP.NET Core MVC 网站项目。Visual Studio 2022 默认使用 SQL Server LocalDB 作为账户数据库。Visual Studio Code（或更准确地说，`dotnet`工具）默认使用 SQLite，您可以通过指定开关改用 SQL Server LocalDB。

让我们看看它的实际效果：

1.  使用您喜欢的代码编辑器添加一个具有存储在数据库中的身份验证账户的 MVC 网站项目，如下表所示：

    1.  项目模板：**ASP.NET Core Web App（模型-视图-控制器）** / `mvc`

    1.  语言：C#

    1.  工作区/解决方案文件和文件夹：`PracticalApps`

    1.  项目文件和文件夹：`Northwind.Mvc`

    1.  选项：**身份验证类型：个人账户** / `--auth Individual`

    1.  对于 Visual Studio，将所有其他选项保留为其默认值

1.  在 Visual Studio Code 中，选择`Northwind.Mvc`作为活动 OmniSharp 项目。

1.  构建`Northwind.Mvc`项目。

1.  在命令行或终端中，使用`help`开关查看此项目模板的其他选项，如下所示：

    ```cs
    dotnet new mvc --help 
    ```

1.  注意结果，如下所示的部分输出：

    ```cs
    ASP.NET Core Web App (Model-View-Controller) (C#)
    Author: Microsoft
    Description: A project template for creating an ASP.NET Core application with example ASP.NET Core MVC Views and Controllers. This template can also be used for RESTful HTTP services.
    This template contains technologies from parties other than Microsoft, see https://aka.ms/aspnetcore/6.0-third-party-notices for details. 
    ```

有许多选项，特别是与身份验证相关的选项，如下表所示：

| 开关 | 描述 |
| --- | --- |
| `-au&#124;--auth` | 使用的认证类型：`None`（默认）：此选择还允许你禁用 HTTPS。`Individual`：个人认证，将注册用户及其密码存储在数据库中（默认使用 SQLite）。我们将在本章创建的项目中使用此选项。`IndividualB2C`：使用 Azure AD B2C 的个人认证。`SingleOrg`：单租户的组织认证。`MultiOrg`：多租户的组织认证。`Windows`：Windows 认证。主要用于内网。 |
| `-uld&#124;--use-local-db` | 是否使用 SQL Server LocalDB 代替 SQLite。此选项仅在指定`--auth Individual`或`--auth IndividualB2C`时适用。值是一个可选的`bool`，默认值为`false`。 |
| `-rrc&#124;--razor-runtime-compilation` | 确定项目是否配置为在`Debug`构建中使用 Razor 运行时编译。这可以提高调试时启动的性能，因为它可以延迟 Razor 视图的编译。值是一个可选的`bool`，默认值为`false`。 |
| `-f&#124;--framework` | 项目的目标框架。值可以是：`net6.0`（默认）、`net5.0`或`netcoreapp3.1` |

## 为 SQL Server LocalDB 创建认证数据库

如果你使用 Visual Studio 2022 创建了 MVC 项目，或者你使用`dotnet new mvc`并带有`-uld`或`--use-local-db`开关，那么用于认证和授权的数据库将存储在 SQL Server LocalDB 中。但该数据库尚未存在。现在让我们创建它。

在命令提示符或终端中，在`Northwind.Mvc`文件夹下，输入运行数据库迁移的命令，以便创建用于存储认证凭据的数据库，如下所示：

```cs
dotnet ef database update 
```

如果你使用`dotnet new`创建了 MVC 项目，那么用于认证和授权的数据库将存储在 SQLite 中，且已创建名为`app.db`的文件。

认证数据库的连接字符串名为`DefaultConnection`，它存储在 MVC 网站项目根目录下的`appsettings.json`文件中。

对于 SQL Server LocalDB（使用截断的连接字符串），请参见以下标记：

```cs
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=aspnet-Northwind.Mvc-...;Trusted_Connection=True;MultipleActiveResultSets=true"
  }, 
```

对于 SQLite，请参见以下标记：

```cs
{
  "ConnectionStrings": {
    "DefaultConnection": "DataSource=app.db;Cache=Shared"
  }, 
```

## 探索默认的 ASP.NET Core MVC 网站

让我们回顾一下默认 ASP.NET Core MVC 网站项目模板的行为：

1.  在`Northwind.Mvc`项目中，展开`Properties`文件夹，打开`launchSettings.json`文件，并注意为项目配置的随机端口号（你的将不同），用于`HTTPS`和`HTTP`，如下所示：

    ```cs
    "profiles": {
      "Northwind.Mvc": {
        "commandName": "Project",
        "dotnetRunMessages": true,
        "launchBrowser": true,
        "applicationUrl": "https://localhost:7274;http://localhost:5274",
        "environmentVariables": {
          "ASPNETCORE_ENVIRONMENT": "Development"
        }
      }, 
    ```

1.  将端口号更改为`5001`用于`HTTPS`，`5000`用于`HTTP`，如下所示：

    ```cs
    "applicationUrl": "https://localhost:5001;http://localhost:5000", 
    ```

1.  保存对`launchSettings.json`文件的更改。

1.  启动网站。

1.  启动 Chrome 并打开**开发者工具**。

1.  导航至`http://localhost:5000/`并注意以下内容，如图*15.1*所示：

    +   HTTP 请求会自动重定向到端口`5001`上的 HTTPS。

    +   顶部导航菜单，包含**首页**、**隐私**、**注册**和**登录**的链接。如果视口宽度为 575 像素或更小，则导航会折叠成一个汉堡菜单。

    +   网站标题**Northwind.Mvc**，显示在页眉和页脚中。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_01.png)

图 15.1：ASP.NET Core MVC 项目模板网站首页

### 理解访问者注册

默认情况下，密码必须至少包含一个非字母数字字符，至少包含一个数字（0-9），以及至少包含一个大写字母（A-Z）。在这种探索场景中，我使用`Pa$$w0rd`。

MVC 项目模板遵循**双重选择加入**（**DOI**）的最佳实践，这意味着在填写电子邮件和密码进行注册后，会向该电子邮件地址发送一封电子邮件，访问者必须点击该电子邮件中的链接以确认他们想要注册。

我们尚未配置电子邮件提供商来发送该电子邮件，因此我们必须模拟这一步骤：

1.  在顶部导航菜单中，点击**注册**。

1.  输入电子邮件和密码，然后点击**注册**按钮。（我使用了`test@example.com`和`Pa$$w0rd`。）

1.  点击文本为**点击此处确认您的账户**的链接，并注意您将被重定向到一个可以自定义的**确认电子邮件**网页。

1.  在顶部导航菜单中，点击**登录**，输入您的电子邮件和密码（注意有一个可选的复选框用于记住您，以及如果访问者忘记密码或想要注册为新访问者时的链接），然后点击**登录**按钮。

1.  在顶部导航菜单中点击您的电子邮件地址。这将导航到账户管理页面。请注意，您可以设置电话号码，更改您的电子邮件地址，更改您的密码，启用两因素认证（如果您添加了认证器应用），以及下载和删除您的个人数据。

1.  关闭 Chrome 并关闭网络服务器。

## 审查 MVC 网站项目结构

在您的代码编辑器中，在 Visual Studio **解决方案资源管理器**（切换显示**所有文件**）或在 Visual Studio Code **资源管理器**中，审查 MVC 网站项目的结构，如图 15.2 所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_02.png)

图 15.2：ASP.NET Core MVC 项目的默认文件夹结构

我们稍后将对其中一些部分进行更详细的探讨，但目前请注意以下几点：

+   `区域`：此文件夹包含用于将您的网站项目与**ASP.NET Core Identity**（用于身份验证）集成的嵌套文件夹和文件。

+   `bin`、`obj`：这些文件夹包含构建过程中所需的临时文件和项目的已编译程序集。

+   `控制器`：此文件夹包含具有方法（称为动作）的 C#类，这些方法获取模型并将其传递给视图，例如，`HomeController.cs`。

+   `Data`：此文件夹包含 Entity Framework Core 迁移类，这些类由 ASP.NET Core Identity 系统用于提供身份验证和授权的数据存储，例如`ApplicationDbContext.cs`。

+   `Models`：此文件夹包含表示由控制器收集并传递给视图的所有数据的 C#类，例如`ErrorViewModel.cs`。

+   `Properties`：此文件夹包含 Windows 上 IIS 或 IIS Express 的配置文件，以及在开发期间启动网站的名为`launchSettings.json`的文件。此文件仅用于本地开发机器，不会部署到生产网站。

+   `Views`：此文件夹包含结合 HTML 和 C#代码以动态生成 HTML 响应的`.cshtml` Razor 文件。`_ViewStart`文件设置默认布局，`_ViewImports`导入所有视图中使用的公共命名空间，如标签助手：

    +   `Home`：此子文件夹包含主页和隐私页面的 Razor 文件。

    +   `Shared`：此子文件夹包含用于共享布局、错误页面以及登录和验证脚本的两个部分视图的 Razor 文件。

+   `wwwroot`：此文件夹包含网站使用的静态内容，如用于样式的 CSS、JavaScript 库、此网站项目的 JavaScript 以及`favicon.ico`文件。您还可以在此处放置图像和其他静态文件资源，如 PDF 文档。项目模板包括 Bootstrap 和 jQuery 库。

+   `app.db`：这是存储注册访问者的 SQLite 数据库。（如果您使用 SQL Server LocalDB，则不需要它。）

+   `appsettings.json` 和 `appsettings.Development.json`：这些文件包含网站运行时可加载的设置，例如 ASP.NET Core Identity 系统的数据库连接字符串和日志级别。

+   `Northwind.Mvc.csproj`：此文件包含项目设置，如使用 Web .NET SDK、确保`app.db`文件被复制到网站输出目录的 SQLite 入口，以及项目所需的一列 NuGet 包，包括：

    +   `Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore`

    +   `Microsoft.AspNetCore.Identity.EntityFrameworkCore`

    +   `Microsoft.AspNetCore.Identity.UI`

    +   `Microsoft.EntityFrameworkCore.Sqlite` 或 `Microsoft.EntityFrameworkCore.SqlServer`

    +   `Microsoft.EntityFrameworkCore.Tools`

+   `Program.cs`：此文件定义了一个隐藏的`Program`类，其中包含`Main`入口点。它构建了一个处理传入 HTTP 请求的管道，并使用默认选项（如配置 Kestrel Web 服务器和加载`appsettings`）托管网站。它添加并配置了网站所需的服务，例如用于身份验证的 ASP.NET Core Identity、用于身份数据存储的 SQLite 或 SQL Server 等，以及应用程序的路由。

## 审查 ASP.NET Core Identity 数据库

打开`appsettings.json`以找到用于 ASP.NET Core Identity 数据库的连接字符串，如下面的标记中突出显示的 SQL Server LocalDB 所示：

```cs
{
  "ConnectionStrings": {
    "DefaultConnection": "**Server=(localdb)\\mssqllocaldb;Database=aspnet-Northwind.Mvc-2F6A1E12-F9CF-480C-987D-FEFB4827DE22;Trusted_Connection=True;MultipleActiveResultSets=true**"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*"
} 
```

如果你使用 SQL Server LocalDB 作为身份数据存储，那么你可以使用**服务器资源管理器**连接到数据库。你可以从`appsettings.json`文件复制并粘贴连接字符串（但需移除`(localdb)`和`mssqllocaldb`之间的第二个反斜杠）。

如果你安装了 SQLite 工具，如 SQLiteStudio，那么你可以打开 SQLite 的`app.db`数据库文件。

随后，你可以看到 ASP.NET Core Identity 系统用于注册用户和角色的表格，包括用于存储注册访问者的`AspNetUsers`表。

**最佳实践**：ASP.NET Core MVC 项目模板通过存储密码的哈希值而不是密码本身来遵循最佳实践，你将在*第二十章*，*保护你的数据和应用程序*中了解更多。

# 探索一个 ASP.NET Core MVC 网站

让我们逐步了解构成现代 ASP.NET Core MVC 网站的各个部分。

## 理解 ASP.NET Core MVC 初始化

恰如其分地，我们将从探索 MVC 网站的默认初始化和配置开始：

1.  打开`Program.cs`文件，并注意到它使用了顶级程序特性（因此有一个隐藏的`Program`类和一个`Main`方法）。这个文件可以被视为从上到下分为四个重要部分。

    .NET 5 及更早版本的 ASP.NET Core 项目模板使用`Startup`类将这些部分分离到不同的方法中，但到了.NET 6，微软鼓励将所有内容放在一个`Program.cs`文件中。

1.  第一部分导入了一些命名空间，如下面的代码所示：

    ```cs
    using Microsoft.AspNetCore.Identity; // IdentityUser
    using Microsoft.EntityFrameworkCore; // UseSqlServer, UseSqlite
    using Northwind.Mvc.Data; // ApplicationDbContext 
    ```

    记住，默认情况下，许多其他命名空间是通过.NET 6 及更高版本的隐式使用功能导入的。构建项目后，全局导入的命名空间可以在以下路径找到：`obj\Debug\net6.0\Northwind.Mvc.GlobalUsings.g.cs`。

1.  第二部分创建并配置了一个 Web 主机构建器。它使用 SQL Server 或 SQLite 注册了一个应用程序数据库上下文，其数据库连接字符串从`appsettings.json`文件加载用于数据存储，添加了 ASP.NET Core Identity 用于身份验证，并配置它使用应用程序数据库，并添加了对带有视图的 MVC 控制器的支持，如下面的代码所示：

    ```cs
    var builder = WebApplication.CreateBuilder(args);
    // Add services to the container.
    var connectionString = builder.Configuration
      .GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
      options.UseSqlServer(connectionString)); // or UseSqlite
    builder.Services.AddDatabaseDeveloperPageExceptionFilter();
    builder.Services.AddDefaultIdentity<IdentityUser>(options => 
      options.SignIn.RequireConfirmedAccount = true)
      .AddEntityFrameworkStores<ApplicationDbContext>();
    builder.Services.AddControllersWithViews(); 
    ```

    `构建器`对象有两个常用对象：`配置`和`服务`。

    +   `配置`包含了所有可能设置配置的地方的合并值：`appsettings.json`、环境变量、命令行参数等。

    +   `服务`是一个注册依赖服务的集合

    调用`AddDbContext`是注册依赖服务的一个示例。ASP.NET Core 实现了**依赖注入**(**DI**)设计模式，使得其他组件如控制器可以通过其构造函数请求所需服务。开发者在这一部分`Program.cs`（或使用`Startup`类时在其`ConfigureServices`方法中）注册这些服务。

1.  第三部分配置了 HTTP 请求管道。它配置了一个相对 URL 路径，在网站运行于开发环境时执行数据库迁移，或在生产环境中提供更友好的错误页面和 HSTS。HTTPS 重定向、静态文件、路由、ASP.NET Identity 被启用，MVC 默认路由和 Razor 页面被配置，如下所示：

    ```cs
    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
      app.UseMigrationsEndPoint();
    }
    else
    {
      app.UseExceptionHandler("/Home/Error");
      // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
      app.UseHsts();
    }
    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllerRoute(
      name: "default",
      pattern: "{controller=Home}/{action=Index}/{id?}");
    app.MapRazorPages(); 
    ```

    我们在*第十四章*，*使用 ASP.NET Core Razor Pages 构建网站*中学习了这些方法和功能的大部分。

    **最佳实践**：扩展方法`UseMigrationsEndPoint`的作用是什么？你可以阅读官方文档，但帮助不大。例如，它没有告诉我们默认定义了什么相对 URL 路径：[`docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.migrationsendpointextensions.usemigrationsendpoint`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.migrationsendpointextensions.usemigrationsendpoint)。幸运的是，ASP.NET Core 是开源的，因此我们可以阅读源代码并发现其作用，链接如下：[`github.com/dotnet/aspnetcore/blob/main/src/Middleware/Diagnostics.EntityFrameworkCore/src/MigrationsEndPointOptions.cs#L18`](https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Diagnostics.EntityFrameworkCore/src/MigrationsEndPointOptions.cs#L18)。养成探索 ASP.NET Core 源代码的习惯，以理解其工作原理。

    除了`UseAuthentication`和`UseAuthorization`方法外，`Program.cs`这一部分最重要的方法是`MapControllerRoute`，它为 MVC 映射了一个默认路由。此路由非常灵活，因为它几乎可以映射到任何传入的 URL，如下一主题所示。

    尽管本章我们不会创建任何 Razor 页面，但我们仍需保留映射 Razor 页面支持的方法调用，因为我们的 MVC 网站使用 ASP.NET Core Identity 进行认证和授权，并使用 Razor 类库为其用户界面组件，如访客注册和登录。

1.  第四个也是最后一个部分包含一个线程阻塞的方法调用，它运行网站并等待传入的 HTTP 请求以进行响应，如下所示：

    ```cs
    app.Run(); // blocking call 
    ```

## 理解 MVC 的默认路由

路由的职责是发现要实例化的控制器类名称和要执行的动作方法，以及一个可选的`id`参数，该参数将传递给生成 HTTP 响应的方法。

MVC 的默认路由配置如下所示：

```cs
endpoints.MapControllerRoute(
  name: "default",
  pattern: "{controller=Home}/{action=Index}/{id?}"); 
```

路由模式在花括号`{}`中的部分称为**段**，它们类似于方法的命名参数。这些段的值可以是任何`字符串`。URL 中的段不区分大小写。

路由模式查看浏览器请求的任何 URL 路径，并匹配它以提取`控制器`的名称、`动作`的名称和可选的`id`值（`?`符号使其可选）。

如果用户未输入这些名称，它将使用默认值`Home`作为控制器，`Index`作为操作（`=`赋值为命名段设置默认值）。

下表包含示例 URL 以及默认路由如何确定控制器和动作的名称：

| URL | 控制器 | 动作 | ID |
| --- | --- | --- | --- |
| `/` | Home | Index |  |
| `/Muppet` | Muppet | Index |  |
| `/Muppet/Kermit` | Muppet | Kermit |  |
| `/Muppet/Kermit/Green` | Muppet | Kermit | Green |
| `/Products` | Products | Index |  |
| `/Products/Detail` | Products | Detail |  |
| `/Products/Detail/3` | Products | Detail | 3 |

## 理解控制器和动作

在 MVC 中，C 代表*控制器*。从路由和传入的 URL，ASP.NET Core 知道控制器的名称，因此它将查找一个类，该类装饰有`[Controller]`属性或派生自装饰有该属性的类，例如，Microsoft 提供的名为`ControllerBase`的类，如下代码所示：

```cs
namespace Microsoft.AspNetCore.Mvc
{
  //
  // Summary:
  // A base class for an MVC controller without view support.
  [Controller]
  public abstract class ControllerBase
  {
... 
```

### 理解 ControllerBase 类

如 XML 注释所示，`ControllerBase`不支持视图。它用于创建 Web 服务，正如您将在*第十六章*，*构建和消费 Web 服务*中所见。

`ControllerBase`拥有许多有用的属性，用于处理当前 HTTP 上下文，如下表所示：

| 属性 | 描述 |
| --- | --- |
| `Request` | 仅 HTTP 请求。例如，头部、查询字符串参数、请求主体作为可读取的流、内容类型和长度，以及 Cookie。 |
| `Response` | 仅 HTTP 响应。例如，头部、响应主体作为可写入的流、内容类型和长度、状态码和 Cookie。还有像`OnStarting`和`OnCompleted`这样的委托，您可以将方法挂接到它们上。 |
| `HttpContext` | 当前 HTTP 上下文的所有信息，包括请求和响应、连接信息、服务器上通过中间件启用的功能集合，以及用于认证和授权的`用户`对象。 |

### 理解 Controller 类

Microsoft 提供了另一个名为`Controller`的类，如果您的类确实需要视图支持，它们可以从该类继承，如下代码所示：

```cs
namespace Microsoft.AspNetCore.Mvc
{
  //
  // Summary:
  // A base class for an MVC controller with view support.
  public abstract class Controller : ControllerBase,
    IActionFilter, IFilterMetadata, IAsyncActionFilter, IDisposable
  {
... 
```

`Controller`拥有许多有用的属性，用于处理视图，如下表所示：

| 属性 | 描述 |
| --- | --- |
| `ViewData` | 控制器可以在其中存储键/值对的字典，该字典在视图中可访问。该字典的生命周期仅限于当前请求/响应。 |
| `ViewBag` | 一个动态对象，它封装了`ViewData`，以提供更友好的语法来设置和获取字典值。 |
| `TempData` | 控制器可以在其中存储键/值对的字典，该字典在视图中可访问。该字典的生命周期为当前请求/响应以及同一访问者会话的下一个请求/响应。这对于在初始请求期间存储值、响应重定向并在后续请求中读取存储的值非常有用。 |

`Controller` 有许多与视图工作相关的有用方法，如下表所示：

| 属性 | 描述 |
| --- | --- |
| `视图` | 执行一个视图后返回`ViewResult`，该视图渲染完整的响应，例如，一个动态生成的网页。视图可以通过约定或指定字符串名称来选择。可以将模型传递给视图。 |
| `PartialView` | 执行视图后返回`PartialViewResult`，该视图是完整响应的一部分，例如，动态生成的 HTML 块。视图可以通过约定或指定字符串名称来选择。可以将模型传递给视图。 |
| `ViewComponent` | 执行组件后返回`ViewComponentResult`，该组件动态生成 HTML。组件必须通过指定其类型或名称来选择。可以传递一个对象作为参数。 |
| `Json` | 返回包含 JSON 序列化对象的`JsonResult`。这对于实现 MVC 控制器的一部分简单 Web API 非常有用，该控制器主要返回供人类查看的 HTML。 |

### 理解控制器的职责

控制器的职责如下：

+   识别控制器需要在类构造函数中处于有效状态并正常运行的服务。

+   使用动作名称来识别要执行的方法。

+   从 HTTP 请求中提取参数。

+   使用参数获取构建视图模型所需的任何额外数据，并将其传递给客户端的适当视图。例如，如果客户端是 Web 浏览器，则渲染 HTML 的视图最为合适。其他客户端可能更喜欢替代渲染方式，如 PDF 文件或 Excel 文件等文档格式，或 JSON 或 XML 等数据格式。

+   将视图的结果作为具有适当状态码的 HTTP 响应返回给客户端。

让我们回顾用于生成主页、隐私和错误页面的控制器：

1.  展开`Controllers`文件夹

1.  打开名为`HomeController.cs`的文件

1.  注意，如下列代码所示：

    +   导入了额外的命名空间，我已添加注释以显示它们所需的类型。

    +   声明一个私有只读字段，用于存储在构造函数中设置的`HomeController`的日志记录器引用。

    +   所有三个动作方法都调用名为`View`的方法，并将结果作为`IActionResult`接口返回给客户端。

    +   `Error`动作方法将其视图模型与用于跟踪的请求 ID 一起传递到其视图中。错误响应将不会被缓存：

    ```cs
    using Microsoft.AspNetCore.Mvc; // Controller, IActionResult
    using Northwind.Mvc.Models; // ErrorViewModel
    using System.Diagnostics; // Activity
    namespace Northwind.Mvc.Controllers;
    public class HomeController : Controller
    {
      private readonly ILogger<HomeController> _logger;
      public HomeController(ILogger<HomeController> logger)
      {
        _logger = logger;
      }
      public IActionResult Index()
      {
        return View();
      }
      public IActionResult Privacy()
      {
        return View();
      }
      [ResponseCache(Duration = 0,
        Location = ResponseCacheLocation.None, NoStore = true)]
      public IActionResult Error()
      {
        return View(new ErrorViewModel { RequestId = 
          Activity.Current?.Id ?? HttpContext.TraceIdentifier });
      }
    } 
    ```

如果访问者导航到路径`/`或`/Home`，则相当于`/Home/Index`，因为这些是默认路由中控制器和动作的默认名称。

## 理解视图搜索路径约定

`Index`和`Privacy`方法在实现上相同，但它们返回不同的网页。这是因为**约定**。对`View`方法的调用在不同的路径中查找 Razor 文件以生成网页。

让我们故意破坏一个页面名称，以便我们可以看到默认搜索的路径：

1.  在`Northwind.Mvc`项目中，展开`Views`文件夹，然后展开`Home`文件夹。

1.  将`Privacy.cshtml`文件重命名为`Privacy2.cshtml`。

1.  启动网站。

1.  启动 Chrome，导航到`https://localhost:5001/`，点击**隐私**，并注意搜索视图以渲染网页的路径（包括 MVC 视图和 Razor 页面的`Shared`文件夹），如*图 15.3*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_03.png)

    图 15.3：显示视图默认搜索路径的异常

1.  关闭 Chrome 并关闭 Web 服务器。

1.  将`Privacy2.cshtml`文件重命名为`Privacy.cshtml`。

您现在已经看到了视图搜索路径约定，如下列列表所示：

+   特定的 Razor 视图：`/Views/{controller}/{action}.cshtml`

+   共享 Razor 视图：`/Views/Shared/{action}.cshtml`

+   共享 Razor 页面：`/Pages/Shared/{action}.cshtml`

## 理解日志记录

您刚刚看到，一些错误被捕获并写入控制台。您可以使用记录器以相同的方式向控制台写入消息。

1.  在`Controllers`文件夹中的`HomeController.cs`文件里，在`Index`方法中，添加语句以使用记录器向控制台写入不同级别的消息，如下列代码所示：

    ```cs
    _logger.LogError("This is a serious error (not really!)");
    _logger.LogWarning("This is your first warning!");
    _logger.LogWarning("Second warning!");
    _logger.LogInformation("I am in the Index method of the HomeController."); 
    ```

1.  启动`Northwind.Mvc`网站项目。

1.  启动 Web 浏览器并导航到网站的主页。

1.  在命令提示符或终端中，注意消息，如下列输出所示：

    ```cs
    fail: Northwind.Mvc.Controllers.HomeController[0]
          This is a serious error (not really!)
    warn: Northwind.Mvc.Controllers.HomeController[0]
          This is your first warning!
    warn: Northwind.Mvc.Controllers.HomeController[0]
          Second warning!
    info: Northwind.Mvc.Controllers.HomeController[0]
          I am in the Index method of the HomeController. 
    ```

1.  关闭 Chrome 并关闭 Web 服务器。

## 理解过滤器

当您需要向多个控制器和动作添加某些功能时，您可以使用或定义自己的过滤器，这些过滤器作为属性类实现。

过滤器可以应用于以下级别：

+   通过在动作方法上装饰属性，在动作级别进行设置。这只会影响该动作方法。

+   通过在控制器类上装饰属性，在控制器级别进行设置。这将影响控制器的所有方法。

+   通过将属性类型添加到`MvcOptions`实例的`Filters`集合中，在全局级别进行设置，该实例可用于在调用`AddControllersWithViews`方法时配置 MVC，如下列代码所示：

    ```cs
    builder.Services.AddControllersWithViews(options =>
      {
        options.Filters.Add(typeof(MyCustomFilter));
      }); 
    ```

### 使用过滤器来保护动作方法

你可能希望确保控制器类中的某个特定动作方法只能由特定安全角色的成员调用。你可以通过在方法上装饰`[Authorize]`属性来实现这一点，如下列表所述：

+   `[Authorize]`：仅允许经过身份验证（非匿名，已登录）的访问者访问此动作方法。

+   `[Authorize(Roles = "Sales,Marketing")]`：仅允许指定角色中的访问者访问此动作方法。

让我们来看一个例子：

1.  在`HomeController.cs`中，导入`Microsoft.AspNetCore.Authorization`命名空间。

1.  给`Privacy`方法添加一个属性，仅允许名为`Administrators`的组/角色中的已登录用户访问，如以下高亮代码所示：

    ```cs
    **[****Authorize(Roles =** **"Administrators"****)****]**
    public IActionResult Privacy() 
    ```

1.  启动网站。

1.  点击**隐私**，注意你将被重定向到登录页面。

1.  输入你的电子邮件和密码。

1.  点击**登录**，注意你被拒绝访问。

1.  关闭 Chrome 并关闭 Web 服务器。

### 启用角色管理和编程创建角色

默认情况下，角色管理在 ASP.NET Core MVC 项目中未启用，因此我们必须首先启用它，然后创建一个控制器，该控制器将编程创建一个`Administrators`角色（如果不存在）并将测试用户分配给该角色：

1.  在`Program.cs`中，在 ASP.NET Core Identity 及其数据库的设置中，添加对`AddRoles`的调用以启用角色管理，如下高亮代码所示：

    ```cs
    services.AddDefaultIdentity<IdentityUser>(
      options => options.SignIn.RequireConfirmedAccount = true)
     **.AddRoles<IdentityRole>()** **// enable role management**
      .AddEntityFrameworkStores<ApplicationDbContext>(); 
    ```

1.  在`Controllers`中，添加一个名为`RolesController.cs`的空控制器类并修改其内容，如下代码所示：

    ```cs
    using Microsoft.AspNetCore.Identity; // RoleManager, UserManager
    using Microsoft.AspNetCore.Mvc; // Controller, IActionResult
    using static System.Console;
    namespace Northwind.Mvc.Controllers;
    public class RolesController : Controller
    {
      private string AdminRole = "Administrators";
      private string UserEmail = "test@example.com";
      private readonly RoleManager<IdentityRole> roleManager;
      private readonly UserManager<IdentityUser> userManager;
      public RolesController(RoleManager<IdentityRole> roleManager,
        UserManager<IdentityUser> userManager)
      {
        this.roleManager = roleManager;
        this.userManager = userManager;
      }
      public async Task<IActionResult> Index()
      {
        if (!(await roleManager.RoleExistsAsync(AdminRole)))
        {
          await roleManager.CreateAsync(new IdentityRole(AdminRole));
        }
        IdentityUser user = await userManager.FindByEmailAsync(UserEmail);
        if (user == null)
        {
          user = new();
          user.UserName = UserEmail;
          user.Email = UserEmail;
          IdentityResult result = await userManager.CreateAsync(
            user, "Pa$$w0rd");
          if (result.Succeeded)
          {
            WriteLine($"User {user.UserName} created successfully.");
          }
          else
          { 
            foreach (IdentityError error in result.Errors)
            {
              WriteLine(error.Description);
            }
          }
        }
        if (!user.EmailConfirmed)
        {
          string token = await userManager
            .GenerateEmailConfirmationTokenAsync(user);
          IdentityResult result = await userManager
            .ConfirmEmailAsync(user, token);
          if (result.Succeeded)
          {
            WriteLine($"User {user.UserName} email confirmed successfully.");
          }
          else
          {
            foreach (IdentityError error in result.Errors)
            {
              WriteLine(error.Description);
            }
          }
        }
        if (!(await userManager.IsInRoleAsync(user, AdminRole)))
        {
          IdentityResult result = await userManager
            .AddToRoleAsync(user, AdminRole);
          if (result.Succeeded)
          {
            WriteLine($"User {user.UserName} added to {AdminRole} successfully.");
          }
          else
          {
            foreach (IdentityError error in result.Errors)
            {
              WriteLine(error.Description);
            }
          }
        }
        return Redirect("/");
      }
    } 
    ```

    注意以下事项：

    +   角色名称和用户电子邮件的两个字段。

    +   构造函数获取并存储已注册用户和角色管理依赖服务。

    +   如果`Administrators`角色不存在，我们使用角色管理器创建它。

    +   我们尝试通过其电子邮件查找测试用户，如果不存在则创建它，然后将用户分配给`Administrators`角色。

    +   由于网站使用 DOI，我们必须生成一个电子邮件确认令牌，并使用它来确认新用户的电子邮件地址。

    +   成功消息和任何错误都会输出到控制台。

    +   你将自动重定向到主页。

1.  启动网站。

1.  点击**隐私**，注意你将被重定向到登录页面。

1.  输入你的电子邮件和密码。（我使用了`mark@example.com`。）

1.  点击**登录**，注意你像之前一样被拒绝访问。

1.  点击**主页**。

1.  在地址栏中，手动输入`roles`作为相对 URL 路径，如下链接所示：`https://localhost:5001/roles`。

1.  查看输出到控制台的成功消息，如下所示：

    ```cs
    User test@example.com created successfully.
    User test@example.com email confirmed successfully.
    User test@example.com added to Administrators successfully. 
    ```

1.  点击**注销**，因为你必须注销并重新登录以加载角色成员资格，这些成员资格是在你已经登录后创建的。

1.  再次尝试访问**隐私**页面，输入新用户程序化创建的电子邮件，例如`test@example.com`，以及他们的密码，然后点击**登录**，您现在应该可以访问了。

1.  关闭 Chrome 并关闭 Web 服务器。

### 使用过滤器缓存响应

为了提高响应时间和可扩展性，您可能希望缓存由操作方法生成的 HTTP 响应，通过使用`[ResponseCache]`属性装饰该方法。

您通过设置参数来控制响应的缓存位置和时长，如下面的列表所示：

+   `时长`：以秒为单位。这设置了以秒为单位的`max-age` HTTP 响应头。常见的选择是一个小时（3600 秒）和一天（86400 秒）。

+   `位置`：`ResponseCacheLocation`值之一，`任何`，`客户端`或`无`。这设置了`缓存控制`HTTP 响应头。

+   `NoStore`：如果`true`，这将忽略`时长`和`位置`，并将缓存控制 HTTP 响应头设置为`no-store`。

让我们看一个例子：

1.  在`HomeController.cs`中，向`Index`方法添加一个属性，以在浏览器或服务器和浏览器之间的任何代理上缓存响应 10 秒，如下面的代码中突出显示的那样：

    ```cs
    **[****ResponseCache(Duration = 10, Location = ResponseCacheLocation.Any)****]**
    public IActionResult Index() 
    ```

1.  在`视图`中，在`主页`中，打开`Index.cshtml`，并添加一个段落以长格式输出当前时间，包括秒，如下面的标记所示：

    ```cs
    <p class="alert alert-primary">@DateTime.Now.ToLongTimeString()</p> 
    ```

1.  启动网站。

1.  注意主页上的时间。

1.  点击**注册**。

1.  点击**主页**并注意主页上的时间相同，因为使用了页面的缓存版本。

1.  点击**注册**。至少等待十秒钟。

1.  点击**主页**并注意时间现已更新。

1.  点击**登录**，输入您的电子邮件和密码，然后点击**登录**。

1.  注意主页上的时间。

1.  点击**隐私**。

1.  点击**主页**并注意页面未被缓存。

1.  查看控制台并注意警告消息，该消息解释说您的缓存已被覆盖，因为访问者已登录，在这种情况下，ASP.NET Core 使用防伪令牌，它们不应被缓存，如下面的输出所示：

    ```cs
    warn: Microsoft.AspNetCore.Antiforgery.DefaultAntiforgery[8]
          The 'Cache-Control' and 'Pragma' headers have been overridden and set to 'no-cache, no-store' and 'no-cache' respectively to prevent caching of this response. Any response that uses antiforgery should not be cached. 
    ```

1.  关闭 Chrome 并关闭 Web 服务器。

### 使用过滤器定义自定义路由

您可能希望为操作方法定义简化路由，而不是使用默认路由。

例如，要显示隐私页面，当前需要以下 URL 路径，该路径指定了控制器和操作：

```cs
https://localhost:5001/home/privacy 
```

我们可以使路由更简单，如下面的链接所示：

```cs
https://localhost:5001/private 
```

让我们看看如何做到这一点：

1.  在`HomeController.cs`中，向`隐私`方法添加一个属性，以定义简化路由，如下面的代码中突出显示的那样：

    ```cs
    **[****Route(****"private"****)****]**
    [Authorize(Roles = "Administrators")]
    public IActionResult Privacy() 
    ```

1.  启动网站。

1.  在地址栏中，输入以下 URL 路径：

    ```cs
    https://localhost:5001/private 
    ```

1.  输入您的电子邮件和密码，点击**登录**，并注意简化路径显示了**隐私**页面。

1.  关闭 Chrome 并关闭 Web 服务器。

## 理解实体和视图模型

MVC 中的 M 代表*模型*。模型代表响应请求所需的数据。常用的模型类型有两种：实体模型和视图模型。

**实体模型**代表数据库中的实体，如 SQL Server 或 SQLite。根据请求，可能需要从数据存储中检索一个或多个实体。实体模型使用类定义，因为它们可能需要更改，然后用于更新底层数据存储。

我们想要在响应请求时展示的所有数据就是**MVC 模型**，有时称为**视图模型**，因为它是一个传递给视图以渲染成 HTML 或 JSON 等响应格式的模型。视图模型应该是不可变的，因此通常使用记录来定义。

例如，以下 HTTP `GET`请求可能意味着浏览器正在请求产品编号为 3 的产品详情页：

[`www.example.com/products/details/3`](http://www.example.com/products/details/3)

控制器需要使用 ID 路由值 3 来检索该产品的实体，并将其传递给一个视图，该视图随后将模型转换为 HTML，以便在浏览器中显示。

设想当用户访问我们的网站时，我们希望向他们展示一个类别轮播、产品列表以及本月我们接待的访问者数量计数。

我们将引用您在*第十三章*，*介绍 C#和.NET 的实际应用*中创建的 Northwind 数据库的 Entity Framework Core 实体数据模型：

1.  在`Northwind.Mvc`项目中，添加对`Northwind.Common.DataContext`的项目引用，无论是 SQLite 还是 SQL Server，如下列标记所示：

    ```cs
    <ItemGroup>
      <!-- change Sqlite to SqlServer if you prefer -->
      <ProjectReference Include=
    "..\Northwind.Common.DataContext.Sqlite\Northwind.Common.DataContext.Sqlite.csproj" />
    </ItemGroup> 
    ```

1.  构建`Northwind.Mvc`项目以编译其依赖项。

1.  如果您正在使用 SQL Server，或者可能想要在 SQL Server 和 SQLite 之间切换，那么在`appsettings.json`中，添加一个使用 SQL Server 的 Northwind 数据库的连接字符串，如下列标记中突出显示的那样：

    ```cs
    {
      "ConnectionStrings": {
        "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=aspnet-Northwind.Mvc-DC9C4FAF-DD84-4FC9-B925-69A61240EDA7;Trusted_Connection=True;MultipleActiveResultSets=true",
    **"NorthwindConnection"****:** **"Server=.;Database=Northwind;Trusted_Connection=True;MultipleActiveResultSets=true"**
      }, 
    ```

1.  在`Program.cs`中，导入用于处理实体模型类型的命名空间，如下列代码所示：

    ```cs
    using Packt.Shared; // AddNorthwindContext extension method 
    ```

1.  在`builder.Build`方法调用之前，添加语句以加载适当的连接字符串，然后注册`Northwind`数据库上下文，如下列代码所示：

    ```cs
    // if you are using SQL Server
    string sqlServerConnection = builder.Configuration
      .GetConnectionString("NorthwindConnection");
    builder.Services.AddNorthwindContext(sqlServerConnection);
    // if you are using SQLite default is ..\Northwind.db
    builder.Services.AddNorthwindContext(); 
    ```

1.  向`Models`文件夹添加一个类文件，并将其命名为`HomeIndexViewModel.cs`。

    **最佳实践**：尽管 MVC 项目模板创建的`ErrorViewModel`类并未遵循此约定，但我建议您为视图模型类采用命名约定`{Controller}{Action}ViewModel`。

1.  修改语句以定义一个记录，该记录具有三个属性，分别用于访问者数量计数以及类别和产品列表，如下列代码所示：

    ```cs
    using Packt.Shared; // Category, Product
    namespace Northwind.Mvc.Models;
    public record HomeIndexViewModel
    (
      int VisitorCount,
      IList<Category> Categories,
      IList<Product> Products
    ); 
    ```

1.  在`HomeController.cs`中，导入`Packt.Shared`命名空间，如下列代码所示：

    ```cs
    using Packt.Shared; // NorthwindContext 
    ```

1.  添加一个字段以存储对`Northwind`实例的引用，并在构造函数中初始化它，如下列代码中突出显示的那样：

    ```cs
    public class HomeController : Controller
    {
      private readonly ILogger<HomeController> _logger;
    **private****readonly** **NorthwindContext db;**
      public HomeController(ILogger<HomeController> logger,
     **NorthwindContext injectedContext****)**
      {
        _logger = logger;
     **db = injectedContext;**
      }
    ... 
    ```

    ASP.NET Core 将使用构造函数参数注入来传递在`Program.cs`中指定的连接字符串的`NorthwindContext`数据库上下文实例。

1.  修改`Index`操作方法中的语句，以创建此方法的视图模型实例，使用`Random`类模拟访客计数，生成 1 到 1000 之间的数字，并使用`Northwind`数据库获取类别和产品列表，然后将模型传递给视图，如下面的代码中突出显示所示：

    ```cs
    [ResponseCache(Duration = 10, Location = ResponseCacheLocation.Any)]
    public IActionResult Index()
    {
      _logger.LogError("This is a serious error (not really!)");
      _logger.LogWarning("This is your first warning!");
      _logger.LogWarning("Second warning!");
      _logger.LogInformation("I am in the Index method of the HomeController.");
     **HomeIndexViewModel model =** **new**
     **(**
     **VisitorCount: (****new** **Random()).Next(****1****,** **1001****),**
     **Categories: db.Categories.ToList(),**
     **Products: db.Products.ToList()**
     **);**
    **return** **View(model);** **// pass model to view**
    } 
    ```

记住视图搜索约定：当在控制器的操作方法中调用`View`方法时，ASP.NET Core MVC 会在`Views`文件夹中查找与当前控制器同名的子文件夹，即`Home`。然后查找与当前操作同名的文件，即`Index.cshtml`。它还会在`Shared`文件夹中搜索与操作方法名匹配的视图，以及在`Pages`文件夹中搜索 Razor 页面。

## 理解视图

MVC 中的 V 代表*视图*。视图的责任是将模型转换为 HTML 或其他格式。

有多种**视图引擎**可用于此目的。默认视图引擎称为**Razor**，它使用`@`符号指示服务器端代码执行。随 ASP.NET Core 2.0 引入的 Razor Pages 功能使用相同的视图引擎，因此可以使用相同的 Razor 语法。

让我们修改主页视图以渲染类别和产品列表：

1.  展开`Views`文件夹，然后展开`Home`文件夹。

1.  打开`Index.cshtml`文件，并注意包裹在`@{ }`中的 C#代码块。这会首先执行，并可用于存储需要传递到共享布局文件的数据，例如网页标题，如下面的代码所示：

    ```cs
    @{
      ViewData["Title"] = "Home Page";
    } 
    ```

1.  注意使用 Bootstrap 进行样式化的`<div>`元素中的静态 HTML 内容。

    **良好实践**：除了定义自己的样式外，还应基于实现响应式设计的通用库（如 Bootstrap）来构建样式。

    与 Razor 页面一样，有一个名为`_ViewStart.cshtml`的文件，由`View`方法执行。它用于设置适用于所有视图的默认值。

    例如，它将所有视图的`Layout`属性设置为共享布局文件，如下面的标记所示：

    ```cs
    @{
      Layout = "_Layout";
    } 
    ```

1.  在`Views`文件夹中，打开`_ViewImports.cshtml`文件，并注意它导入了一些命名空间，然后添加了 ASP.NET Core 标签助手，如下面的代码所示：

    ```cs
    @using Northwind.Mvc 
    @using Northwind.Mvc.Models
    @addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers 
    ```

1.  在`Shared`文件夹中，打开`_Layout.cshtml`文件。

1.  注意标题是从`ViewData`字典中读取的，该字典是在`Index.cshtml`视图中较早设置的，如下面的标记所示：

    ```cs
    <title>@ViewData["Title"] – Northwind.Mvc</title> 
    ```

1.  注意支持 Bootstrap 和站点样式表的链接渲染，其中`~`表示`wwwroot`文件夹，如下面的标记所示：

    ```cs
    <link rel="stylesheet" 
      href="~/lib/bootstrap/dist/css/bootstrap.css" />
    <link rel="stylesheet" href="~/css/site.css" /> 
    ```

1.  注意头部导航栏的渲染，如下面的标记所示：

    ```cs
    <body>
      <header>
        <nav class="navbar ..."> 
    ```

1.  注意渲染一个可折叠的`<div>`，其中包含用于登录的部分视图和超链接，允许用户使用带有`asp-controller`和`asp-action`等属性的 ASP.NET Core 标签助手在页面间导航，如下面的标记所示：

    ```cs
    <div class=
      "navbar-collapse collapse d-sm-inline-flex justify-content-between">
      <ul class="navbar-nav flex-grow-1">
        <li class="nav-item">
          <a class="nav-link text-dark" asp-area=""
            asp-controller="Home" asp-action="Index">Home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link text-dark"
            asp-area="" asp-controller="Home" 
            asp-action="Privacy">Privacy</a>
        </li>
      </ul>
      <partial name="_LoginPartial" />
    </div> 
    ```

    `<a>`元素使用名为`asp-controller`和`asp-action`的标签助手属性来指定链接被点击时将执行的控制器名称和动作名称。如果你想导航到一个 Razor 类库中的功能，比如你在前一章创建的`employees`组件，那么你可以使用`asp-area`来指定功能名称。

1.  注意`<main>`元素内主体的渲染，如下面的标记所示：

    ```cs
    <div class="container">
      <main role="main" class="pb-3">
        @RenderBody()
      </main>
    </div> 
    ```

    `RenderBody`方法注入特定 Razor 视图的内容，例如在共享布局中该点的`Index.cshtml`文件。

1.  注意在页面底部渲染`<script>`元素，这样不会减慢页面显示速度，并且你可以在一个可选定义的名为`scripts`的部分中添加自己的脚本块，如下面的标记所示：

    ```cs
    <script src="img/jquery.min.js"></script>
    <script src="img/bootstrap.bundle.min.js">
    </script>
    <script src="img/site.js" asp-append-version="true"></script> 
    @await RenderSectionAsync("scripts", required: false) 
    ```

当在任何元素（如`<img>`或`<script>`）中与`src`属性一起指定`asp-append-version`并设置为`true`时，将调用 Image Tag Helper（此助手的名称不佳，因为它不仅影响图像！）。

它的工作原理是自动附加一个名为`v`的查询字符串值，该值是从引用的源文件的哈希生成的，如下面的示例生成输出所示：

```cs
<script src="img/site.js? v=Kl_dqr9NVtnMdsM2MUg4qthUnWZm5T1fCEimBPWDNgM"></script> 
```

如果`site.js`文件中的任何一个字节发生变化，其哈希值就会不同，因此如果浏览器或 CDN 正在缓存该脚本文件，则会清除缓存的副本并替换为新版本。

# 定制 ASP.NET Core MVC 网站

现在你已经审查了一个基本 MVC 网站的结构，你将对其进行定制和扩展。你已经为`Northwind`数据库注册了一个 EF Core 模型，接下来的任务是在首页输出一些该数据。

## 定义自定义样式

首页将展示 Northwind 数据库中的 77 种产品列表。为了高效利用空间，我们希望以三列形式显示该列表。为此，我们需要为网站定制样式表：

1.  在`wwwroot\css`文件夹中，打开`site.css`文件。

1.  在文件底部，添加一个新的样式，该样式将应用于具有`product-columns` ID 的元素，如下面的代码所示：

    ```cs
    #product-columns
    {
      column-count: 3;
    } 
    ```

## 设置类别图像

Northwind 数据库包含一个有八个类别的表，但它们没有图像，而网站配上一些色彩丰富的图片会更好看：

1.  在`wwwroot`文件夹中，创建一个名为`images`的文件夹。

1.  在`images`文件夹中，添加八个名为`category1.jpeg`、`category2.jpeg`，以此类推，直到`category8.jpeg`的图像文件。

您可以从本书 GitHub 仓库的以下链接下载图片：[`github.com/markjprice/cs10dotnet6/tree/master/Assets/Categories`](https://github.com/markjprice/cs10dotnet6/tree/master/Assets/Categories)

## 理解 Razor 语法

在我们自定义主页视图之前，让我们回顾一个具有初始 Razor 代码块的示例 Razor 文件，该代码块实例化了一个具有价格和数量的订单，然后在网页上输出订单信息，如下面的标记所示：

```cs
@{
  Order order = new()
  {
    OrderId = 123,
    Product = "Sushi",
    Price = 8.49M,
    Quantity = 3
  };
}
<div>Your order for @order.Quantity of @order.Product has a total cost of $@ order.Price * @order.Quantity</div> 
```

前面的 Razor 文件将产生以下错误的输出：

```cs
Your order for 3 of Sushi has a total cost of $8.49 * 3 
```

尽管 Razor 标记可以使用`@object.property`语法包含任何单一属性的值，但您应该用括号将表达式括起来，如下面的标记所示：

```cs
<div>Your order for @order.Quantity of @order.Product has a total cost of $@ (order.Price * order.Quantity)</div> 
```

前面的 Razor 表达式将产生以下正确的输出：

```cs
Your order for 3 of Sushi has a total cost of $25.47 
```

## 定义类型化视图

为了提高编写视图时的 IntelliSense，您可以使用顶部的`@model`指令定义视图可以预期的类型：

1.  在`Views\Home`文件夹中，打开`Index.cshtml`。

1.  在文件顶部，添加一个语句，将模型类型设置为使用`HomeIndexViewModel`，如下面的代码所示：

    ```cs
    @model HomeIndexViewModel 
    ```

    现在，每当我们在本视图中键入`Model`时，您的代码编辑器将知道模型的正确类型，并为其提供 IntelliSense。

    在视图中输入代码时，请记住以下事项：

    +   声明模型的类型，使用`@model`（小写 m）。

    +   与模型实例交互，使用`@Model`（大写 M）。

    让我们继续自定义主页视图。

1.  在初始的 Razor 代码块中，添加一个声明当前项的`string`变量的语句，并在现有的`<div>`元素下添加新的标记，以轮播形式输出类别，并以无序列表形式输出产品，如下面的标记所示：

    ```cs
    @using Packt.Shared
    @model HomeIndexViewModel 
    @{
      ViewData["Title"] = "Home Page";
      string currentItem = "";
    }
    <div class="text-center">
      <h1 class="display-4">Welcome</h1>
      <p>Learn about <a href="https://docs.microsoft.com/aspnet/core">building Web apps with ASP.NET Core</a>.</p>
      <p class="alert alert-primary">@DateTime.Now.ToLongTimeString()</p>
    </div>
    @if (Model is not null)
    {
    <div id="categories" class="carousel slide" data-ride="carousel" 
         data-interval="3000" data-keyboard="true">
      <ol class="carousel-indicators">
      @for (int c = 0; c < Model.Categories.Count; c++)
      {
        if (c == 0)
        {
          currentItem = "active";
        }
        else
        {
          currentItem = "";
        }
        <li data-target="#categories" data-slide-to="@c"  
            class="@currentItem"></li>
      }
      </ol>
      <div class="carousel-inner">
      @for (int c = 0; c < Model.Categories.Count; c++)
      {
        if (c == 0)
        {
          currentItem = "active";
        }
        else
        {
          currentItem = "";
        }
        <div class="carousel-item @currentItem">
          <img class="d-block w-100" src=   
            "~/images/category@(Model.Categories[c].CategoryId).jpeg"  
            alt="@Model.Categories[c].CategoryName" />
          <div class="carousel-caption d-none d-md-block">
            <h2>@Model.Categories[c].CategoryName</h2>
            <h3>@Model.Categories[c].Description</h3>
            <p>
              <a class="btn btn-primary"  
                href="/category/@Model.Categories[c].CategoryId">View</a>
            </p>
          </div>
        </div>
      }
      </div>
      <a class="carousel-control-prev" href="#categories" 
        role="button" data-slide="prev">
        <span class="carousel-control-prev-icon" 
          aria-hidden="true"></span>
        <span class="sr-only">Previous</span>
      </a>
      <a class="carousel-control-next" href="#categories" 
        role="button" data-slide="next">
        <span class="carousel-control-next-icon" aria-hidden="true"></span>
        <span class="sr-only">Next</span>
      </a>
    </div>
    }
    <div class="row">
      <div class="col-md-12">
        <h1>Northwind</h1>
        <p class="lead">
          We have had @Model?.VisitorCount visitors this month.
        </p>
        @if (Model is not null)
        {
        <h2>Products</h2>
        <div id="product-columns">
          <ul>
          @foreach (Product p in @Model.Products)
          {
            <li>
              <a asp-controller="Home"
                 asp-action="ProductDetail"
                 asp-route-id="@p.ProductId">
                @p.ProductName costs 
    @(p.UnitPrice is null ? "zero" : p.UnitPrice.Value.ToString("C"))
              </a>
            </li>
          }
          </ul>
        </div>
        }
      </div>
    </div> 
    ```

在审查前面的 Razor 标记时，请注意以下几点：

+   很容易将静态 HTML 元素（如`<ul>`和`<li>`）与 C#代码混合，以输出类别轮播和产品名称列表。

+   具有`id`属性为`product-columns`的`<div>`元素将使用我们之前定义的自定义样式，因此该元素中的所有内容将以三列显示。

+   每个类别的`<img>`元素使用括号包围 Razor 表达式，以确保编译器不会将`.jpeg`作为表达式的一部分，如下面的标记所示：`"~/images/category@(Model.Categories[c].CategoryID).jpeg"`

+   产品链接的`<a>`元素使用标签助手生成 URL 路径。点击这些超链接将由`HomeController`及其`ProductDetail`动作方法处理。此动作方法目前尚不存在，但您将在本章稍后添加。产品 ID 作为名为`id`的路由段传递，如下面的 Ipoh Coffee 的 URL 路径所示：`https://localhost:5001/Home/ProductDetail/43`。

## 审查自定义主页

让我们看看自定义首页的结果：

1.  启动`Northwind.Mvc`网站项目。

1.  注意首页有一个旋转的轮播显示类别，随机数量的访客，以及三列中的产品列表，如*图 15.4*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_04.png)

    图 15.4：更新后的 Northwind MVC 网站首页

    目前，点击任何类别或产品链接都会给出**404 Not Found**错误，因此让我们看看如何实现使用传递的参数来查看产品或类别详细信息的页面。

1.  关闭 Chrome 并关闭 Web 服务器。

## 使用路由值传递参数

传递简单参数的一种方法是使用默认路由中定义的`id`段：

1.  在`HomeController`类中，添加一个名为`ProductDetail`的操作方法，如下面的代码所示：

    ```cs
    public IActionResult ProductDetail(int? id)
    {
      if (!id.HasValue)
      {
        return BadRequest("You must pass a product ID in the route, for example, /Home/ProductDetail/21");
      }
      Product? model = db.Products
        .SingleOrDefault(p => p.ProductId == id);
      if (model == null)
      {
        return NotFound($"ProductId {id} not found.");
      }
      return View(model); // pass model to view and then return result
    } 
    ```

    注意以下事项：

    +   此方法利用 ASP.NET Core 的一个特性，称为**模型绑定**，自动将路由中传递的`id`与方法中名为`id`的参数匹配。

    +   在方法内部，我们检查`id`是否没有值，如果是，我们调用`BadRequest`方法返回`400`状态码和一条自定义消息，解释正确的 URL 路径格式。

    +   否则，我们可以连接到数据库并尝试使用`id`值检索产品。

    +   如果我们找到产品，我们将其传递给视图；否则，我们调用`NotFound`方法返回`404`状态码和一条自定义消息，解释数据库中未找到该 ID 的产品。

1.  在`Views/Home`文件夹中，添加一个名为`ProductDetail.cshtml`的新文件。

1.  修改内容，如下面的标记所示：

    ```cs
    @model Packt.Shared.Product 
    @{
      ViewData["Title"] = "Product Detail - " + Model.ProductName;
    }
    <h2>Product Detail</h2>
    <hr />
    <div>
      <dl class="dl-horizontal">
        <dt>Product Id</dt>
        <dd>@Model.ProductId</dd>
        <dt>Product Name</dt>
        <dd>@Model.ProductName</dd>
        <dt>Category Id</dt>
        <dd>@Model.CategoryId</dd>
        <dt>Unit Price</dt>
        <dd>@Model.UnitPrice.Value.ToString("C")</dd>
        <dt>Units In Stock</dt>
        <dd>@Model.UnitsInStock</dd>
      </dl>
    </div> 
    ```

1.  启动`Northwind.Mvc`项目。

1.  当首页显示产品列表时，点击其中一个，例如，第二个产品，**张**。

1.  注意浏览器地址栏中的 URL 路径，浏览器标签中显示的页面标题，以及产品详情页，如*图 15.5*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_05.png)

    图 15.5：张的产品详情页

1.  查看**开发者工具**。

1.  在 Chrome 的地址栏中编辑 URL，请求一个不存在的产品 ID，例如 99，并注意 404 Not Found 状态码和自定义错误响应。

## 更详细地理解模型绑定器

模型绑定器功能强大，默认的绑定器为您做了很多工作。默认路由确定要实例化的控制器类和要调用的操作方法后，如果该方法有参数，则这些参数需要设置值。

模型绑定器通过查找 HTTP 请求中传递的参数值来实现这一点，这些参数值可以是以下任何类型的参数：

+   **路由参数**，如我们在上一节中使用的`id`，如以下 URL 路径所示：`/Home/ProductDetail/2`

+   **查询字符串参数**，如下面的 URL 路径所示：`/Home/ProductDetail?id=2`

+   **表单参数**，如下面的标记所示：

    ```cs
    <form action="post" action="/Home/ProductDetail">
      <input type="text" name="id" value="2" />
      <input type="submit" />
    </form> 
    ```

模型绑定器可以填充几乎任何类型：

+   简单类型，如`int`、`string`、`DateTime`和`bool`。

+   由`class`、`record`或`struct`定义的复杂类型。

+   集合类型，如数组和列表。

让我们创建一个略显人为的示例，以说明使用默认模型绑定器可以实现什么：

1.  在`Models`文件夹中，添加一个名为`Thing.cs`的新文件。

1.  修改内容以定义一个具有两个属性的类，一个名为`Id`的可空整数和一个名为`Color`的字符串，如下面的代码所示：

    ```cs
    namespace Northwind.Mvc.Models;
    public class Thing
    {
      public int? Id { get; set; }
      public string? Color { get; set; }
    } 
    ```

1.  在`HomeController`中，添加两个新的动作方法，一个用于显示带有表单的页面，另一个用于使用你的新模型类型显示带有参数的事物，如下面的代码所示：

    ```cs
    public IActionResult ModelBinding()
    {
      return View(); // the page with a form to submit
    }
    public IActionResult ModelBinding(Thing thing)
    {
      return View(thing); // show the model bound thing
    } 
    ```

1.  在`Views\Home`文件夹中，添加一个名为`ModelBinding.cshtml`的新文件。

1.  修改其内容，如下面的标记所示：

    ```cs
    @model Thing 
    @{
      ViewData["Title"] = "Model Binding Demo";
    }
    <h1>@ViewData["Title"]</h1>
    <div>
      Enter values for your thing in the following form:
    </div>
    <form method="POST" action="/home/modelbinding?id=3">
      <input name="color" value="Red" />
      <input type="submit" />
    </form>
    @if (Model != null)
    {
    <h2>Submitted Thing</h2>
    <hr />
    <div>
      <dl class="dl-horizontal">
        <dt>Model.Id</dt>
        <dd>@Model.Id</dd>
        <dt>Model.Color</dt>
        <dd>@Model.Color</dd>
      </dl>
    </div>
    } 
    ```

1.  在`Views/Home`中，打开`Index.cshtml`，并在第一个`<div>`中，添加一个指向模型绑定页面的新段落链接，如下面的标记所示：

    ```cs
    <p><a asp-action="ModelBinding" asp-controller="Home">Binding</a></p> 
    ```

1.  启动网站。

1.  在首页上，点击**绑定**。

1.  注意*图 15.6*中所示的关于模糊匹配的未处理异常：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_06.png)

    图 15.6：未处理的模糊动作方法匹配异常

1.  关闭 Chrome 并关闭 Web 服务器。

### 消除动作方法的歧义

尽管 C#编译器可以通过注意到签名不同来区分这两种方法，但从 HTTP 请求的路由角度来看，这两种方法都是潜在的匹配。我们需要一种 HTTP 特定的方法来消除动作方法的歧义。

我们可以通过为动作创建不同的名称或指定一个方法应该用于特定的 HTTP 动词，如`GET`、`POST`或`DELETE`来做到这一点。这就是我们将解决问题的方式：

1.  在`HomeController`中，装饰第二个`ModelBinding`动作方法，以指示它应该用于处理 HTTP `POST`请求，即当表单提交时，如下面的代码中突出显示的那样：

    ```cs
    **[****HttpPost****]**
    public IActionResult ModelBinding(Thing thing) 
    ```

    另一个`ModelBinding`动作方法将隐式用于所有其他类型的 HTTP 请求，如`GET`、`PUT`、`DELETE`等。

1.  启动网站。

1.  在首页上，点击**绑定**。

1.  点击**提交**按钮，并注意`Id`属性的值是从查询字符串参数设置的，而颜色属性的值是从表单参数设置的，如*图 15.7*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_07.png)

    图 15.7：模型绑定演示页面

1.  关闭 Chrome 并关闭 Web 服务器。

### 传递路由参数

现在我们将使用路由参数设置属性：

1.  修改表单的动作，以传递值`2`作为路由参数，如下面的标记中突出显示的那样：

    ```cs
    <form method="POST" action="/home/modelbinding**/2**?id=3"> 
    ```

1.  启动网站。

1.  在首页上，点击**绑定**。

1.  点击**提交**按钮，并注意`Id`属性的值是从路由参数设置的，而`Color`属性的值是从表单参数设置的。

1.  关闭 Chrome 并关闭 Web 服务器。

### 传递表单参数

现在我们将使用表单参数设置属性：

1.  修改表单的操作，将值 1 作为表单参数传递，如下面的标记中突出显示的那样：

    ```cs
    <form method="POST" action="/home/modelbinding/2?id=3">
     **<input name=****"id"****value****=****"1"** **/>**
      <input name="color" value="Red" />
      <input type="submit" />
    </form> 
    ```

1.  启动网站。

1.  在主页上，点击**绑定**。

1.  点击**提交**按钮，并注意`Id`和`Color`属性的值都是从表单参数设置的。

**最佳实践**：如果你有多个同名参数，请记住表单参数的优先级最高，而查询字符串参数的优先级最低，用于自动模型绑定。

## 验证模型

模型绑定过程可能会导致错误，例如，如果模型被装饰了验证规则，可能会发生数据类型转换或验证错误。已绑定的数据以及任何绑定或验证错误都存储在`ControllerBase.ModelState`中。

让我们通过应用一些验证规则到绑定的模型上，然后在视图中显示无效数据消息，来探索我们能用模型状态做什么：

1.  在`Models`文件夹中，打开`Thing.cs`。

1.  导入`System.ComponentModel.DataAnnotations`命名空间。

1.  用验证属性装饰`Id`属性，以限制允许的数字范围为 1 到 10，并确保访问者提供颜色，并添加一个新的`Email`属性，使用正则表达式进行验证，如下面的代码中突出显示的那样：

    ```cs
    public class Thing
    {
     **[****Range(1, 10)****]**
      public int? Id { get; set; }
     **[****Required****]**
      public string? Color { get; set; }
     **[****EmailAddress****]**
    **public****string****? Email {** **get****;** **set****; }**
    } 
    ```

1.  在`Models`文件夹中，添加一个名为`HomeModelBindingViewModel.cs`的新文件。

1.  修改其内容以定义一个记录，该记录具有存储绑定模型的属性、指示存在错误的标志以及错误消息序列，如下面的代码所示：

    ```cs
    namespace Northwind.Mvc.Models;
    public record HomeModelBindingViewModel
    (
      Thing Thing,
      bool HasErrors, 
      IEnumerable<string> ValidationErrors
    ); 
    ```

1.  在`HomeController`中，在处理 HTTP `POST`的`ModelBinding`方法中，注释掉之前将事物传递给视图的语句，而是添加语句来创建视图模型的实例。验证模型并存储错误消息数组，然后将视图模型传递给视图，如下面的代码中突出显示的那样：

    ```cs
    [HttpPost]
    public IActionResult ModelBinding(Thing thing)
    {
     **HomeModelBindingViewModel model =** **new****(**
     **thing,**
     **!ModelState.IsValid,** 
     **ModelState.Values**
     **.SelectMany(state => state.Errors)**
     **.Select(error => error.ErrorMessage)**
     **);**
    **return** **View(model);**
    } 
    ```

1.  在`Views\Home`中，打开`ModelBinding.cshtml`。

1.  修改模型类型声明以使用视图模型类，如下面的标记所示：

    ```cs
    @model Northwind.Mvc.Models.HomeModelBindingViewModel 
    ```

1.  添加一个`<div>`来显示任何模型验证错误，并更改事物的属性输出，因为视图模型已更改，如下面的标记中突出显示的那样：

    ```cs
    <form method="POST" action="/home/modelbinding/2?id=3">
      <input name="id" value="1" />
      <input name="color" value="Red" />
      <input name="email" value="test@example.com" />
      <input type="submit" />
    </form>
    @if (Model != null)
    {
      <h2>Submitted Thing</h2>
      <hr />
      <div>
        <dl class="dl-horizontal">
          <dt>Model**.Thing**.Id</dt>	
          <dd>@Model**.Thing**.Id</dd>	
          <dt>Model**.Thing**.Color</dt>
          <dd>@Model**.Thing**.Color</dd>
    **<****dt****>****Model.Thing.Email****</****dt****>**
    **<****dd****>****@Model.Thing.Email****</****dd****>**
        </dl>
      </div>
      @if (Model.HasErrors)
      {
        <div>
          @foreach(string errorMessage in Model.ValidationErrors)
          {
            <div class="alert alert-danger" role="alert">@errorMessage</div>
          }
        </div>
      }
    } 
    ```

1.  启动网站。

1.  在主页上，点击**绑定**。

1.  点击**提交**按钮，并注意`1`、`红色`和`test@example.com`是有效值。

1.  输入一个`Id`为`13`，清空颜色文本框，删除电子邮件地址中的`@`，点击**提交**按钮，并注意错误消息，如图*15.8*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_08.png)

    图 15.8：带有字段验证的模型绑定演示页面

1.  关闭 Chrome 并关闭 Web 服务器。

**最佳实践**：微软在实现 `EmailAddress` 验证属性时使用了哪种正则表达式？请在以下链接中查找答案：[`github.com/microsoft/referencesource/blob/5697c29004a34d80acdaf5742d7e699022c64ecd/System.ComponentModel.DataAnnotations/DataAnnotations/EmailAddressAttribute.cs#L54`](https://github.com/microsoft/referencesource/blob/5697c29004a34d80acdaf5742d7e699022c64ecd/System.ComponentModel.DataAnnotations/DataAnnotations/EmailAddressAttribute.cs#L54)

## 理解视图助手方法

在为 ASP.NET Core MVC 创建视图时，你可以使用 `Html` 对象及其方法生成标记。

以下是一些有用的方法：

+   `ActionLink`：使用此方法生成包含指向指定控制器和动作的 URL 路径的 `<a>` 锚点元素。例如，`Html.ActionLink(linkText: "绑定", actionName: "模型绑定", controllerName: "主页")` 将生成 `<a href="/主页/模型绑定">绑定</a>`。你也可以使用锚点标签助手实现相同效果：`<a asp-action="模型绑定" asp-controller="主页">绑定</a>`。

+   `AntiForgeryToken`：在 `<form>` 内部使用此方法插入包含防伪令牌的 `<hidden>` 元素，该令牌将在表单提交时进行验证。

+   `Display` 和 `DisplayFor`：使用此方法根据当前模型使用显示模板为相关表达式生成 HTML 标记。对于 .NET 类型，有内置的显示模板，也可以在 `DisplayTemplates` 文件夹中创建自定义模板。在区分大小写的文件系统上，文件夹名称是区分大小写的。

+   `DisplayForModel`：使用此方法为整个模型生成 HTML 标记，而非单个表达式。

+   `Editor` 和 `EditorFor`：使用此方法根据当前模型使用编辑模板为相关表达式生成 HTML 标记。对于 .NET 类型，有使用 `<label>` 和 `<input>` 元素的内置编辑模板，也可以在 `EditorTemplates` 文件夹中创建自定义模板。在区分大小写的文件系统上，文件夹名称是区分大小写的。

+   `EditorForModel`：使用此方法为整个模型生成 HTML 标记，而非单个表达式。

+   `Encode`：使用此方法将对象或字符串安全地编码为 HTML。例如，字符串值 `"<script>"` 将被编码为 `"&lt;script&gt;"`。通常不需要这样做，因为 Razor 的 `@` 符号默认对字符串值进行编码。

+   `Raw`：使用此方法渲染字符串值，*不*进行 HTML 编码。

+   `PartialAsync` 和 `RenderPartialAsync`：使用这些方法为部分视图生成 HTML 标记。你可以选择性地传递模型和视图数据。

让我们看一个例子：

1.  在 `Views/Home` 中，打开 `ModelBinding.cshtml`。

1.  修改 `Email` 属性的渲染方式，使用 `DisplayFor`，如下所示：

    ```cs
    <dd>@Html.DisplayFor(model => model.Thing.Email)</dd> 
    ```

1.  启动网站。

1.  点击 **绑定**。

1.  点击 **提交**。

1.  注意电子邮件地址是一个可点击的超链接，而不仅仅是文本。

1.  关闭 Chrome 并关闭 Web 服务器。

1.  在`Models/Thing.cs`中，在`Email`属性上方注释掉`[EmailAddress]`属性。

1.  启动网站。

1.  点击**绑定**。

1.  点击**提交**。

1.  注意，电子邮件地址只是文本。

1.  关闭 Chrome 并关闭网络服务器。

1.  在`Models/Thing.cs`中，取消注释`[EmailAddress]`属性。

正是通过在`Email`属性上使用`[EmailAddress]`验证属性进行装饰，并使用`DisplayFor`呈现它，通知 ASP.NET Core 将该值视为电子邮件地址，从而将其渲染为可点击的链接。

# 查询数据库并使用显示模板

我们来创建一个新的动作方法，它可以接收查询字符串参数，并利用该参数查询 Northwind 数据库中价格高于指定值的产品。

在前面的示例中，我们定义了一个视图模型，其中包含视图中需要呈现的每个值的属性。在这个例子中，将有两个值：一个产品列表和访客输入的价格。为了避免必须为视图模型定义一个类或记录，我们将产品列表作为模型传递，并将最高价格存储在`ViewData`集合中。

我们来实现这个功能：

1.  在`HomeController`中，导入`Microsoft.EntityFrameworkCore`命名空间。我们需要这个来添加`Include`扩展方法，以便我们可以包含相关实体，正如你在*第十章*，*使用 Entity Framework Core 处理数据*中所学。

1.  添加一个新的动作方法，如下所示：

    ```cs
    public IActionResult ProductsThatCostMoreThan(decimal? price)
    {
      if (!price.HasValue)
      {
        return BadRequest("You must pass a product price in the query string, for example, /Home/ProductsThatCostMoreThan?price=50");
      }
      IEnumerable<Product> model = db.Products
        .Include(p => p.Category)
        .Include(p => p.Supplier)
        .Where(p => p.UnitPrice > price);
      if (!model.Any())
      {
        return NotFound(
          $"No products cost more than {price:C}.");
      }
      ViewData["MaxPrice"] = price.Value.ToString("C");
      return View(model); // pass model to view
    } 
    ```

1.  在`Views/Home`文件夹中，添加一个名为`ProductsThatCostMoreThan.cshtml`的新文件。

1.  修改内容，如下所示：

    ```cs
    @using Packt.Shared
    @model IEnumerable<Product> 
    @{
      string title =
        "Products That Cost More Than " + ViewData["MaxPrice"]; 
      ViewData["Title"] = title;
    }
    <h2>@title</h2>
    @if (Model is null)
    {
      <div>No products found.</div>
    }
    else
    {
      <table class="table">
        <thead>
          <tr>
            <th>Category Name</th>
            <th>Supplier's Company Name</th>
            <th>Product Name</th>
            <th>Unit Price</th>
            <th>Units In Stock</th>
          </tr>
        </thead>
        <tbody>
        @foreach (Product p in Model)
        {
          <tr>
            <td>
              @Html.DisplayFor(modelItem => p.Category.CategoryName)
            </td>
            <td>
              @Html.DisplayFor(modelItem => p.Supplier.CompanyName)
            </td>
            <td>
              @Html.DisplayFor(modelItem => p.ProductName)
            </td>
            <td>
              @Html.DisplayFor(modelItem => p.UnitPrice)
            </td>
            <td>
              @Html.DisplayFor(modelItem => p.UnitsInStock)
            </td>
          </tr>
        }
        <tbody>
      </table>
    } 
    ```

1.  在`Views/Home`文件夹中，打开`Index.cshtml`。

1.  在访客计数下方、**产品**标题及其产品列表上方添加以下表单元素。这将提供一个供用户输入价格的表单。用户点击**提交**后，将调用动作方法，显示价格高于输入值的产品：

    ```cs
    <h3>Query products by price</h3>
    <form asp-action="ProductsThatCostMoreThan" method="GET">
      <input name="price" placeholder="Enter a product price" />
      <input type="submit" />
    </form> 
    ```

1.  启动网站。

1.  在主页上，在表单中输入一个价格，例如`50`，然后点击**提交**。

1.  注意你输入的价格高于该价格的产品表，如图 15.9 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_16_09.png)

    图 15.9：价格超过£50 的产品筛选列表

1.  关闭 Chrome 并关闭网络服务器。

# 使用异步任务提高可扩展性

在构建桌面或移动应用时，可以使用多个任务（及其底层线程）来提高响应性，因为当一个线程忙于任务时，另一个线程可以处理与用户的交互。

任务及其线程在服务器端也非常有用，尤其是对于处理文件或从商店或可能需要一段时间响应的网络服务请求数据的网站。但对于 CPU 密集型的复杂计算，它们是有害的，因此应将这些计算同步处理，如同常规操作。

当 HTTP 请求到达 Web 服务器时，会从其池中分配一个线程来处理该请求。但如果该线程必须等待资源，则它被阻止处理任何更多的传入请求。如果网站收到的并发请求数量超过了其线程池中的线程数量，那么其中一些请求将以服务器超时错误**503 服务不可用**响应。

被锁定的线程并没有做有用的工作。它们*本可以*处理其他请求之一，但前提是我们需要在网站中实现异步代码。

每当线程等待它需要的资源时，它可以返回到线程池并处理不同的传入请求，从而提高网站的可扩展性，即增加它可以处理的同时请求的数量。

为什么不直接拥有一个更大的线程池？在现代操作系统中，池中的每个线程都有一个 1 MB 的堆栈。异步方法使用的内存较少。它还消除了在池中创建新线程的需要，这需要时间。新线程添加到池中的速率通常是每两秒一个，这与在异步线程之间切换相比，这是一个非常长的时间。

**最佳实践**：使你的控制器动作方法异步化。

## 使控制器动作方法异步化

将现有动作方法异步化很容易：

1.  修改`Index`动作方法以使其异步，返回一个任务，并等待调用异步方法以获取类别和产品，如下列代码中突出显示的那样：

    ```cs
    public **async** **Task<IActionResult>** Index()
    {
      HomeIndexViewModel model = new
      (
        VisitorCount = (new Random()).Next(1, 1001),
        Categories = **await** db.Categories.ToList**Async**(),
        Products = **await** db.Products.ToList**Async**()
      );
      return View(model); // pass model to view
    } 
    ```

1.  以类似方式修改`ProductDetail`动作方法，如下列代码中突出显示的那样：

    ```cs
    public **async** **Task<IActionResult>** ProductDetail(int? id)
    {
      if (!id.HasValue)
      {
        return BadRequest("You must pass a product ID in the route, for example,
    /Home/ProductDetail/21");
      }
      Product? model = **await** db.Products
        .SingleOrDefault**Async**(p => p.ProductId == id);
      if (model == null)
      {
        return NotFound($"ProductId {id} not found.");
      }
      return View(model); // pass model to view and then return result
    } 
    ```

1.  启动网站并注意网站的功能相同，但相信它现在将更好地扩展。

1.  关闭 Chrome 并关闭 Web 服务器。

# 实践与探索

通过回答一些问题来测试你的知识和理解，进行一些实践练习，并深入研究本章的主题。

## 练习 15.1 – 测试你的知识

回答以下问题：

1.  当在`Views`文件夹中创建具有特殊名称的文件`_ViewStart`和`_ViewImports`时，它们有什么作用？

1.  默认 ASP.NET Core MVC 路由中定义的三个段是什么，它们代表什么，哪些是可选的？

1.  默认模型绑定器的作用是什么，它可以处理哪些数据类型？

1.  在共享布局文件如`_Layout.cshtml`中，如何输出当前视图的内容？

1.  在共享布局文件如`_Layout.cshtml`中，如何输出当前视图可以提供内容的节，以及视图如何为该节提供内容？

1.  在控制器的动作方法内部调用`View`方法时，按照约定会搜索哪些路径以查找视图？

1.  如何指示访问者的浏览器将响应缓存 24 小时？

1.  即使你不是自己创建任何 Razor 页面，为什么你可能还会启用它们？

1.  如何识别可以作为控制器的类？ASP.NET Core MVC 是如何做到的？

1.  ASP.NET Core MVC 在哪些方面使得测试网站变得更加容易？

## 练习 15.2 – 实践实现 MVC，通过实现类别详细页面

`Northwind.Mvc` 项目有一个主页，显示类别，但当点击 `查看` 按钮时，网站返回 `404 未找到` 错误，例如，对于以下 URL：

`https://localhost:5001/category/1`

通过添加显示类别详细页面的功能来扩展 `Northwind.Mvc` 项目。

## 练习 15.3 – 通过理解和实现异步操作方法来实践提高可扩展性

几年前，Stephen Cleary 为 MSDN 杂志撰写了一篇精彩文章，阐述了在 ASP.NET 中实现异步操作方法的扩展性优势。这些原则同样适用于 ASP.NET Core，甚至更为重要，因为与文章中描述的旧版 ASP.NET 不同，ASP.NET Core 支持异步过滤器和其他组件。

请阅读以下链接中的文章：

[`docs.microsoft.com/en-us/archive/msdn-magazine/2014/october/async-programming-introduction-to-async-await-on-asp-net`](https://docs.microsoft.com/en-us/archive/msdn-magazine/2014/october/async-programming-introduction-to-async-await-on-asp-net)

## 练习 15.4 – 实践单元测试 MVC 控制器

控制器是网站业务逻辑运行的位置，因此使用单元测试来验证该逻辑的正确性非常重要，正如您在*第四章*，*编写、调试和测试函数*中所学。

为 `HomeController` 编写一些单元测试。

**良好实践**：您可以在以下链接中了解更多关于如何单元测试控制器的信息：[`docs.microsoft.com/en-us/aspnet/core/mvc/controllers/testing`](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/testing)

## 练习 15.5 – 探索主题

使用以下页面上的链接来了解更多关于本章涵盖的主题：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-15---building-websites-using-the-model-view-controller-pattern`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-15---building-websites-using-the-model-view-controller-pattern)

# 总结

在本章中，您学习了如何通过注册和注入依赖服务（如数据库上下文和记录器）来构建易于单元测试的大型复杂网站，并使用 ASP.NET Core MVC 使团队编程管理变得更加容易。您了解了配置、认证、路由、模型、视图和控制器。

在下一章中，您将学习如何构建和消费使用 HTTP 作为通信层的 Web 服务。


# 第十六章：构建和消费 Web 服务

本章是关于学习如何使用 ASP.NET Core Web API 构建 Web 服务（即 HTTP 或 REST 服务）以及使用 HTTP 客户端消费 Web 服务，这些客户端可以是任何类型的.NET 应用，包括网站、移动或桌面应用。

本章要求您具备在*第十章*，*使用 Entity Framework Core 处理数据*，以及*第十三章*至*第十五章*中关于 C#和.NET 的实际应用以及使用 ASP.NET Core 构建网站的知识和技能。

本章我们将涵盖以下主题：

+   使用 ASP.NET Core Web API 构建 Web 服务

+   文档化和测试 Web 服务

+   使用 HTTP 客户端消费 Web 服务

+   为 Web 服务实现高级功能

+   使用最小 API 构建 Web 服务

# 使用 ASP.NET Core Web API 构建 Web 服务

在我们构建现代 Web 服务之前，需要先介绍一些背景知识，为本章设定上下文。

## 理解 Web 服务缩略语

尽管 HTTP 最初设计用于请求和响应 HTML 及其他供人类查看的资源，但它也非常适合构建服务。

罗伊·菲尔丁在其博士论文中描述**表述性状态转移**(**REST**)架构风格时指出，HTTP 标准适合构建服务，因为它定义了以下内容：

+   唯一标识资源的 URI，如`https://localhost:5001/api/products/23`。

+   对这些资源执行常见任务的方法，如`GET`、`POST`、`PUT`和`DELETE`。

+   请求和响应中交换的内容媒体类型协商能力，如 XML 和 JSON。内容协商发生在客户端指定类似`Accept: application/xml,*/*;q=0.8`的请求头时。ASP.NET Core Web API 默认的响应格式是 JSON，这意味着其中一个响应头会是`Content-Type: application/json; charset=utf-8`。

**Web 服务**采用 HTTP 通信标准，因此有时被称为 HTTP 或 RESTful 服务。本章讨论的就是 HTTP 或 RESTful 服务。

Web 服务也可指实现部分**WS-*标准**的**简单对象访问协议**(**SOAP**)服务。这些标准使不同系统上实现的客户端和服务能相互通信。WS-*标准最初由 IBM 定义，微软等其他公司也参与了制定。

### 理解 Windows Communication Foundation (WCF)

.NET Framework 3.0 及更高版本包含名为**Windows Communication Foundation**(**WCF**)的**远程过程调用**(**RPC**)技术。RPC 技术使一个系统上的代码能通过网络在另一系统上执行代码。

WCF 使开发者能轻松创建服务，包括实现 WS-*标准的 SOAP 服务。后来它也支持构建 Web/HTTP/REST 风格的服务，但如果仅需要这些，它显得过于复杂。

如果你有现有的 WCF 服务并希望将它们迁移到现代.NET，那么有一个开源项目在 2021 年 2 月发布了其首个**正式发布版**（**GA**）。你可以在以下链接中了解更多信息：

[`corewcf.github.io/blog/2021/02/19/corewcf-ga-release`](https://corewcf.github.io/blog/2021/02/19/corewcf-ga-release)

### 替代 WCF 的方案

微软推荐的 WCF 替代方案是**gRPC**。gRPC 是一种现代的跨平台开源 RPC 框架，由谷歌创建（非官方地，“g”代表 gRPC）。你将在*第十八章*，*构建和消费专业化服务*中了解更多关于 gRPC 的信息。

## 理解 Web API 的 HTTP 请求和响应

HTTP 定义了标准的请求类型和标准代码来指示响应类型。大多数这些类型和代码可用于实现 Web API 服务。

最常见的请求类型是`GET`，用于检索由唯一路径标识的资源，并附带如可接受的媒体类型等额外选项，这些选项作为请求头设置，如下例所示：

```cs
GET /path/to/resource
Accept: application/json 
```

常见响应包括成功和多种失败类型，如下表所示：

| 状态码 | 描述 |
| --- | --- |
| `200 成功` | 路径正确形成，资源成功找到，序列化为可接受的媒体类型，然后返回在响应体中。响应头指定`Content-Type`、`Content-Length`和`Content-Encoding`，例如 GZIP。 |
| `301 永久移动` | 随着时间的推移，Web 服务可能会更改其资源模型，包括用于标识现有资源的路径。Web 服务可以通过返回此状态码和一个名为`Location`的响应头来指示新路径，该响应头包含新路径。 |
| `302 找到` | 类似于`301`。 |
| `304 未修改` | 如果请求包含`If-Modified-Since`头，则 Web 服务可以响应此状态码。响应体为空，因为客户端应使用其缓存的资源副本。 |
| `400 错误请求` | 请求无效，例如，它使用了一个整数 ID 的产品路径，但 ID 值缺失。 |
| `401 未授权` | 请求有效，资源已找到，但客户端未提供凭证或无权访问该资源。重新认证可能会启用访问，例如，通过添加或更改`Authorization`请求头。 |
| `403 禁止访问` | 请求有效，资源已找到，但客户端无权访问该资源。重新认证也无法解决问题。 |
| `404 未找到` | 请求有效，但资源未找到。如果稍后重复请求，资源可能会被找到。若要表明资源将永远无法找到，返回`410 已删除`。 |
| `406 不可接受` | 如果请求具有仅列出网络服务不支持的媒体类型的`Accept`头。例如，如果客户端请求 JSON 但网络服务只能返回 XML。 |
| `451 因法律原因不可用` | 在美国托管的网站可能会为来自欧洲的请求返回此状态，以避免不得不遵守《通用数据保护条例》（GDPR）。该数字的选择是对小说《华氏 451 度》的引用，其中书籍被禁止和焚烧。 |
| `500 服务器错误` | 请求有效，但在处理请求时服务器端出现问题。稍后再试可能有效。 |
| `503 服务不可用` | 网络服务正忙，无法处理请求。稍后再试可能有效。 |

其他常见的 HTTP 请求类型包括`POST`、`PUT`、`PATCH`或`DELETE`，用于创建、修改或删除资源。

要创建新资源，您可能会发出带有包含新资源的正文的`POST`请求，如下所示：

```cs
POST /path/to/resource
Content-Length: 123
Content-Type: application/json 
```

要创建新资源或更新现有资源，您可能会发出带有包含现有资源全新版本的正文的`PUT`请求，如果资源不存在，则创建它，如果存在，则替换它（有时称为**upsert**操作），如下所示：

```cs
PUT /path/to/resource
Content-Length: 123
Content-Type: application/json 
```

要更有效地更新现有资源，您可能会发出带有包含仅需要更改的属性的对象的正文的`PATCH`请求，如下所示：

```cs
PATCH /path/to/resource
Content-Length: 123
Content-Type: application/json 
```

要删除现有资源，您可能会发出`DELETE`请求，如下所示：

```cs
DELETE /path/to/resource 
```

除了上述表格中针对`GET`请求的响应外，所有创建、修改或删除资源的请求类型都有额外的可能的常见响应，如下表所示：

| 状态码 | 描述 |
| --- | --- |
| `201 已创建` | 新资源已成功创建，响应头名为`Location`包含其路径，响应正文包含新创建的资源。立即`GET`资源应返回`200`。 |
| `202 已接受` | 新资源无法立即创建，因此请求被排队等待稍后处理，立即`GET`资源可能会返回`404`。正文可以包含指向某种状态检查器或资源可用时间估计的资源。 |
| `204 无内容` | 通常用于响应`DELETE`请求，因为在删除后在正文中返回资源通常没有意义！有时用于响应`POST`、`PUT`或`PATCH`请求，如果客户端不需要确认请求是否正确处理。 |
| `405 方法不允许` | 当请求使用的方法不被支持时返回。例如，设计为只读的网络服务可能明确禁止`PUT`、`DELETE`等。 |
| `415 Unsupported Media Type` | 当请求体中的资源使用 Web 服务无法处理的媒体类型时返回。例如，如果主体包含 XML 格式的资源，但 Web 服务只能处理 JSON。 |

## 创建 ASP.NET Core Web API 项目

我们将构建一个 Web 服务，该服务提供了一种使用 ASP.NET Core 在 Northwind 数据库中处理数据的方法，以便数据可以被任何能够发出 HTTP 请求并在任何平台上接收 HTTP 响应的客户端应用程序使用：

1.  使用您喜欢的代码编辑器添加新项目，如以下列表所定义：

    1.  项目模板：**ASP.NET Core Web API** / `webapi`

    1.  工作区/解决方案文件和文件夹：`PracticalApps`

    1.  项目文件和文件夹：`Northwind.WebApi`

    1.  其他 Visual Studio 选项：**身份验证类型**：无，**为 HTTPS 配置**：已选中，**启用 Docker**：已清除，**启用 OpenAPI 支持**：已选中。

1.  在 Visual Studio Code 中，选择`Northwind.WebApi`作为活动的 OmniSharp 项目。

1.  构建`Northwind.WebApi`项目。

1.  在`Controllers`文件夹中，打开并审查`WeatherForecastController.cs`，如下所示：

    ```cs
    using Microsoft.AspNetCore.Mvc;
    namespace Northwind.WebApi.Controllers;
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
      private static readonly string[] Summaries = new[]
      {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild",
        "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
      };
      private readonly ILogger<WeatherForecastController> _logger;
      public WeatherForecastController(
        ILogger<WeatherForecastController> logger)
      {
        _logger = logger;
      }
      [HttpGet]
      public IEnumerable<WeatherForecast> Get()
      {
        return Enumerable.Range(1, 5).Select(index =>
          new WeatherForecast
          {
            Date = DateTime.Now.AddDays(index),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
          })
          .ToArray();
      }
    } 
    ```

    在审查前面的代码时，请注意以下几点：

    +   控制器类`Controller`继承自`ControllerBase`。这比 MVC 中使用的`Controller`类更简单，因为它没有像`View`这样的方法，通过将视图模型传递给 Razor 文件来生成 HTML 响应。

    +   `[Route]`属性为客户端注册了`/weatherforecast`相对 URL，用于发出将由该控制器处理的 HTTP 请求。例如，对`https://localhost:5001/weatherforecast/`的 HTTP 请求将由该控制器处理。一些开发人员喜欢在控制器名称前加上`api/`，这是一种区分混合项目中 MVC 和 Web API 的约定。如果使用`[controller]`，如所示，它使用类名中`Controller`之前的字符，在本例中为`WeatherForecast`，或者您可以简单地输入一个不同的名称，不带方括号，例如`[Route("api/forecast")]`。

    +   `[ApiController]`属性是在 ASP.NET Core 2.1 中引入的，它为控制器启用了 REST 特定的行为，例如对于无效模型的自动 HTTP `400`响应，如本章后面将看到的。

    +   `[HttpGet]`属性将`Controller`类中的`Get`方法注册为响应 HTTP `GET`请求，其实现使用共享的`Random`对象返回一个`WeatherForecast`对象数组，其中包含未来五天的随机温度和摘要，如`Bracing`或`Balmy`。

1.  添加第二个`Get`方法，该方法允许调用指定预测应提前多少天，通过实现以下内容：

    +   在原始方法上方添加注释，以显示其响应的操作方法和 URL 路径。

    +   添加一个带有整数参数`days`的新方法。

    +   将原始`Get`方法实现代码语句剪切并粘贴到新的`Get`方法中。

    +   修改新方法以创建一个整数`IEnumerable`，其上限为请求的天数，并修改原始`Get`方法以调用新`Get`方法并传递值`5`。

你的方法应如以下代码中突出显示的那样：

```cs
**// GET /weatherforecast**
[HttpGet]
public IEnumerable<WeatherForecast> Get() **// original method**
{
  **return** **Get(****5****);** **// five day forecast**
}
**// GET /weatherforecast/7**
**[****HttpGet(****"{days:int}"****)****]**
**public** **IEnumerable<WeatherForecast>** **Get****(****int** **days****)** **// new method**
{
**return** **Enumerable.Range(****1****, days).Select(index =>**
    new WeatherForecast
    {
      Date = DateTime.Now.AddDays(index),
      TemperatureC = Random.Shared.Next(-20, 55),
      Summary = Summaries[Random.Shared.Next(Summaries.Length)]
    })
    .ToArray();
} 
```

在`[HttpGet]`属性中，注意路由格式模式`{days:int}`，它将`days`参数约束为`int`值。

## 审查 Web 服务的功能

现在，我们将测试 Web 服务的功能：

1.  如果你使用的是 Visual Studio，在**属性**中，打开`launchSettings.json`文件，并注意默认情况下，它将启动浏览器并导航至`/swagger`相对 URL 路径，如下所示突出显示：

    ```cs
    "profiles": {
      "Northwind.WebApi": {
        "commandName": "Project",
        "dotnetRunMessages": "true",
    **"launchBrowser"****:** **true****,**
    **"launchUrl"****:** **"swagger"****,**
        "applicationUrl": "https://localhost:5001;http://localhost:5000",
        "environmentVariables": {
          "ASPNETCORE_ENVIRONMENT": "Development"
        }
      }, 
    ```

1.  修改名为`Northwind.WebApi`的配置文件，将`launchBrowser`设置为`false`。

1.  对于`applicationUrl`，将随机端口号更改为`HTTP`的`5000`和`HTTPS`的`5001`。

1.  启动 Web 服务项目。

1.  启动 Chrome。

1.  导航至`https://localhost:5001/`，注意你会收到一个`404`状态码响应，因为我们尚未启用静态文件，也没有`index.html`文件，或者配置了路由的 MVC 控制器。记住，此项目并非设计为人机交互界面，因此对于 Web 服务而言，这是预期行为。

    GitHub 上的解决方案配置为使用端口`5002`，因为在本书后面我们将更改其配置。

1.  在 Chrome 中，显示**开发者工具**。

1.  导航至`https://localhost:5001/weatherforecast`，注意 Web API 服务应返回一个包含五个随机天气预报对象的 JSON 文档数组，如图*16.1*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_01.png)

    图 16.1：来自天气预报 Web 服务的请求与响应

1.  关闭**开发者工具**。

1.  导航至`https://localhost:5001/weatherforecast/14`，并注意请求两周天气预报时的响应，如图*16.2*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_02.png)

    图 16.2：两周天气预报的 JSON 文档

1.  关闭 Chrome 并关闭 Web 服务器。

## 为 Northwind 数据库创建 Web 服务

与 MVC 控制器不同，Web API 控制器不会调用 Razor 视图以返回 HTML 响应供网站访问者在浏览器中查看。相反，它们使用与发起 HTTP 请求的客户端应用程序的内容协商，在 HTTP 响应中返回 XML、JSON 或 X-WWW-FORM-URLENCODED 等格式的数据。

客户端应用程序必须随后将数据从协商格式反序列化。现代 Web 服务最常用的格式是**JavaScript 对象表示法**（**JSON**），因为它紧凑且在构建使用 Angular、React 和 Vue 等客户端技术的**单页应用程序**（**SPAs**）时，能与浏览器中的 JavaScript 原生工作。

我们将引用你在*第十三章*，*C#与.NET 实用应用入门*中创建的 Northwind 数据库的 Entity Framework Core 实体数据模型：

1.  在`Northwind.WebApi`项目中，为 SQLite 或 SQL Server 添加对`Northwind.Common.DataContext`的项目引用，如下所示：

    ```cs
    <ItemGroup>
      <!-- change Sqlite to SqlServer if you prefer -->
      <ProjectReference Include=
    "..\Northwind.Common.DataContext.Sqlite\Northwind.Common.DataContext.Sqlite.csproj" />
    </ItemGroup> 
    ```

1.  构建项目并修复代码中的任何编译错误。

1.  打开`Program.cs`并导入用于处理 Web 媒体格式化程序和共享 Packt 类的命名空间，如下所示：

    ```cs
    using Microsoft.AspNetCore.Mvc.Formatters;
    using Packt.Shared; // AddNorthwindContext extension method
    using static System.Console; 
    ```

1.  在调用`AddControllers`之前，添加一条语句以注册`Northwind`数据库上下文类（它将根据您在项目文件中引用的数据库提供程序使用 SQLite 或 SQL Server），如下所示：

    ```cs
    // Add services to the container.
    builder.Services.AddNorthwindContext(); 
    ```

1.  在调用`AddControllers`时，添加一个 lambda 块，其中包含将默认输出格式化程序的名称和支持的媒体类型写入控制台的语句，然后添加 XML 序列化程序格式化程序，如下所示：

    ```cs
    builder.Services.AddControllers(options =>
    {
      WriteLine("Default output formatters:");
      foreach (IOutputFormatter formatter in options.OutputFormatters)
      {
        OutputFormatter? mediaFormatter = formatter as OutputFormatter;
        if (mediaFormatter == null)
        {
          WriteLine($"  {formatter.GetType().Name}");
        }
        else // OutputFormatter class has SupportedMediaTypes
        {
          WriteLine("  {0}, Media types: {1}",
            arg0: mediaFormatter.GetType().Name,
            arg1: string.Join(", ",
              mediaFormatter.SupportedMediaTypes));
        }
      }
    })
    .AddXmlDataContractSerializerFormatters()
    .AddXmlSerializerFormatters(); 
    ```

1.  启动 Web 服务。

1.  在命令提示符或终端中，请注意有四种默认的输出格式化程序，包括将`null`值转换为`204 No Content`的程序，以及支持纯文本、字节流和 JSON 响应的程序，如下所示：

    ```cs
    Default output formatters: 
      HttpNoContentOutputFormatter
      StringOutputFormatter, Media types: text/plain
      StreamOutputFormatter
      SystemTextJsonOutputFormatter, Media types: application/json, text/json, application/*+json 
    ```

1.  关闭 Web 服务器。

## 为实体创建数据仓库

定义和实现提供 CRUD 操作的数据仓库是良好的实践。CRUD 缩写包括以下操作：

+   C 代表创建

+   R 代表检索（或读取）

+   U 代表更新

+   D 代表删除

我们将为 Northwind 中的`Customers`表创建一个数据仓库。该表中只有 91 个客户，因此我们将整个表的副本存储在内存中，以提高读取客户记录时的可扩展性和性能。

**最佳实践**：在实际的 Web 服务中，应使用分布式缓存，如 Redis，这是一个开源的数据结构存储，可用作高性能、高可用性的数据库、缓存或消息代理。

我们将遵循现代最佳实践，使仓库 API 异步。它将通过构造函数参数注入由`Controller`类实例化，因此会为每个 HTTP 请求创建一个新实例：

1.  在`Northwind.WebApi`项目中，创建一个名为`Repositories`的文件夹。

1.  向`Repositories`文件夹添加两个类文件，名为`ICustomerRepository.cs`和`CustomerRepository.cs`。

1.  `ICustomerRepository`接口将定义五个方法，如下所示：

    ```cs
    using Packt.Shared; // Customer
    namespace Northwind.WebApi.Repositories;
    public interface ICustomerRepository
    {
      Task<Customer?> CreateAsync(Customer c);
      Task<IEnumerable<Customer>> RetrieveAllAsync();
      Task<Customer?> RetrieveAsync(string id);
      Task<Customer?> UpdateAsync(string id, Customer c);
      Task<bool?> DeleteAsync(string id);
    } 
    ```

1.  `CustomerRepository`类将实现这五个方法，记住，使用`await`的方法必须标记为`async`，如下所示：

    ```cs
    using Microsoft.EntityFrameworkCore.ChangeTracking; // EntityEntry<T>
    using Packt.Shared; // Customer
    using System.Collections.Concurrent; // ConcurrentDictionary
    namespace Northwind.WebApi.Repositories;
    public class CustomerRepository : ICustomerRepository
    {
      // use a static thread-safe dictionary field to cache the customers
      private static ConcurrentDictionary
        <string, Customer>? customersCache;
      // use an instance data context field because it should not be
      // cached due to their internal caching
      private NorthwindContext db;
      public CustomerRepository(NorthwindContext injectedContext)
      {
        db = injectedContext;
        // pre-load customers from database as a normal
        // Dictionary with CustomerId as the key,
        // then convert to a thread-safe ConcurrentDictionary
        if (customersCache is null)
        {
          customersCache = new ConcurrentDictionary<string, Customer>(
            db.Customers.ToDictionary(c => c.CustomerId));
        }
      }
      public async Task<Customer?> CreateAsync(Customer c)
      {
        // normalize CustomerId into uppercase
        c.CustomerId = c.CustomerId.ToUpper();
        // add to database using EF Core
        EntityEntry<Customer> added = await db.Customers.AddAsync(c);
        int affected = await db.SaveChangesAsync();
        if (affected == 1)
        {
          if (customersCache is null) return c;
          // if the customer is new, add it to cache, else
          // call UpdateCache method
          return customersCache.AddOrUpdate(c.CustomerId, c, UpdateCache);
        }
        else
        {
          return null;
        }
      }
      public Task<IEnumerable<Customer>> RetrieveAllAsync()
      {
        // for performance, get from cache
        return Task.FromResult(customersCache is null 
            ? Enumerable.Empty<Customer>() : customersCache.Values);
      }
      public Task<Customer?> RetrieveAsync(string id)
      {
        // for performance, get from cache
        id = id.ToUpper();
        if (customersCache is null) return null!;
        customersCache.TryGetValue(id, out Customer? c);
        return Task.FromResult(c);
      }
      private Customer UpdateCache(string id, Customer c)
      {
        Customer? old;
        if (customersCache is not null)
        {
          if (customersCache.TryGetValue(id, out old))
          {
            if (customersCache.TryUpdate(id, c, old))
            {
              return c;
            }
          }
        }
        return null!;
      }
      public async Task<Customer?> UpdateAsync(string id, Customer c)
      {
        // normalize customer Id
        id = id.ToUpper();
        c.CustomerId = c.CustomerId.ToUpper();
        // update in database
        db.Customers.Update(c);
        int affected = await db.SaveChangesAsync();
        if (affected == 1)
        {
          // update in cache
          return UpdateCache(id, c);
        }
        return null;
      }
      public async Task<bool?> DeleteAsync(string id)
      {
        id = id.ToUpper();
        // remove from database
        Customer? c = db.Customers.Find(id);
        if (c is null) return null;
        db.Customers.Remove(c);
        int affected = await db.SaveChangesAsync();
        if (affected == 1)
        {
          if (customersCache is null) return null;
          // remove from cache
          return customersCache.TryRemove(id, out c);
        }
        else
        {
          return null;
        }
      }
    } 
    ```

## 实现 Web API 控制器

对于返回数据而非 HTML 的控制器，有一些有用的属性和方法。

使用 MVC 控制器时，像`/home/index`这样的路由告诉我们控制器类名和操作方法名，例如`HomeController`类和`Index`操作方法。

使用 Web API 控制器，如`/weatherforecast`的路由仅告诉我们控制器类名，例如`WeatherForecastController`。为了确定要执行的操作方法名称，我们必须将 HTTP 方法（如`GET`和`POST`）映射到控制器类中的方法。

您应该使用以下属性装饰控制器方法，以指示它们将响应的 HTTP 方法：

+   `[HttpGet]`，`[HttpHead]`：这些操作方法响应`GET`或`HEAD`请求以检索资源，并返回资源及其响应头或仅返回响应头。

+   `[HttpPost]`：此操作方法响应`POST`请求以创建新资源或执行服务定义的其他操作。

+   `[HttpPut]`，`[HttpPatch]`：这些操作方法响应`PUT`或`PATCH`请求以更新现有资源，无论是替换还是更新其属性的子集。

+   `[HttpDelete]`：此操作方法响应`DELETE`请求以删除资源。

+   `[HttpOptions]`：此操作方法响应`OPTIONS`请求。

### 理解操作方法返回类型

操作方法可以返回.NET 类型，如单个`string`值、由`class`、`record`或`struct`定义的复杂对象，或复杂对象的集合。ASP.NET Core Web API 会将它们序列化为 HTTP 请求`Accept`头中设置的请求数据格式，例如，如果已注册合适的序列化器，则为 JSON。

为了更精细地控制响应，有一些辅助方法返回围绕.NET 类型的`ActionResult`包装器。

如果操作方法可能基于输入或其他变量返回不同的返回类型，则应声明其返回类型为`IActionResult`。如果操作方法将仅返回单个类型但具有不同的状态代码，则应声明其返回类型为`ActionResult<T>`。

**最佳实践**：使用`[ProducesResponseType]`属性装饰操作方法，以指示客户端应在响应中预期的所有已知类型和 HTTP 状态代码。此信息随后可以公开，以说明客户端应如何与您的 Web 服务交互。将其视为正式文档的一部分。本章后面，您将学习如何安装代码分析器，以便在您未按此方式装饰操作方法时给出警告。

例如，根据 id 参数获取产品的操作方法将装饰有三个属性——一个表示它响应`GET`请求并具有 id 参数，另外两个表示成功时和客户端提供无效产品 ID 时的处理方式，如下面的代码所示：

```cs
[HttpGet("{id}")]
[ProducesResponseType(200, Type = typeof(Product))] 
[ProducesResponseType(404)]
public IActionResult Get(string id) 
```

`ControllerBase`类具有方法，使其易于返回不同的响应，如下表所示：

| 方法 | 描述 |
| --- | --- |
| `Ok` | 返回`200`状态码和一个转换为客户端首选格式的资源，如 JSON 或 XML。常用于响应`GET`请求。 |
| `CreatedAtRoute` | 返回一个`201`状态码和到新资源的路径。通常用于响应`POST`请求以快速创建资源。 |
| `Accepted` | 返回一个`202`状态码以指示请求正在处理但尚未完成。通常用于响应`POST`、`PUT`、`PATCH`或`DELETE`请求，这些请求触发了一个需要很长时间才能完成的背景进程。 |
| `NoContentResult` | 返回一个`204`状态码和一个空的响应主体。通常用于响应`PUT`、`PATCH`或`DELETE`请求，当响应不需要包含受影响的资源时。 |
| `BadRequest` | 返回一个`400`状态码和一个可选的详细信息消息字符串。 |
| `NotFound` | 返回一个`404`状态码和一个自动填充的`ProblemDetails`主体（需要 2.2 或更高版本的兼容性版本）。 |

## 配置客户仓库和 Web API 控制器

现在您将配置仓库，以便它可以从 Web API 控制器内部调用。

当 Web 服务启动时，您将为仓库注册一个作用域依赖服务实现，然后使用构造函数参数注入在新 Web API 控制器中获取它，以便与客户工作。

为了展示使用路由区分 MVC 和 Web API 控制器的示例，我们将使用客户控制器的常见`/api`URL 前缀约定：

1.  打开`Program.cs`并导入`Northwind.WebApi.Repositories`命名空间。

1.  在调用`Build`方法之前添加一个语句，该语句将注册`CustomerRepository`以在运行时作为作用域依赖使用，如下所示高亮显示的代码：

    ```cs
    **builder.Services.AddScoped<ICustomerRepository, CustomerRepository>();**
    var app = builder.Build(); 
    ```

    **最佳实践**：我们的仓库使用一个注册为作用域依赖的数据库上下文。您只能在其他作用域依赖内部使用作用域依赖，因此我们不能将仓库注册为单例。您可以在以下链接了解更多信息：[`docs.microsoft.com/en-us/dotnet/core/extensions/dependency-injection#scoped`](https://docs.microsoft.com/en-us/dotnet/core/extensions/dependency-injection#scoped)

1.  在`Controllers`文件夹中，添加一个名为`CustomersController.cs`的新类。

1.  在`CustomersController`类文件中，添加语句以定义一个 Web API 控制器类以与客户工作，如下所示的代码：

    ```cs
    using Microsoft.AspNetCore.Mvc; // [Route], [ApiController], ControllerBase
    using Packt.Shared; // Customer
    using Northwind.WebApi.Repositories; // ICustomerRepository
    namespace Northwind.WebApi.Controllers;
    // base address: api/customers
    [Route("api/[controller]")]
    [ApiController]
    public class CustomersController : ControllerBase
    {
      private readonly ICustomerRepository repo;
      // constructor injects repository registered in Startup
      public CustomersController(ICustomerRepository repo)
      {
        this.repo = repo;
      }
      // GET: api/customers
      // GET: api/customers/?country=[country]
      // this will always return a list of customers (but it might be empty)
      [HttpGet]
      [ProducesResponseType(200, Type = typeof(IEnumerable<Customer>))]
      public async Task<IEnumerable<Customer>> GetCustomers(string? country)
      {
        if (string.IsNullOrWhiteSpace(country))
        {
          return await repo.RetrieveAllAsync();
        }
        else
        {
          return (await repo.RetrieveAllAsync())
            .Where(customer => customer.Country == country);
        }
      }
      // GET: api/customers/[id]
      [HttpGet("{id}", Name = nameof(GetCustomer))] // named route
      [ProducesResponseType(200, Type = typeof(Customer))]
      [ProducesResponseType(404)]
      public async Task<IActionResult> GetCustomer(string id)
      {
        Customer? c = await repo.RetrieveAsync(id);
        if (c == null)
        {
          return NotFound(); // 404 Resource not found
        }
        return Ok(c); // 200 OK with customer in body
      }
      // POST: api/customers
      // BODY: Customer (JSON, XML)
      [HttpPost]
      [ProducesResponseType(201, Type = typeof(Customer))]
      [ProducesResponseType(400)]
      public async Task<IActionResult> Create([FromBody] Customer c)
      {
        if (c == null)
        {
          return BadRequest(); // 400 Bad request
        }
        Customer? addedCustomer = await repo.CreateAsync(c);
        if (addedCustomer == null)
        {
          return BadRequest("Repository failed to create customer.");
        }
        else
        {
          return CreatedAtRoute( // 201 Created
            routeName: nameof(GetCustomer),
            routeValues: new { id = addedCustomer.CustomerId.ToLower() },
            value: addedCustomer);
        }
      }
      // PUT: api/customers/[id]
      // BODY: Customer (JSON, XML)
      [HttpPut("{id}")]
      [ProducesResponseType(204)]
      [ProducesResponseType(400)]
      [ProducesResponseType(404)]
      public async Task<IActionResult> Update(
        string id, [FromBody] Customer c)
      {
        id = id.ToUpper();
        c.CustomerId = c.CustomerId.ToUpper();
        if (c == null || c.CustomerId != id)
        {
          return BadRequest(); // 400 Bad request
        }
        Customer? existing = await repo.RetrieveAsync(id);
        if (existing == null)
        {
          return NotFound(); // 404 Resource not found
        }
        await repo.UpdateAsync(id, c);
        return new NoContentResult(); // 204 No content
      }
      // DELETE: api/customers/[id]
      [HttpDelete("{id}")]
      [ProducesResponseType(204)]
      [ProducesResponseType(400)]
      [ProducesResponseType(404)]
      public async Task<IActionResult> Delete(string id)
      {
        Customer? existing = await repo.RetrieveAsync(id);
        if (existing == null)
        {
          return NotFound(); // 404 Resource not found
        }
        bool? deleted = await repo.DeleteAsync(id);
        if (deleted.HasValue && deleted.Value) // short circuit AND
        {
          return new NoContentResult(); // 204 No content
        }
        else
        {
          return BadRequest( // 400 Bad request
            $"Customer {id} was found but failed to delete.");
        }
      }
    } 
    ```

在审查此 Web API 控制器类时，请注意以下内容：

+   `Controller`类注册了一个以`api/`开头的路由，并包含控制器的名称，即`api/customers`。

+   构造函数使用依赖注入来获取注册的仓库以与客户工作。

+   有五个操作方法来执行对客户的 CRUD 操作——两个`GET`方法（获取所有客户或一个客户），`POST`（创建），`PUT`（更新）和`DELETE`。

+   方法`GetCustomers`可以接受一个`string`类型的参数，该参数为国名。若该参数缺失，则返回所有客户信息。若存在，则用于按国家筛选客户。

+   `GetCustomer`方法有一个显式命名的路由`GetCustomer`，以便在插入新客户后用于生成 URL。

+   `Create`和`Update`方法都使用`[FromBody]`装饰`customer`参数，以告知模型绑定器从`POST`请求体中填充其值。

+   `Create`方法返回的响应使用了`GetCustomer`路由，以便客户端知道将来如何获取新创建的资源。我们正在将两个方法匹配起来，以创建并获取客户。

+   `Create`和`Update`方法无需检查 HTTP 请求体中传递的客户模型状态，并在模型无效时返回包含模型验证错误详情的`400 Bad Request`，因为控制器装饰有`[ApiController]`，它会为你执行此操作。

当服务接收到 HTTP 请求时，它将创建一个`Controller`类实例，调用相应的动作方法，以客户端偏好的格式返回响应，并释放控制器使用的资源，包括仓库及其数据上下文。

## 指定问题详情

ASP.NET Core 2.1 及更高版本新增了一项特性，即实现了指定问题详情的 Web 标准。

在启用了 ASP.NET Core 2.2 或更高版本兼容性的项目中，使用`[ApiController]`装饰的 Web API 控制器中，返回`IActionResult`且返回客户端错误状态码（即`4xx`）的动作方法，将自动在响应体中包含`ProblemDetails`类的序列化实例。

如果你想自行控制，那么你可以创建一个`ProblemDetails`实例，并包含额外信息。

让我们模拟一个需要向客户端返回自定义数据的错误请求：

1.  在`Delete`方法的实现顶部，添加语句检查`id`是否匹配字符串值`"bad"`，如果是，则返回一个自定义的问题详情对象，如下所示：

    ```cs
    // take control of problem details
    if (id == "bad")
    {
      ProblemDetails problemDetails = new()
      {
        Status = StatusCodes.Status400BadRequest,
        Type = "https://localhost:5001/customers/failed-to-delete",
        Title = $"Customer ID {id} found but failed to delete.",
        Detail = "More details like Company Name, Country and so on.",
        Instance = HttpContext.Request.Path
      };
      return BadRequest(problemDetails); // 400 Bad Request
    } 
    ```

1.  你稍后将测试此功能。

## 控制 XML 序列化

在`Program.cs`文件中，我们添加了`XmlSerializer`，以便我们的 Web API 服务在客户端请求时，既能返回 JSON 也能返回 XML。

然而，`XmlSerializer`无法序列化接口，而我们的实体类使用`ICollection<T>`来定义相关子实体，这会在运行时导致警告，例如对于`Customer`类及其`Orders`属性，如下输出所示：

```cs
warn: Microsoft.AspNetCore.Mvc.Formatters.XmlSerializerOutputFormatter[1]
An error occurred while trying to create an XmlSerializer for the type 'Packt.Shared.Customer'.
System.InvalidOperationException: There was an error reflecting type 'Packt.Shared.Customer'.
---> System.InvalidOperationException: Cannot serialize member 'Packt.
Shared.Customer.Orders' of type 'System.Collections.Generic.ICollection`1[[Packt. Shared.Order, Northwind.Common.EntityModels, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null]]', see inner exception for more details. 
```

我们可以通过在将`Customer`序列化为 XML 时排除`Orders`属性来防止此警告：

1.  在`Northwind.Common.EntityModels.Sqlite`和`Northwind.Common.EntityModels.SqlServer`项目中，打开`Customers.cs`文件。

1.  导入`System.Xml.Serialization`命名空间，以便我们能使用`[XmlIgnore]`属性。

1.  为`Orders`属性添加一个属性，以便在序列化时忽略它，如下面的代码中突出显示的那样：

    ```cs
    [InverseProperty(nameof(Order.Customer))]
    **[****XmlIgnore****]**
    public virtual ICollection<Order> Orders { get; set; } 
    ```

1.  在`Northwind.Common.EntityModels.SqlServer`项目中，同样为`CustomerCustomerDemos`属性添加`[XmlIgnore]`装饰。

# 记录和测试网络服务

通过浏览器发起 HTTP `GET`请求，你可以轻松测试网络服务。要测试其他 HTTP 方法，我们需要更高级的工具。

## 使用浏览器测试 GET 请求

你将使用 Chrome 测试`GET`请求的三种实现——获取所有客户、获取指定国家的客户以及通过唯一客户 ID 获取单个客户：

1.  启动`Northwind.WebApi`网络服务。

1.  启动 Chrome。

1.  访问`https://localhost:5001/api/customers`并注意返回的 JSON 文档，其中包含 Northwind 数据库中的所有 91 位客户（未排序），如图*16.3*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_03.png)

    图 16.3：Northwind 数据库中的客户作为 JSON 文档

1.  访问`https://localhost:5001/api/customers/?country=Germany`并注意返回的 JSON 文档，其中仅包含德国的客户，如图*16.4*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_04.png)

    图 16.4：来自德国的客户列表作为 JSON 文档

    如果返回的是空数组，请确保你输入的国家名称使用了正确的字母大小写，因为数据库查询是区分大小写的。例如，比较`uk`和`UK`的结果。

1.  访问`https://localhost:5001/api/customers/alfki`并注意返回的 JSON 文档，其中仅包含名为**Alfreds Futterkiste**的客户，如图*16.5*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_05.png)

    图 16.5：特定客户信息作为 JSON 文档

与国家名称不同，我们无需担心客户`id`值的大小写，因为在控制器类内部，我们已在代码中将`string`值规范化为大写。

但我们如何测试其他 HTTP 方法，如`POST`、`PUT`和`DELETE`？以及我们如何记录我们的网络服务，使其易于任何人理解如何与之交互？

为解决第一个问题，我们可以安装一个名为**REST Client**的 Visual Studio Code 扩展。为解决第二个问题，我们可以使用**Swagger**，这是全球最流行的 HTTP API 文档和测试技术。但首先，让我们看看 Visual Studio Code 扩展能做什么。

有许多工具可用于测试 Web API，例如**Postman**。尽管 Postman 很受欢迎，但我更喜欢**REST Client**，因为它不会隐藏实际发生的情况。我觉得 Postman 过于图形化。但我鼓励你探索不同的工具，找到适合你风格的工具。你可以在以下链接了解更多关于 Postman 的信息：[`www.postman.com/`](https://www.postman.com/)

## 使用 REST Client 扩展测试 HTTP 请求

REST Client 是一个扩展，允许你在 Visual Studio Code 中发送任何类型的 HTTP 请求并查看响应。即使你更喜欢使用 Visual Studio 作为代码编辑器，安装 Visual Studio Code 来使用像 REST Client 这样的扩展也是有用的。

### 使用 REST Client 进行 GET 请求

我们将首先创建一个文件来测试`GET`请求：

1.  如果你尚未安装由毛华超（`humao.rest-client`）开发的 REST Client，请立即在 Visual Studio Code 中安装它。

1.  在你偏好的代码编辑器中，启动`Northwind.WebApi`项目网络服务。

1.  在 Visual Studio Code 中，在`PracticalApps`文件夹中创建一个`RestClientTests`文件夹，然后打开该文件夹。

1.  在`RestClientTests`文件夹中，创建一个名为`get-customers.http`的文件，并修改其内容以包含一个 HTTP `GET`请求来检索所有客户，如下面的代码所示：

    ```cs
    GET https://localhost:5001/api/customers/ HTTP/1.1 
    ```

1.  在 Visual Studio Code 中，导航至**视图** | **命令面板**，输入`rest client`，选择命令**Rest Client: Send Request**，然后按 Enter，如图 16.6 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_06.png)

    图 16.6：使用 REST Client 发送 HTTP GET 请求

1.  注意**响应**显示在一个新的选项卡窗口面板中，并且你可以通过拖放选项卡将打开的选项卡重新排列为水平布局。

1.  输入更多`GET`请求，每个请求之间用三个井号分隔，以测试获取不同国家的客户和使用其 ID 获取单个客户，如下面的代码所示：

    ```cs
    ###
    GET https://localhost:5001/api/customers/?country=Germany HTTP/1.1 
    ###
    GET https://localhost:5001/api/customers/?country=USA HTTP/1.1 
    Accept: application/xml
    ###
    GET https://localhost:5001/api/customers/ALFKI HTTP/1.1 
    ###
    GET https://localhost:5001/api/customers/abcxy HTTP/1.1 
    ```

1.  点击每个请求上方的**发送请求**链接来发送它；例如，具有请求头以 XML 而非 JSON 格式请求美国客户的`GET`请求，如图 16.7 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_07.png)

图 16.7：使用 REST Client 发送 XML 请求并获取响应

### 使用 REST Client 进行其他请求

接下来，我们将创建一个文件来测试其他请求，如`POST`：

1.  在`RestClientTests`文件夹中，创建一个名为`create-customer.http`的文件，并修改其内容以定义一个`POST`请求来创建新客户，注意 REST Client 将在你输入常见 HTTP 请求时提供 IntelliSense，如下面的代码所示：

    ```cs
    POST https://localhost:5001/api/customers/ HTTP/1.1 
    Content-Type: application/json
    Content-Length: 301
    {
      "customerID": "ABCXY",
      "companyName": "ABC Corp",
      "contactName": "John Smith",
      "contactTitle": "Sir",
      "address": "Main Street",
      "city": "New York",
      "region": "NY",
      "postalCode": "90210",
      "country":  "USA",
      "phone": "(123) 555-1234",
      "fax": null,
      "orders": null
    } 
    ```

1.  由于不同操作系统中的行尾不同，`Content-Length`头的值在 Windows 和 macOS 或 Linux 上会有所不同。如果值错误，则请求将失败。要发现正确的内容长度，选择请求的主体，然后在状态栏中查看字符数，如图 16.8 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_08.png)

    图 16.8：检查正确的内容长度

1.  发送请求并注意响应是`201 Created`。同时注意新创建客户的地址（即 URL）是`https://localhost:5001/api/Customers/abcxy`，并在响应体中包含新创建的客户，如图 16.9 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_09.png)

图 16.9：添加新客户

我将留给您一个可选挑战，创建 REST 客户端文件以测试更新客户（使用`PUT`）和删除客户（使用`DELETE`）。尝试对存在和不存在的客户进行操作。解决方案位于本书的 GitHub 仓库中。

既然我们已经看到了一种快速简便的测试服务方法，这同时也是学习 HTTP 的好方法，那么外部开发者呢？我们希望他们学习和调用我们的服务尽可能简单。为此，我们将使用 Swagger。

## 理解 Swagger

Swagger 最重要的部分是**OpenAPI 规范**，它定义了您 API 的 REST 风格契约，详细说明了所有资源和操作，以易于开发、发现和集成的人机可读格式。

开发者可以使用 Web API 的 OpenAPI 规范自动生成其首选语言或库中的强类型客户端代码。

对我们来说，另一个有用的功能是**Swagger UI**，因为它自动为您的 API 生成文档，并内置了可视化测试功能。

让我们回顾一下如何使用`Swashbuckle`包为我们的 Web 服务启用 Swagger：

1.  如果 Web 服务正在运行，请关闭 Web 服务器。

1.  打开`Northwind.WebApi.csproj`并注意`Swashbuckle.AspNetCore`的包引用，如下所示：

    ```cs
    <ItemGroup>
      <PackageReference Include="Swashbuckle.AspNetCore" Version="6.1.5" />
    </ItemGroup> 
    ```

1.  将`Swashbuckle.AspNetCore`包的版本更新至最新，例如，截至 2021 年 9 月撰写时，版本为`6.2.1`。

1.  在`Program.cs`中，注意导入 Microsoft 的 OpenAPI 模型命名空间，如下所示：

    ```cs
    using Microsoft.OpenApi.Models; 
    ```

1.  导入 Swashbuckle 的 SwaggerUI 命名空间，如下所示：

    ```cs
    using Swashbuckle.AspNetCore.SwaggerUI; // SubmitMethod 
    ```

1.  在`Program.cs`大约中间位置，注意添加 Swagger 支持的语句，包括 Northwind 服务的文档，表明这是您服务的第一版，并更改标题，如下所示高亮显示：

    ```cs
    builder.Services.AddSwaggerGen(c =>
      {
        c.SwaggerDoc("v1", new()
          { Title = "**Northwind Service API**", Version = "v1" });
      }); 
    ```

1.  在配置 HTTP 请求管道的部分中，注意在开发模式下使用 Swagger 和 Swagger UI 的语句，并定义 OpenAPI 规范 JSON 文档的端点。

1.  添加代码以明确列出我们希望在 Web 服务中支持的 HTTP 方法，并更改端点名称，如下所示高亮显示：

    ```cs
    var app = builder.Build();
    // Configure the HTTP request pipeline.
    if (builder.Environment.IsDevelopment())
    {
      app.UseSwagger(); 
      app.UseSwaggerUI(c =>
     **{**
     **c.SwaggerEndpoint(****"/swagger/v1/swagger.json"****,**
    **"Northwind Service API Version 1"****);**
     **c.SupportedSubmitMethods(****new****[] {** 
     **SubmitMethod.Get, SubmitMethod.Post,**
     **SubmitMethod.Put, SubmitMethod.Delete });**
     **});**
    } 
    ```

## 使用 Swagger UI 测试请求

现在您已准备好使用 Swagger 测试 HTTP 请求：

1.  启动`Northwind.WebApi` Web 服务。

1.  在 Chrome 中导航至`https://localhost:5001/swagger/`，并注意**Customers**和**WeatherForecast** Web API 控制器已被发现并记录，以及 API 使用的**Schemas**。

1.  点击**GET /api/Customers/{id}**展开该端点，并注意客户**id**所需的参数，如*图 16.10*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_10.png)

    图 16.10：在 Swagger 中检查 GET 请求的参数

1.  点击**试用**，输入`ALFKI`作为**ID**，然后点击宽大的蓝色**执行**按钮，如图*16.11*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_11.png)

    图 16.11：点击执行按钮前输入客户 ID

1.  向下滚动并注意**请求 URL**、带有**代码**的**服务器响应**以及包含**响应体**和**响应头**的**详细信息**，如图*16.12*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_12.png)

    图 16.12：成功 Swagger 请求中关于 ALFKI 的信息

1.  滚动回页面顶部，点击**POST /api/Customers**展开该部分，然后点击**试用**。

1.  点击**请求体**框内，修改 JSON 以定义新客户，如下所示：

    ```cs
    {
      "customerID": "SUPER",
      "companyName": "Super Company",
      "contactName": "Rasmus Ibensen",
      "contactTitle": "Sales Leader",
      "address": "Rotterslef 23",
      "city": "Billund",
      "region": null,
      "postalCode": "4371",
      "country": "Denmark",
      "phone": "31 21 43 21",
      "fax": "31 21 43 22"
    } 
    ```

1.  点击**执行**，并注意**请求 URL**、带有**代码**的**服务器响应**以及包含**响应体**和**响应头**的**详细信息**，注意响应代码为`201`表示客户已成功创建，如图*16.13*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_13.png)

    图 16.13：成功添加新客户

1.  滚动回页面顶部，点击**GET /api/Customers**，点击**试用**，输入`Denmark`作为国家参数，点击**执行**，确认新客户已添加到数据库，如图*16.14*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_14.png)

    图 16.14：成功获取包括新添加客户在内的丹麦客户

1.  点击**DELETE /api/Customers/{id}**，点击**试用**，输入`super`作为**ID**，点击**执行**，并注意**服务器响应代码**为`204`，表明成功删除，如图*16.15*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_15.png)

    图 16.15：成功删除客户

1.  再次点击**执行**，并注意**服务器响应代码**为`404`，表明客户不再存在，**响应体**包含问题详情 JSON 文档，如图*16.16*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_16.png)

    图 16.16：已删除的客户不再存在

1.  输入`bad`作为**ID**，再次点击**执行**，并注意**服务器响应代码**为`400`，表明客户确实存在但删除失败（此情况下，因为网络服务模拟此错误），**响应体**包含一个自定义问题详情 JSON 文档，如图*16.17*所示:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_17.png)

    图 16.17：客户确实存在但删除失败

1.  使用`GET`方法确认新客户已从数据库中删除（原丹麦仅有两个客户）。

    我将使用`PUT`方法更新现有客户的测试留给读者。

1.  关闭 Chrome 并关闭网络服务器。

## 启用 HTTP 日志记录

HTTP 日志记录是一个可选的中间件组件，它记录有关 HTTP 请求和 HTTP 响应的信息，包括以下内容：

+   HTTP 请求信息

+   头部

+   主体

+   HTTP 响应信息

这在网络服务中对于审计和调试场景非常有价值，但需注意，它可能对性能产生负面影响。你还可能记录**个人身份信息**（**PII**），这在某些司法管辖区可能导致合规问题。

让我们看看 HTTP 日志记录的实际效果：

1.  在`Program.cs`中，导入用于处理 HTTP 日志记录的命名空间，如下列代码所示：

    ```cs
    using Microsoft.AspNetCore.HttpLogging; // HttpLoggingFields 
    ```

1.  在服务配置部分，添加一条配置 HTTP 日志记录的语句，如下列代码所示：

    ```cs
    builder.Services.AddHttpLogging(options =>
    {
      options.LoggingFields = HttpLoggingFields.All;
      options.RequestBodyLogLimit = 4096; // default is 32k
      options.ResponseBodyLogLimit = 4096; // default is 32k
    }); 
    ```

1.  在 HTTP 管道配置部分，添加一条在路由调用前添加 HTTP 日志记录的语句，如下列代码所示：

    ```cs
    app.UseHttpLogging(); 
    ```

1.  启动`Northwind.WebApi`网络服务。

1.  启动 Chrome 浏览器。

1.  导航至`https://localhost:5001/api/customers`。

1.  在命令提示符或终端中，注意请求和响应已被记录，如下列输出所示：

    ```cs
    info: Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware[1]
          Request:
          Protocol: HTTP/1.1
          Method: GET
          Scheme: https
          PathBase:
          Path: /api/customers
          QueryString:
          Connection: keep-alive
          Accept: */*
          Accept-Encoding: gzip, deflate, br
          Host: localhost:5001
    info: Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware[2]
          Response:
          StatusCode: 200
          Content-Type: application/json; charset=utf-8
          ...
          Transfer-Encoding: chunked 
    ```

1.  关闭 Chrome 并关闭网络服务器。

你现在已准备好构建消费你的网络服务的应用程序。

# 使用 HTTP 客户端消费网络服务

既然我们已经构建并测试了 Northwind 服务，接下来我们将学习如何使用`HttpClient`类及其工厂从任何.NET 应用中调用该服务。

## 理解 HttpClient

最简便的网络服务消费方式是使用`HttpClient`类。然而，许多人错误地使用它，因为它实现了`IDisposable`，且微软的官方文档展示了其不当用法。请参阅 GitHub 仓库中的书籍链接，以获取更多关于此话题的讨论文章。

通常，当类型实现`IDisposable`时，你应该在`using`语句中创建它，以确保其尽快被释放。`HttpClient`则不同，因为它被共享、可重入且部分线程安全。

问题与底层网络套接字的管理方式有关。简而言之，你应该为应用程序生命周期内消费的每个 HTTP 端点使用单一的`HttpClient`实例。这将允许每个`HttpClient`实例设置适合其工作端点的默认值，同时高效管理底层网络套接字。

## 使用 HttpClientFactory 配置 HTTP 客户端

微软已意识到此问题，并在 ASP.NET Core 2.1 中引入了`HttpClientFactory`以鼓励最佳实践；这正是我们将采用的技术。

在下述示例中，我们将以 Northwind MVC 网站作为 Northwind Web API 服务的客户端。由于两者需同时托管于同一网络服务器上，我们首先需要配置它们使用不同的端口号，如下表所示：

+   Northwind Web API 服务将使用`HTTPS`监听端口`5002`。

+   Northwind MVC 网站将继续使用`HTTP`监听端口`5000`，使用`HTTPS`监听端口`5001`。

让我们来配置这些端口：

1.  在`Northwind.WebApi`项目的`Program.cs`中，添加一个对`UseUrls`的扩展方法调用，指定`HTTPS`端口为`5002`，如下列高亮代码所示：

    ```cs
    var builder = WebApplication.CreateBuilder(args);
    **builder.WebHost.UseUrls(****"https://localhost:5002/"****);** 
    ```

1.  在`Northwind.Mvc`项目中，打开`Program.cs`，并导入用于处理 HTTP 客户端工厂的命名空间，如下面的代码所示：

    ```cs
    using System.Net.Http.Headers; // MediaTypeWithQualityHeaderValue 
    ```

1.  添加一条语句以启用`HttpClientFactory`，并使用命名客户端通过 HTTPS 在端口`5002`上调用 Northwind Web API 服务，并请求 JSON 作为默认响应格式，如下面的代码所示：

    ```cs
    builder.Services.AddHttpClient(name: "Northwind.WebApi",
      configureClient: options =>
      {
        options.BaseAddress = new Uri("https://localhost:5002/");
        options.DefaultRequestHeaders.Accept.Add(
          new MediaTypeWithQualityHeaderValue(
          "application/json", 1.0));
      }); 
    ```

## 在控制器中以 JSON 形式获取客户

我们现在可以创建一个 MVC 控制器动作方法，该方法使用工厂创建 HTTP 客户端，发起一个针对客户的`GET`请求，并使用.NET 5 中引入的`System.Net.Http.Json`程序集和命名空间中的便捷扩展方法反序列化 JSON 响应：

1.  打开`Controllers/HomeController.cs`，并声明一个用于存储 HTTP 客户端工厂的字段，如下面的代码所示：

    ```cs
    private readonly IHttpClientFactory clientFactory; 
    ```

1.  在构造函数中设置字段，如下面的代码中突出显示的那样：

    ```cs
    public HomeController(
      ILogger<HomeController> logger,
      NorthwindContext injectedContext**,**
     **IHttpClientFactory httpClientFactory**)
    {
      _logger = logger;
      db = injectedContext;
     **clientFactory = httpClientFactory;**
    } 
    ```

1.  创建一个新的动作方法，用于调用 Northwind Web API 服务，获取所有客户，并将他们传递给一个视图，如下面的代码所示：

    ```cs
    public async Task<IActionResult> Customers(string country)
    {
      string uri;
      if (string.IsNullOrEmpty(country))
      {
        ViewData["Title"] = "All Customers Worldwide";
        uri = "api/customers/";
      }
      else
      {
        ViewData["Title"] = $"Customers in {country}";
        uri = $"api/customers/?country={country}";
      }
      HttpClient client = clientFactory.CreateClient(
        name: "Northwind.WebApi");
      HttpRequestMessage request = new(
        method: HttpMethod.Get, requestUri: uri);
      HttpResponseMessage response = await client.SendAsync(request);
      IEnumerable<Customer>? model = await response.Content
        .ReadFromJsonAsync<IEnumerable<Customer>>();
      return View(model);
    } 
    ```

1.  在`Views/Home`文件夹中，创建一个名为`Customers.cshtml`的 Razor 文件。

1.  修改 Razor 文件以渲染客户，如下面的标记所示：

    ```cs
    @using Packt.Shared
    @model IEnumerable<Customer>
    <h2>@ViewData["Title"]</h2>
    <table class="table">
      <thead>
        <tr>
          <th>Company Name</th>
          <th>Contact Name</th>
          <th>Address</th>
          <th>Phone</th>
        </tr>
      </thead>
      <tbody>
        @if (Model is not null)
        {
          @foreach (Customer c in Model)
          {
            <tr>
              <td>
                @Html.DisplayFor(modelItem => c.CompanyName)
              </td>
              <td>
                @Html.DisplayFor(modelItem => c.ContactName)
              </td>
              <td>
                @Html.DisplayFor(modelItem => c.Address) 
                @Html.DisplayFor(modelItem => c.City)
                @Html.DisplayFor(modelItem => c.Region)
                @Html.DisplayFor(modelItem => c.Country) 
                @Html.DisplayFor(modelItem => c.PostalCode)
              </td>
              <td>
                @Html.DisplayFor(modelItem => c.Phone)
              </td>
            </tr>
          }
        }
      </tbody>
    </table> 
    ```

1.  在`Views/Home/Index.cshtml`中，在渲染访客计数后添加一个表单，允许访客输入一个国家并查看客户，如下面的标记所示：

    ```cs
    <h3>Query customers from a service</h3>
    <form asp-action="Customers" method="get">
      <input name="country" placeholder="Enter a country" />
      <input type="submit" />
    </form> 
    ```

## 启用跨源资源共享

**跨源资源共享**（**CORS**）是一种基于 HTTP 头部的标准，用于保护当客户端和服务器位于不同域（源）时的 Web 资源。它允许服务器指示哪些源（由域、方案或端口的组合定义）除了它自己的源之外，它将允许从这些源加载资源。

由于我们的 Web 服务托管在端口`5002`上，而我们的 MVC 网站托管在端口`5000`和`5001`上，它们被视为不同的源，因此资源不能共享。

在服务器上启用 CORS，并配置我们的 Web 服务，使其仅允许来自 MVC 网站的请求，这将非常有用：

1.  在`Northwind.WebApi`项目中，打开`Program.cs`。

1.  在服务配置部分添加一条语句，以添加对 CORS 的支持，如下面的代码所示：

    ```cs
    builder.Services.AddCors(); 
    ```

1.  在 HTTP 管道配置部分添加一条语句，在调用`UseEndpoints`之前，使用 CORS 并允许来自具有`https://localhost:5001`源的 Northwind MVC 等任何网站的`GET`、`POST`、`PUT`和`DELETE`请求，如下面的代码所示：

    ```cs
    app.UseCors(configurePolicy: options =>
    {
      options.WithMethods("GET", "POST", "PUT", "DELETE");
      options.WithOrigins(
        "https://localhost:5001" // allow requests from the MVC client
      );
    }); 
    ```

1.  启动`Northwind.WebApi`项目，并确认 Web 服务仅在端口`5002`上监听，如下面的输出所示：

    ```cs
    info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://localhost:5002 
    ```

1.  启动`Northwind.Mvc`项目，并确认网站正在监听端口`5000`和`5002`，如下面的输出所示：

    ```cs
    info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://localhost:5001
    info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://localhost:5000 
    ```

1.  启动 Chrome。

1.  在客户表单中，输入一个国家，如`Germany`、`UK`或`USA`，点击**提交**，并注意客户列表，如图*16.18*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_18.png)

    图 16.18：英国的客户

1.  点击浏览器中的**返回**按钮，清除国家文本框，点击**提交**，并注意全球客户列表。

1.  在命令提示符或终端中，注意`HttpClient`会记录它发出的每个 HTTP 请求和接收的 HTTP 响应，如下面的输出所示：

    ```cs
    info: System.Net.Http.HttpClient.Northwind.WebApi.ClientHandler[100]
      Sending HTTP request GET https://localhost:5002/api/customers/?country=UK
    info: System.Net.Http.HttpClient.Northwind.WebApi.ClientHandler[101]
      Received HTTP response headers after 931.864ms - 200 
    ```

1.  关闭 Chrome 并关闭网络服务器。

你已成功构建了一个网络服务，并从 MVC 网站中调用了它。

# 为网络服务实现高级功能

既然你已经看到了构建网络服务及其从客户端调用的基础知识，让我们来看看一些更高级的功能。

## 实现健康检查 API

有许多付费服务执行基本的站点可用性测试，如基本 ping，有些则提供更高级的 HTTP 响应分析。

ASP.NET Core 2.2 及更高版本使得实现更详细的网站健康检查变得容易。例如，你的网站可能在线，但它准备好了吗？它能从数据库检索数据吗？

让我们为我们的网络服务添加基本的健康检查功能：

1.  在`Northwind.WebApi`项目中，添加一个项目引用以启用 Entity Framework Core 数据库健康检查，如下面的标记所示：

    ```cs
    <PackageReference Include=  
      "Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore"   
      Version="6.0.0" /> 
    ```

1.  构建项目。

1.  在`Program.cs`中，在服务配置部分的底部，添加一条语句以添加健康检查，包括到 Northwind 数据库上下文，如下面的代码所示：

    ```cs
    builder.Services.AddHealthChecks()
      .AddDbContextCheck<NorthwindContext>(); 
    ```

    默认情况下，数据库上下文检查调用 EF Core 的`CanConnectAsync`方法。你可以通过调用`AddDbContextCheck`方法来自定义运行的操作。

1.  在 HTTP 管道配置部分，在调用`MapControllers`之前，添加一条语句以使用基本健康检查，如下面的代码所示：

    ```cs
    app.UseHealthChecks(path: "/howdoyoufeel"); 
    ```

1.  启动网络服务。

1.  启动 Chrome。

1.  导航到`https://localhost:5002/howdoyoufeel`并注意网络服务以纯文本响应：`Healthy`。

1.  在命令提示符或终端中，注意用于测试数据库健康状况的 SQL 语句，如下面的输出所示：

    ```cs
    Level: Debug, Event Id: 20100, State: Executing DbCommand [Parameters=[], CommandType='Text', CommandTimeout='30']
    SELECT 1 
    ```

1.  关闭 Chrome 并关闭网络服务器。

## 实现 Open API 分析器和约定

在本章中，你学习了如何通过手动使用属性装饰控制器类来启用 Swagger 以记录网络服务。

在 ASP.NET Core 2.2 或更高版本中，有 API 分析器会反射带有`[ApiController]`属性的控制器类来自动记录它。分析器假设了一些 API 约定。

要使用它，你的项目必须启用 OpenAPI 分析器，如下面的标记中突出显示的那样：

```cs
<PropertyGroup>
  <TargetFramework>net6.0</TargetFramework>
  <Nullable>enable</Nullable>
  <ImplicitUsings>enable</ImplicitUsings>
 **<IncludeOpenAPIAnalyzers>****true****</IncludeOpenAPIAnalyzers>**
</PropertyGroup> 
```

安装后，未正确装饰的控制器应显示警告（绿色波浪线），并在编译源代码时发出警告。例如，`WeatherForecastController`类。

自动代码修复随后可以添加适当的`[Produces]`和`[ProducesResponseType]`属性，尽管这在当前仅适用于 Visual Studio。在 Visual Studio Code 中，您将看到分析器认为您应该添加属性的警告，但您必须手动添加它们。

## 实现瞬态故障处理

当客户端应用或网站调用 Web 服务时，可能来自世界的另一端。客户端与服务器之间的网络问题可能导致与您的实现代码无关的问题。如果客户端发起调用失败，应用不应就此放弃。如果它尝试再次调用，问题可能已经解决。我们需要一种方法来处理这些临时故障。

为了处理这些瞬态故障，微软建议您使用第三方库 Polly 来实现带有指数退避的自动重试。您定义一个策略，库将处理其余所有事务。

**最佳实践**：您可以在以下链接了解更多关于 Polly 如何使您的 Web 服务更可靠的信息：[`docs.microsoft.com/en-us/dotnet/architecture/microservices/implement-resilient-applications/implement-http-call-retries-exponential-backoff-polly`](https://docs.microsoft.com/en-us/dotnet/architecture/microservices/implement-resilient-applications/implement-http-call-retries-exponential-backoff-polly)

## 添加安全 HTTP 头部

ASP.NET Core 内置了对常见安全 HTTP 头部（如 HSTS）的支持。但还有许多其他 HTTP 头部您应考虑实现。

添加这些头部的最简单方法是使用中间件类：

1.  在`Northwind.WebApi`项目/文件夹中，创建一个名为`SecurityHeadersMiddleware.cs`的文件，并修改其语句，如下所示：

    ```cs
    using Microsoft.Extensions.Primitives; // StringValues
    public class SecurityHeaders
    {
      private readonly RequestDelegate next;
      public SecurityHeaders(RequestDelegate next)
      {
        this.next = next;
      }
      public Task Invoke(HttpContext context)
      {
        // add any HTTP response headers you want here
        context.Response.Headers.Add(
          "super-secure", new StringValues("enable"));
        return next(context);
      }
    } 
    ```

1.  在`Program.cs`中，在 HTTP 管道配置部分，添加一条语句，在调用`UseEndpoints`之前注册中间件，如下所示：

    ```cs
    app.UseMiddleware<SecurityHeaders>(); 
    ```

1.  启动 Web 服务。

1.  启动 Chrome。

1.  显示**开发者工具**及其**网络**标签以记录请求和响应。

1.  导航至`https://localhost:5002/weatherforecast`。

1.  注意我们添加的自定义 HTTP 响应头部，名为`super-secure`，如*图 16.19*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_19.png)

    *图 16.19*：添加名为 super-secure 的自定义 HTTP 头部

# 使用最小 API 构建 Web 服务

对于.NET 6，微软投入了大量精力为 C# 10 语言添加新特性，并简化 ASP.NET Core 库，以实现使用最小 API 创建 Web 服务。

您可能还记得 Web API 项目模板中提供的天气预报服务。它展示了使用控制器类返回使用假数据的五天天气预报。我们现在将使用最小 API 重现该天气服务。

首先，天气服务有一个类来表示单个天气预报。我们将在多个项目中需要使用这个类，所以让我们为此创建一个类库：

1.  使用您喜欢的代码编辑器添加一个新项目，如下列清单所定义：

    1.  项目模板：**类库** / `classlib`

    1.  工作区/解决方案文件和文件夹：`PracticalApps`

    1.  项目文件和文件夹：`Northwind.Common`

1.  将`Class1.cs`重命名为`WeatherForecast.cs`。

1.  修改`WeatherForecast.cs`，如下面的代码所示：

    ```cs
    namespace Northwind.Common
    {
      public class WeatherForecast
      {
        public static readonly string[] Summaries = new[]
        {
          "Freezing", "Bracing", "Chilly", "Cool", "Mild",
          "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };
        public DateTime Date { get; set; }
        public int TemperatureC { get; set; }
        public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
        public string? Summary { get; set; }
      }
    } 
    ```

## 使用最小 API 构建天气服务

现在让我们使用最小 API 重新创建该天气服务。它将在端口`5003`上监听，并启用 CORS 支持，以便请求只能来自 MVC 网站，并且只允许`GET`请求：

1.  使用您喜欢的代码编辑器添加一个新项目，如下列清单所定义：

    1.  项目模板：**ASP.NET Core 空** / `web`

    1.  工作区/解决方案文件和文件夹：`PracticalApps`

    1.  项目文件和文件夹：`Minimal.WebApi`

    1.  其他 Visual Studio 选项：**身份验证类型**：无，**为 HTTPS 配置**：已选中，**启用 Docker**：已清除，**启用 OpenAPI 支持**：已选中。

1.  在 Visual Studio Code 中，选择`Minimal.WebApi`作为活动的 OmniSharp 项目。

1.  在`Minimal.WebApi`项目中，添加一个项目引用指向`Northwind.Common`项目，如下面的标记所示：

    ```cs
    <ItemGroup>
      <ProjectReference Include="..\Northwind.Common\Northwind.Common.csproj" />
    </ItemGroup> 
    ```

1.  构建`Minimal.WebApi`项目。

1.  修改`Program.cs`，如下面的代码中突出显示的那样：

    ```cs
    **using** **Northwind.Common;** **// WeatherForecast**
    var builder = WebApplication.CreateBuilder(args);
    **builder.WebHost.UseUrls(****"https://localhost:5003"****);**
    **builder.Services.AddCors();**
    var app = builder.Build();
    **// only allow the MVC client and only GET requests**
    **app.UseCors(configurePolicy: options =>**
    **{**
     **options.WithMethods(****"GET"****);**
     **options.WithOrigins(****"https://localhost:5001"****);**
    **});**
    **app.MapGet(****"/api/weather"****, () =>** 
    **{**
    **return** **Enumerable.Range(****1****,** **5****).Select(index =>**
    **new** **WeatherForecast**
     **{**
     **Date = DateTime.Now.AddDays(index),**
     **TemperatureC = Random.Shared.Next(****-20****,** **55****),**
     **Summary = WeatherForecast.Summaries[**
     **Random.Shared.Next(WeatherForecast.Summaries.Length)]**
     **})**
     **.ToArray();**
    **});**
    app.Run(); 
    ```

    **良好实践**：对于简单的 Web 服务，避免创建控制器类，而是使用最小 API 将所有配置和实现放在一个地方，即`Program.cs`。

1.  在**属性**中，修改`launchSettings.json`以配置`Minimal.WebApi`配置文件，使其通过 URL 中的端口`5003`启动浏览器，如下面的标记中突出显示的那样：

    ```cs
    "profiles": {
      "Minimal.WebApi": {
        "commandName": "Project",
        "dotnetRunMessages": "true",
        "launchBrowser": true,
    **"applicationUrl"****:** **"https://localhost:5003/api/weather"****,**
        "environmentVariables": {
          "ASPNETCORE_ENVIRONMENT": "Development"
        } 
    ```

## 测试最小天气服务

在创建服务客户端之前，让我们测试它是否返回 JSON 格式的预报：

1.  启动 Web 服务项目。

1.  如果你没有使用 Visual Studio 2022，请启动 Chrome 并导航至`https://localhost:5003/api/weather`。

1.  注意 Web API 服务应返回一个包含五个随机天气预报对象的 JSON 文档数组。

1.  关闭 Chrome 并关闭 Web 服务器。

## 向 Northwind 网站首页添加天气预报

最后，让我们向 Northwind 网站添加一个 HTTP 客户端，以便它可以调用天气服务并在首页显示预报：

1.  在`Northwind.Mvc`项目中，添加一个项目引用指向`Northwind.Common`，如下面的标记中突出显示的那样：

    ```cs
    <ItemGroup>
      <!-- change Sqlite to SqlServer if you prefer -->
      <ProjectReference Include="..\Northwind.Common.DataContext.Sqlite\Northwind.Common.DataContext.Sqlite.csproj" />
     **<ProjectReference Include=****"..\Northwind.Common\Northwind.Common.csproj"** **/>**
    </ItemGroup> 
    ```

1.  在`Program.cs`中，添加一条语句以配置 HTTP 客户端以调用端口`5003`上的最小服务，如下面的代码所示：

    ```cs
    builder.Services.AddHttpClient(name: "Minimal.WebApi",
      configureClient: options =>
      {
        options.BaseAddress = new Uri("https://localhost:5003/");
        options.DefaultRequestHeaders.Accept.Add(
          new MediaTypeWithQualityHeaderValue(
          "application/json", 1.0));
      }); 
    ```

1.  在`HomeController.cs`中，导入`Northwind.Common`命名空间，并在`Index`方法中，添加语句以获取并使用 HTTP 客户端调用天气服务以获取预报并将其存储在`ViewData`中，如下面的代码所示：

    ```cs
    try
    {
      HttpClient client = clientFactory.CreateClient(
        name: "Minimal.WebApi");
      HttpRequestMessage request = new(
        method: HttpMethod.Get, requestUri: "api/weather");
      HttpResponseMessage response = await client.SendAsync(request);
      ViewData["weather"] = await response.Content
        .ReadFromJsonAsync<WeatherForecast[]>();
    }
    catch (Exception ex)
    {
      _logger.LogWarning($"The Minimal.WebApi service is not responding. Exception: {ex.Message}");
      ViewData["weather"] = Enumerable.Empty<WeatherForecast>().ToArray();
    } 
    ```

1.  在`Views/Home`中，在`Index.cshtml`中，导入`Northwind.Common`命名空间，然后在顶部代码块中从`ViewData`字典获取天气预报，如下面的标记所示：

    ```cs
    @{
      ViewData["Title"] = "Home Page";
      string currentItem = "";
     **WeatherForecast[]? weather = ViewData[****"weather"****]** **as** **WeatherForecast[];**
    } 
    ```

1.  在第一个`<div>`中，在渲染当前时间后，除非没有天气预报，否则添加标记以枚举天气预报，并以表格形式呈现，如下所示：

    ```cs
    <p>
      <h4>Five-Day Weather Forecast</h4>
      @if ((weather is null) || (!weather.Any()))
      {
        <p>No weather forecasts found.</p>
      }
      else
      {
      <table class="table table-info">
        <tr>
          @foreach (WeatherForecast w in weather)
          {
            <td>@w.Date.ToString("ddd d MMM") will be @w.Summary</td>
          }
        </tr>
      </table>
      }
    </p> 
    ```

1.  启动`Minimal.WebApi`服务。

1.  启动`Northwind.Mvc`网站。

1.  导航至`https://localhost:5001/`，并注意天气预报，如图*16.20*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_17_20.png)

    图 16.20：Northwind 网站主页上的五天天气预报

1.  查看 MVC 网站的命令提示符或终端，并注意指示请求已发送到最小 API Web 服务`api/weather`端点的信息消息，大约耗时 83ms，如下所示：

    ```cs
    info: System.Net.Http.HttpClient.Minimal.WebApi.LogicalHandler[100]
          Start processing HTTP request GET https://localhost:5003/api/weather
    info: System.Net.Http.HttpClient.Minimal.WebApi.ClientHandler[100]
          Sending HTTP request GET https://localhost:5003/api/weather
    info: System.Net.Http.HttpClient.Minimal.WebApi.ClientHandler[101]
          Received HTTP response headers after 76.8963ms - 200
    info: System.Net.Http.HttpClient.Minimal.WebApi.LogicalHandler[101]
          End processing HTTP request after 82.9515ms – 200 
    ```

1.  停止`Minimal.WebApi`服务，刷新浏览器，并注意几秒后 MVC 网站主页出现，但没有天气预报。

1.  关闭 Chrome 并关闭 Web 服务器。

# 实践与探索

通过回答一些问题测试您的知识和理解，进行一些实践练习，并深入研究本章的主题。

## 练习 16.1 – 测试您的知识

回答以下问题：

1.  为了创建 ASP.NET Core Web API 服务的控制器类，您应该继承自哪个类？

1.  如果您用`[ApiController]`属性装饰控制器类以获得默认行为，如对无效模型自动返回`400`响应，还需要做什么？

1.  指定哪个控制器操作方法将执行以响应 HTTP 请求，您必须做什么？

1.  指定调用操作方法时应预期哪些响应，您必须做什么？

1.  列出三种可以调用的方法，以返回具有不同状态码的响应。

1.  列出四种测试 Web 服务的方法。

1.  尽管`HttpClient`实现了`IDisposable`接口，为何不应在`using`语句中包裹其使用以在完成时释放它，以及应使用什么替代方案？

1.  CORS 缩写代表什么，为何在 Web 服务中启用它很重要？

1.  如何在 ASP.NET Core 2.2 及更高版本中使客户端能够检测您的 Web 服务是否健康？

1.  端点路由提供了哪些好处？

## 练习 16.2 – 使用 HttpClient 练习创建和删除客户

扩展`Northwind.Mvc`网站项目，使其拥有页面，访客可以在其中填写表单以创建新客户，或搜索客户并删除他们。MVC 控制器应调用 Northwind Web 服务来创建和删除客户。

## 练习 16.3 – 探索主题

使用以下页面上的链接，深入了解本章涵盖的主题：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-16---building-and-consuming-web-services`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-16---building-and-consuming-web-services)

# 总结

本章中，你学习了如何构建一个 ASP.NET Core Web API 服务，该服务可被任何能够发起 HTTP 请求并处理 HTTP 响应的平台上的应用调用。

你还学习了如何使用 Swagger 测试和文档化 Web 服务 API，以及如何高效地消费这些服务。

下一章，你将学习使用 Blazor 构建用户界面，这是微软推出的酷炫新技术，让开发者能用 C#而非 JavaScript 来构建网站的客户端单页应用（SPAs）、桌面混合应用，以及潜在的移动应用。
