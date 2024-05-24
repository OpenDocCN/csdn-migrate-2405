# C#7 和 .NET Core 2.0 蓝图（二）

> 原文：[`zh.annas-archive.org/md5/7C3D5DACD7BE632FD426A045B35F94C4`](https://zh.annas-archive.org/md5/7C3D5DACD7BE632FD426A045B35F94C4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：跨平台.NET Core 系统信息管理器

在本章中，我们将创建一个简单的*信息仪表板*应用程序，显示我们正在运行的计算机的信息，以及该计算机位置的天气情况。这是使用 IP 地址完成的，虽然可能不是 100%准确（因为给我的位置是一个镇或者离这里有一段距离），但我想要证明的概念不是位置准确性。

关于我们正在创建的应用程序，我们将做以下事情：

+   在 Windows 上设置应用程序

+   查看`Startup.cs`文件并添加控制器和视图

+   在 Windows 上运行应用程序

+   在 macOS 上运行应用程序

+   在 Linux 上设置和运行应用程序

本章主要介绍 ASP.NET Core 是什么。对于那些不知道的人，.NET Core 允许我们创建可以在 Windows、macOS 和 Linux 上运行的应用程序。

.NET Core 包括 ASP.NET Core 和 EF Core。

Microsoft 将 ASP.NET Core 定义如下：

"ASP.NET Core 是一个跨平台、高性能、开源框架，用于构建现代、基于云的、互联网连接的应用程序。"

是的，.NET Core 是开源的。您可以在 GitHub 上找到它 - [`github.com/dotnet/core`](https://github.com/dotnet/core)。使用.NET Core 的好处列在文档网站上 - [`docs.microsoft.com/en-us/aspnet/core/`](https://docs.microsoft.com/en-us/aspnet/core/)。这些好处如下：

+   构建 Web UI 和 Web API 的统一故事

+   集成现代客户端框架和开发工作流

+   云就绪，基于环境的配置系统

+   内置依赖注入

+   轻量级、高性能和模块化的 HTTP 请求管道

+   能够在**IIS**（**Internet Information Services**）上托管或在自己的进程中进行自托管

+   可以在.NET Core 上运行，支持真正的并行应用程序版本

+   简化现代 Web 开发的工具

+   能够在 Windows、macOS 和 Linux 上构建和运行

+   开源和社区关注

我鼓励您查看 Microsoft 文档网站上关于这个主题的内容 - [`docs.microsoft.com/en-us/aspnet/core/`](https://docs.microsoft.com/en-us/aspnet/core/)。

实际上，ASP.NET Core 只包括适用于您的项目的 NuGet 包。这意味着应用程序更小、性能更好。在本章中，将会看到 NuGet 的用法。

所以，让我们开始吧。接下来，让我们创建我们的第一个跨平台 ASP.NET Core MVC 应用程序。

# 在 Windows 上设置项目

我们需要做的第一件事是在开发机器上设置.NET Core 2.0。出于本书的目的，我使用 Windows PC 来说明这一步骤，但实际上，您可以在 macOS 或 Linux 上设置.NET Core 应用程序。

我将在本章后面说明如何在 Linux 上设置.NET Core。对于 macOS，这个过程类似，但我发现在 Linux 上有点棘手。因此，我选择逐步为 Linux 展示这一步骤。

对于 macOS，我将向您展示如何在 Windows PC 上创建的应用程序上运行。这就是.NET Core 的真正之美。它是一种真正的跨平台技术，能够在任何三个平台（Windows、macOS 和 Linux）上完美运行：

1.  将浏览器指向[`www.microsoft.com/net/core`](https://www.microsoft.com/net/core)并下载.NET Core SDK：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/96908c83-5395-4f3b-86e3-dda1b45b6af5.png)

安装也非常简单。如果您看一下这个屏幕，您会注意到这与 Linux 安装之间的相似之处。两者都有一个通知，告诉您在安装过程中运行一个命令来提高项目恢复速度：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/01c16d8d-5324-4943-a661-1fcc7cd38ffa.png)

安装完成后，您会找到一些资源、文档、教程和发布说明的链接：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ee852623-3c0e-43c8-b119-6a6a57b7bf9f.png)

1.  启动 Visual Studio 并创建一个新的 ASP.NET Core Web 应用程序。同时，选择.NET Framework 4.6.2：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6d128c41-30b5-4433-a094-a294ede6f7f5.png)

1.  在下一个屏幕上，从模板中选择 Web 应用程序（模型-视图-控制器**）**，并确保您已选择了 ASP.NET Core 2.0。准备好后，单击“确定”按钮创建 ASP.NET Core 项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/77f9efc7-3da3-460e-a758-8e931920f2f9.png)

创建项目后，您将在解决方案资源管理器中看到熟悉的 MVC 结构。模型-视图-控制器架构模式需要一点时间来适应，特别是如果您是从传统的 ASP.NET Web Forms 方法转变而来的 Web 开发人员。

我向您保证，使用 MVC 工作一段时间后，您将不想回到 ASP.NET Web Forms。使用 MVC 非常有趣，而且在许多方面更有益，特别是如果这对您来说仍然是全新的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3da47bd2-8afa-47db-a2a0-d084d240f0ff.png)

1.  现在，您可以通过按住*Ctrl* + *F5*或在 Visual Studio 中点击调试按钮来运行应用程序。应用程序启动后，浏览器将显示 MVC 应用程序的标准视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/55f91ff8-2bc4-4181-8243-c85ba648a3df.png)

1.  停止调试会话，右键单击解决方案资源管理器中的项目。从弹出的上下文菜单中，单击 ManageNuGetPackages**...**，这将打开 NuGet 表单。

我们要添加的第一个 NuGet 包是`Newtonsoft.Json`。这是为了使我们能够在应用程序中使用 JSON。

1.  单击安装按钮以将最新版本添加到您的应用程序中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/712f18a2-9b07-4d54-b714-934e92d39ea3.png)

我们要添加的下一个 NuGet 包叫做`DarkSkyCore`。这是一个用于使用 Dark Sky API 的.NET Standard 库。

我已经看到有人对.NET Standard 库的说法产生了疑问。我们在这里处理的是.NET Core，对吧？那么，.NET Standard 是什么呢？

以下网站（.NET Core 教程）对此有很好的解释（[`dotnetcoretutorials.com/2017/01/13/net-standard-vs-net-core-whats-difference/`](https://dotnetcoretutorials.com/2017/01/13/net-standard-vs-net-core-whats-difference/)）：

"如果您编写一个希望在.net Core、UWP、Windows Phone 和.net Framework 上运行的库，您只需要使用所有这些平台上都可用的类。您如何知道哪些类在所有平台上都可用？.net Standard！"

.NET Standard 就是这样一个标准。如果您想要针对更多平台进行目标化，您需要针对较低版本的标准。如果您想要更多的 API 可用，您需要针对较高版本的标准。有一个 GitHub 存储库，[`github.com/dotnet/standard`](https://github.com/dotnet/standard)，您可以查看，并且有一个方便的图表显示每个平台版本实现了标准的哪个版本，可以转到[`github.com/dotnet/standard/blob/master/docs/versions.md`](https://github.com/dotnet/standard/blob/master/docs/versions.md)查看。

1.  返回到`DarkSkyCore`。单击安装按钮以获取最新版本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5da45e25-a948-46e4-bf5b-5d32da6fa99d.png)

现在我们已经安装了 NuGet 包，让我们更详细地查看项目。

# 项目详细信息

在我添加了所有必需的资源、控制器、视图和模型之后查看项目，您会注意到我添加了一些额外的文件夹。

我的解决方案将如下所示：

+   `_docs`（在下面的截图中标记为**1**）：我个人的偏好是保留一个文件夹，我可以在其中做笔记并保存我发现对项目有用的相关链接

+   `climacons`(**2**): 这是包含将用作天气图标的 SVG 文件的文件夹

+   `InformationController`(**3**): 这是项目的控制器

+   `InformationModel`(**4**): 这是项目的模型

+   `GetInfo`(**5**): 这是与我的控制器上的`GetInfo()`方法对应的视图

除了`Models`，`Views`和`Controllers`文件夹，您可以根据需要放置其他文件夹。只需记住保持与解决方案相关的引用即可：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/dfd236a6-dcef-439d-b104-671e6b24bce2.png)

# Climacons

Adam Whitcroft 为 Web 应用程序和 UI 设计师创建了 75 个气候分类的象形文字。我们需要下载它们以在我们的应用程序中使用：

1.  前往[`adamwhitcroft.com/climacons/`](http://adamwhitcroft.com/climacons/)并下载该集合以将其包含在您的项目中。

始终记得要对你应用程序中使用的资源的创建者进行归因。

1.  要将文件夹包含在项目中，只需将 SVG 文件放在项目中的一个文件夹中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/bad6f486-dddc-490a-b932-810e3082fbcb.png)

# Startup.cs 文件

深入代码，让我们从`Startup.cs`文件开始。它应该已经默认创建了，但为了完整起见，我也在这里包含了它。

作为标准命名约定，名称`Startup`用于此文件。但实际上，您可以随意命名它。只需确保在`Program.cs`文件中也将其重命名。

`Startup.cs`文件中应包括以下`using`语句：

```cs
using Microsoft.AspNetCore.Builder; 
using Microsoft.AspNetCore.Hosting; 
using Microsoft.Extensions.Configuration; 
using Microsoft.Extensions.DependencyInjection; 
```

`Startup`文件中包含的代码对您来说将是相同的，并且在创建应用程序时默认生成。在本章中，我们不会修改此文件，但是通常情况下，如果您想要添加任何中间件，您会来到`Configure()`方法：

```cs
public class Startup 
{ 
    public Startup(IConfiguration configuration) 
    { 
        Configuration = configuration; 
    } 

    public IConfiguration Configuration { get; } 

    // This method gets called by the runtime. Use this method to add 
      services to the container. 
    public void ConfigureServices(IServiceCollection services) 
    { 
        services.AddMvc(); 
    } 

    // This method gets called by the runtime. Use this method
     to configure the HTTP request pipeline. 
    public void Configure(IApplicationBuilder app, IHostingEnvironment 
    env) 
    { 
        if (env.IsDevelopment()) 
        { 
            app.UseDeveloperExceptionPage(); 
            app.UseBrowserLink(); 
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

# InformationModel 类

该应用程序的模型非常简单。它将仅公开在我们的控制器中获取的值，并提供视图访问这些值的权限。要添加模型，请右键单击`Models`文件夹，然后添加一个名为`InformationModel`的新类：

```cs
public class InformationModel 
{         
    public string OperatingSystem { get; set; } 
    public string InfoTitle { get; set; } 
    public string FrameworkDescription { get; set; } 
    public string OSArchitecture { get; set; } 
    public string ProcessArchitecture { get; set; } 
    public string Memory { get; set; } 
    public string IPAddressString { get; set; } 
    public string WeatherBy { get; set; } 
    public string CurrentTemperature { get; set; } 
    public string CurrentIcon { get; set; } 
    public string DailySummary { get; set; } 
    public string CurrentCity { get; set; } 
    public string UnitOfMeasure { get; set; } 
} 
```

然后，按照前面的代码清单所示，添加属性。

# InformationController 类

我们需要采取的下一步是为我们的应用程序添加控制器：

1.  右键单击`Controllers`文件夹，选择“添加”，然后在上下文菜单中单击“Controller”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e4d643e4-f6b4-4c7c-a11d-0cd38a4722e6.png)

1.  通过从添加脚手架屏幕中选择 MVC Controller - Empty 来添加一个名为`InformationController`的新控制器。需要将以下`using`语句添加到控制器中：

```cs
using DarkSky.Models; 
using DarkSky.Services; 
using Microsoft.AspNetCore.Hosting; 
using Microsoft.AspNetCore.Mvc; 
using Newtonsoft.Json; 
using System.Globalization; 
using System.IO; 
using System.Net.Http; 
using System.Runtime.InteropServices; 
using System.Threading.Tasks; 
using static System.Math; 
```

微软文档中提到：

IHostingEnvironment 服务提供了与环境交互的核心抽象。这项服务由 ASP.NET 托管层提供，并可以通过依赖注入注入到启动逻辑中。

要了解更多信息，请浏览[`docs.microsoft.com/en-us/aspnet/core/fundamentals/environments`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/environments)并查看文档。

1.  在我们的控制器的前面构造函数中添加以下属性。您会注意到我们已经将`IHostingEnvironment`接口添加到了类中：

```cs
public string PublicIP { get; set; } = "IP Lookup Failed"; 
public double Long { get; set; } 
public double Latt { get; set; } 
public string City { get; set; } 
public string CurrentWeatherIcon { get; set; } 
public string WeatherAttribution { get; set; } 
public string CurrentTemp { get; set; } = "undetermined"; 
public string DayWeatherSummary { get; set; } 
public string TempUnitOfMeasure { get; set; } 
private readonly IHostingEnvironment _hostEnv; 

public InformationController(IHostingEnvironment hostingEnvironment) 
{ 
    _hostEnv = hostingEnvironment; 
} 
```

1.  创建一个名为`GetInfo()`的空方法。控制器（以及其中包含的方法）、视图和模型的命名是非常有意义的。如果遵循 MVC 设计模式的一组约定，将所有这些绑定在一起就会变得非常容易：

```cs
public IActionResult GetInfo() 
{ 

}
```

1.  如果您还记得，`Startup`类在`Configure()`方法中定义了一个`MapRoute`调用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c8f289d8-e874-4fff-9ae2-000d4299d608.png)

代码的这一部分`{controller=Home}/{action=Index}/{id?}`被称为**路由模板**。MVC 应用程序使用标记化来提取路由值。

这意味着以下内容：

+   +   `{controller=Home}`定义了默认为`Home`的控制器的名称

+   `{action=Index}`定义了默认为`Index`的控制器的方法

+   最后，`{id?}`被定义为可选的，通过`?`，可以用来传递参数

这意味着如果我不给应用程序指定路由（或 URL），它将使用在`MapRoute`调用中设置的默认值。

但是，如果我给应用程序一个`http://localhost:50239/Information/GetInfo`的路由，它将重定向到`InformationController`上的`GetInfo()`方法。

有关路由的更多信息，请访问[`docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing`](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing)并阅读文档。

1.  在我们的`Controllers`文件夹中，添加一个名为`LocationInfo`的类。我们将在调用位置信息 API 后使用它将 JSON 字符串绑定到它：

```cs
public class LocationInfo 
{ 
    public string ip { get; set; }  
    public string city { get; set; }  
    public string region { get; set; }  
    public string region_code { get; set; } 
    public string country { get; set; } 
    public string country_name { get; set; } 
    public string postal { get; set; } 
    public double latitude { get; set; } 
    public double longitude { get; set; }  
    public string timezone { get; set; }  
    public string asn { get; set; }  
    public string org { get; set; }          
} 
```

要获取位置信息，您可以使用许多位置 API 之一。我在[`ipapi.co`](https://ipapi.co)上使用了一个 API 来为我提供位置信息。`GetLocationInfo()`方法只是调用 API 并将返回的 JSON 反序列化为刚刚创建的`LocationInfo`类。

就我个人而言，我认为`ipapi`这个名字真的很聪明。这是一个人不容易忘记的东西。他们还在他们的定价中提供了一个免费层，每天可以进行 1,000 次请求。这非常适合个人使用：

```cs
private async Task GetLocationInfo() 
{ 
    var httpClient = new HttpClient(); 
    string json = await 
     httpClient.GetStringAsync("https://ipapi.co/json"); 
    LocationInfo info = JsonConvert.DeserializeObject<LocationInfo>
    (json); 

    PublicIP = info.ip; 
    Long = info.longitude; 
    Latt = info.latitude; 
    City = info.city; 
}
```

1.  我们将使用的下一个 API 是**Dark Sky**。您需要在[`darksky.net/dev`](https://darksky.net/dev)注册帐户以获取您的 API 密钥：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b41cd207-2ca0-4ea1-bf25-873c143c1e7d.png)

我喜欢 Dark Sky 的一点是，他们的 API 还允许您每天进行 1,000 次免费 API 调用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f8380a50-69da-404c-9e9e-ee8f186cc26f.png)

这使它非常适合个人使用。如果您有大量用户，即使选择按使用付费的选项也不贵。

请注意，如果您将 Dark Sky API 用于商业应用程序，您不能要求您应用程序的每个用户注册 Dark Sky API 密钥。您 Dark Sky 应用程序的所有用户必须使用您通过在线门户生成的特定 API 密钥。

对于那些感兴趣的人，常见问题解答提供了对此和许多其他重要问题的澄清：

“...您的最终用户不应该注册 Dark Sky API 密钥：API 密钥应与您的应用程序或服务关联，而不是与您的用户关联。

每天 1,000 次免费调用旨在促进个人使用和应用程序开发，而不是为您的应用程序提供免费天气数据。我们花费了大量资金来开发和维护支持 Dark Sky API 的基础设施。如果您的应用程序因受欢迎而增长，我们将不得不支付用于处理增加的流量所需资源的费用（这将使您的服务和用户受益），而没有财务手段来支持它。因此，我们的服务条款禁止要求用户注册 API 密钥的应用程序。”

跟踪 API 调用也非常容易，可以通过在线门户查看：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6030bb06-60d1-407e-8783-b192fbc5a0b6.png)

有了 Dark Sky API 注册，我们想要看看应用程序是否在使用公制系统或英制系统来测量单位的地区运行。

1.  创建一个名为`GetUnitOfMeasure()`的方法，该方法返回一个`DarkSkyService.OptionalParameters`对象。这本质上只是使用`RegionInfo`类来检查当前地区是否为公制。

然后设置`optParms`变量并将其返回给调用类。我还趁机加入了`TempUnitOfMeasure`属性的摄氏度或华氏度符号：

```cs
private DarkSkyService.OptionalParameters GetUnitOfMeasure() 
{ 
    bool blnMetric = RegionInfo.CurrentRegion.IsMetric; 
    DarkSkyService.OptionalParameters optParms = new 
     DarkSkyService.OptionalParameters(); 
    if (blnMetric) 
    { 
        optParms.MeasurementUnits = "si"; 
        TempUnitOfMeasure = "C"; 
    } 
    else 
    { 
        optParms.MeasurementUnits = "us"; 
        TempUnitOfMeasure = "F"; 
    } 
    return optParms; 
} 
```

1.  要添加的下一种方法称为`GetCurrentWeatherIcon()`，它将用于确定要在我们的网页上显示的 Dark Sky 图标。还有许多选择，但出于简洁起见，我选择只包括这几个图标名称。这些图标名称对应于我们解决方案中`climacons`文件夹中的 SVG 文件名的完整列表：

```cs
private string GetCurrentWeatherIcon(Icon ic) 
{ 
    string iconFilename = string.Empty; 

    switch (ic) 
    { 
        case Icon.ClearDay: 
            iconFilename = "Sun.svg"; 
            break; 

        case Icon.ClearNight: 
            iconFilename = "Moon.svg"; 
            break; 

        case Icon.Cloudy: 
            iconFilename = "Cloud.svg"; 
            break; 

        case Icon.Fog: 
            iconFilename = "Cloud-Fog.svg"; 
            break; 

        case Icon.PartlyCloudyDay: 
            iconFilename = "Cloud-Sun.svg"; 
            break; 

        case Icon.PartlyCloudyNight: 
            iconFilename = "Cloud-Moon.svg"; 
            break; 

        case Icon.Rain: 
            iconFilename = "Cloud-Rain.svg"; 
            break; 

        case Icon.Snow: 
            iconFilename = "Snowflake.svg"; 
            break; 

         case Icon.Wind: 
            iconFilename = "Wind.svg"; 
            break; 
         default: 
            iconFilename = "Thermometer.svg"; 
            break; 
    } 
    return iconFilename; 
} 
```

1.  创建的下一个方法是`GetWeatherInfo()`方法。这只是调用`DarkSkyService`类并将之前在 Dark Sky 门户中生成的 API 密钥传递给它。您会注意到，代码实际上并不是什么高深莫测的东西。

该类中的步骤如下：

1.  1.  定义 Dark Sky 的 API 密钥。

1.  使用 API 密钥实例化一个新的`DarkSkyService`对象。

1.  获取确定度量单位的`OptionalParameters`对象。

1.  然后，我们使用纬度和经度以及`optParms`来获取预报。

1.  根据预报，我找到了适当的天气图标。

1.  我使用`Path.Combine`来获取 SVG 文件的正确路径。

1.  我读取了 SVG 文件中包含的所有文本。

1.  最后，我设置了一些属性，用于将归因于 Dark Sky 的天气摘要和温度值四舍五入，使用静态`Math`类中的`Round`函数。在代码中，我不需要完全限定这一点，因为我之前已经导入了静态`Math`类。

因此，您的代码需要如下所示：

```cs
private async Task GetWeatherInfo() 
{ 
    string apiKey = "YOUR_API_KEY_HERE"; 
    DarkSkyService weather = new DarkSkyService(apiKey);             
    DarkSkyService.OptionalParameters optParms =
     GetUnitOfMeasure(); 
    var foreCast = await weather.GetForecast(Latt, Long, optParms); 

    string iconFilename = 
     GetCurrentWeatherIcon(foreCast.Response.Currently.Icon); 
    string svgFile = Path.Combine(_hostEnv.ContentRootPath, 
     "climacons", iconFilename); 
    CurrentWeatherIcon = System.IO.File.ReadAllText($"{svgFile}"); 

    WeatherAttribution = foreCast.AttributionLine; 
    DayWeatherSummary = foreCast.Response.Daily.Summary; 
    if (foreCast.Response.Currently.Temperature.HasValue) 
        CurrentTemp = 
     Round(foreCast.Response.Currently.Temperature.Value, 
      0).ToString(); 
} 
```

1.  最后但同样重要的是，我们需要向`GetInfo()`方法添加适当的代码。该方法的第一部分涉及查找应用程序正在运行的计算机的系统信息。这显然会根据我们在其上运行.NET Core 应用程序的操作系统而改变：

```cs
public IActionResult GetInfo() 
{ 
    Models.InformationModel model = new Models.InformationModel(); 
    model.OperatingSystem = RuntimeInformation.OSDescription; 
    model.FrameworkDescription = 
     RuntimeInformation.FrameworkDescription; 
    model.OSArchitecture = 
     RuntimeInformation.OSArchitecture.ToString(); 
    model.ProcessArchitecture = 
     RuntimeInformation.ProcessArchitecture.ToString(); 

    string title = string.Empty; 
    string OSArchitecture = string.Empty; 

    if (model.OSArchitecture.ToUpper().Equals("X64")) { 
     OSArchitecture = "64-bit"; } else { OSArchitecture = 
     "32-bit"; } 

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
     title 
     = $"Windows {OSArchitecture}"; } 
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) { 
     title = $"OSX {OSArchitecture}"; } 
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) { 
     title = $"Linux {OSArchitecture}"; } 

    GetLocationInfo().Wait(); 
    model.IPAddressString = PublicIP; 

    GetWeatherInfo().Wait(); 
    model.CurrentIcon = CurrentWeatherIcon; 
    model.WeatherBy = WeatherAttribution; 
    model.CurrentTemperature = CurrentTemp; 
    model.DailySummary = DayWeatherSummary; 
    model.CurrentCity = City; 
    model.UnitOfMeasure = TempUnitOfMeasure; 

    model.InfoTitle = title; 
    return View(model); 
}
```

`GetInfo()`方法的最后一部分涉及确定我们在前面步骤中制作的天气信息。

接下来的工作部分将涉及创建我们的视图。一旦我们完成了这一点，真正的乐趣就开始了。

# GetInfo 视图

将视图放在一起非常简单。除了天气图标之外，我选择了非常简约的方式，但您可以在这里尽情发挥创意：

1.  右键单击`Views`文件夹，然后添加一个名为`Information`的新文件夹。在`Information`文件夹中，通过右键单击文件夹并从上下文菜单中选择添加，然后单击 View...来添加一个名为`GetInfo`的新视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/392dc872-5f29-429c-9e32-c300a7592f36.png)

视图的命名也遵循了 MVC 中使用的命名约定。

请参阅本章前面的*详细项目*部分，以查看显示`Views`文件夹布局的 Visual Studio 解决方案的图像。

已创建的视图使用了 Razor 语法。Razor 是开发人员直接在网页内添加 C#代码（服务器代码）的一种方式。`GetInfo.cshtml`页面内的代码如下：

```cs
@model SystemInfo.Models.InformationModel 

@{ 
    ViewData["Title"] = "GetInfo"; 
} 

<h2> 
    System Information for: @Html.DisplayFor(model => model.InfoTitle)          
</h2> 

<div> 

    <hr /> 
    <dl class="dl-horizontal"> 
        <dt> 
            Operating System 
        </dt>         
        <dd> 
            @Html.DisplayFor(model => model.OperatingSystem)             
        </dd> 
        <dt> 
            Framework Description 
        </dt> 
        <dd> 
            @Html.DisplayFor(model => model.FrameworkDescription) 
        </dd> 
        <dt> 
            Process Architecture 
        </dt> 
        <dd> 
            @Html.DisplayFor(model => model.ProcessArchitecture) 
        </dd>         
        <dt> 
            Public IP 
        </dt> 
        <dd> 
            @Html.DisplayFor(model => model.IPAddressString) 
        </dd>        

    </dl> 
</div> 

<h2> 
    Current Location: @Html.DisplayFor(model => model.CurrentCity) 
</h2> 
<div> 
    <div style="float:left">@Html.Raw(Model.CurrentIcon)</div><div><h3>@Model.CurrentTemperature&deg;@Model.UnitOfMeasure</h3></div> 
</div> 

<div> 
    <h4>@Html.DisplayFor(model => model.DailySummary)</h4> 
</div> 
<div> 
    Weather Info: @Html.DisplayFor(model => model.WeatherBy) 
</div> 
```

正如您所看到的，MVC 将`@model`关键字添加到 Razor 的术语中。通过这样做，您允许视图指定视图的`Model`属性的类型。语法是`@model class`，包含在第一行中，`@model` `SystemInfo.Models.InformationModel`，将视图强类型化为`InformationModel`类。

有了这种灵活性，您可以直接将 C#表达式添加到客户端代码中。

1.  您需要添加的最后一部分代码是在`Views/Shared`文件夹中的`_Layout.cshtml`文件中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2fc9200b-bf77-48d7-a2dd-f26898cde252.png)

我们只是在这里的菜单中添加一个链接，以便导航到我们的`InformationController`类。您会注意到，代码遵循控制器和操作的约定，其中`asp-controller`指定`InformationController`类，`asp-action`指定该控制器内的`GetInfo`方法。

1.  在这个阶段，应用程序应该已经准备好运行。构建它并确保您获得了一个干净的构建。运行应用程序，然后单击信息仪表板菜单项。

信息仪表板将显示它正在运行的计算机信息，以及当前位置的天气信息（或附近位置）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e06fe826-52a5-4d73-9316-dd992810413a.png)

在本章的 Windows 部分，我使用了 Azure，因此服务器位于美国。这就是为什么显示的信息是基于美国的。

1.  最后，让我们来看一下从我们的 Razor 视图生成的 HTML 代码。如果您使用内置的开发者工具（我使用的是 Chrome）并查看页面源代码，您会发现从 Razor 视图创建的 HTML 相当普通：

```cs
<h2> 
    System Information for: Windows 64-bit          
</h2> 

<div> 

    <hr /> 
    <dl class="dl-horizontal"> 
        <dt> 
            Operating System 
        </dt>         
        <dd> 
            Microsoft Windows 10.0.14393              
        </dd> 
        <dt> 
            Framework Description 
        </dt> 
        <dd> 
            .NET Core 4.6.00001.0 
        </dd> 
        <dt> 
            Process Architecture 
        </dt> 
        <dd> 
            X64 
        </dd>         
        <dt> 
            Public IP 
        </dt> 
        <dd> 
            13.90.213.135 
        </dd>        

    </dl> 
</div> 
```

归根结底，这只是 HTML。然而，值得注意的是，我们使用 Razor 来访问我们模型上的属性，并将它们直接放在我们视图的 HTML 中。

# 在 macOS 上运行应用程序

在本章的这一部分，我将假设您正在使用已安装.NET Core 1.1 的 Mac。如果您的 Mac 上没有安装.NET Core，请前往[`www.microsoft.com/net/core#macos`](https://www.microsoft.com/net/core#macos)并按照安装步骤进行安装（或跟随）：

1.  简而言之，从 Windows 的.NET Core 解决方案中，只需发布.NET Core 应用程序。然后，将发布的文件复制到您的 Mac 上。我只是把我的发布文件放在一个名为`netCoreInfoDash`的桌面文件夹中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ac9f3d05-7015-495b-8c70-66299776af27.png)

1.  在您的 Mac 上打开终端，并将工作目录更改为`netCoreInfoDash`文件夹。输入命令`dotnet SystemInfo.dll`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ec98083f-8bc4-48c4-9917-e7532b1588bd.png)

因为该项目是为.NET Core 2.0 创建的，而我们的 Mac 只有.NET Core 1.1，所以我们将在终端中看到以下错误消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7e3e57ef-1ec4-41a4-ae7f-09c5f71c7515.png)

1.  我们需要将 Mac 上的.NET Core 版本更新到 2.0 版。要做到这一点，前往[`www.microsoft.com/net/core#macos`](https://www.microsoft.com/net/core#macos)并安装.NET Core 2.0。

安装.NET Core SDK 非常简单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b63d4f5a-8068-4356-b453-f3f11bb5e9f6.png)

在很短的时间内，.NET Core 2.0 就安装在您的 Mac 上了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/bfdaab9f-2f88-4965-8225-adbddd07312f.png)

1.  回到终端，输入`dotnet SystemInfo.dll`并按*Enter*。这次，您将在终端窗口中看到以下信息输出。您将看到指定了地址`http://localhost:5000`。列出的端口可能会改变，但`5000`通常是给定的端口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b1cd2559-ea7c-429e-b621-53c40c11d9b3.png)

1.  在您的 Mac 上打开浏览器（可以是 Safari，但我使用 Chrome），并导航到—`http://localhost:5000`。您将看到熟悉的应用程序起始页显示出来。如果您点击“信息仪表板”菜单项，您将看到我们创建的页面与在 Windows 机器上显示的完全相同：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c503ed7d-dae5-4827-b646-48d2c6d12c0a.png)

唯一的区别是 Mac 不在 Azure 上，实际上在南非的我的办公室。温度信息已更改为摄氏度，并且显示的机器信息是我的 Mac 的信息。南非这里是一个美好的春天傍晚。

# 在 Linux 上设置应用程序

每个人都在谈论.NET Core 跨平台运行的能力，甚至在 Linux 上也可以。因此，我决定试一试。我知道 Linux 可能不会吸引你们许多人，但能够使用强大的操作系统 Linux 确实有一种明显的满足感。

如果您正在开发.NET Core 应用程序，我建议您为测试目的设置一个 Linux 框。有许多方法可以做到这一点。如果您可以访问 Azure，可以在 Azure 上设置一个 Linux 虚拟机。

您还可以使用虚拟化软件在本地机器上提供一个完全功能的虚拟机。我选择的选项是使用**VirtualBox**，并测试了**Parallels**上的过程。这两种方法都非常简单，但 VirtualBox 是免费使用的，所以这将是一个不错的选择。您可以免费从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载最新版本的 VirtualBox。

你也可以通过从各种在线网站下载现成的 VirtualBox 镜像来节省设置时间。只要确保它们是值得信赖的网站，比如**OS Boxes**在[`www.osboxes.org/virtualbox-images/`](http://www.osboxes.org/virtualbox-images/)。

无论你选择哪种方式，本章的其余部分将假设你已经设置好了你的 Linux 环境，并且准备好设置你的.NET Core 应用程序。

所以让我们看看如何在 Linux 上安装.NET Core：

1.  从[`www.microsoft.com/net/download/linux`](https://www.microsoft.com/net/download/linux)找到安装.NET Core 2.0 的特定 Linux 版本的说明：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0a84828a-443c-458d-a77e-a68bc49fdbb7.png)

1.  我正在使用**Ubuntu 16.04**，点击`sudo apt-get install dotnet-sdk-2.0.0`链接将带我到安装步骤。

1.  通过输入*Ctrl* + *Alt* + *T*在 Linux Ubuntu（或 Linux Mint）上打开终端窗口。

由于我正在运行全新的 Linux，我需要先安装**cURL**。这个工具允许我在服务器和本地机器之间传输数据。

1.  运行以下命令获取 cURL：

```cs
sudo apt-get install curl
```

1.  终端会要求输入密码。在屏幕上输入密码不会有任何显示，但继续输入并按*Enter*：

当你在 Linux 上工作时，屏幕上不显示你输入的密码是有意设计的。这是一个特性。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/238b9dd6-ea4d-4fa2-9b77-b9b37a2dec66.png)

1.  现在，我们需要注册受信任的 Microsoft 签名密钥。输入以下内容：

```cs
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
```

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7ba9167c-cfa0-47e2-8276-5f3647615c80.png)

1.  当这个完成时，输入以下内容：

```cs
    sudo mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
```

1.  现在，我们需要为 Ubuntu 16.04 注册 Microsoft 产品源。要做到这一点，请输入以下内容：

```cs
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-xenial-prod xenial main" > /etc/apt/sources.list.d/dotnetdev.list'
```

1.  然后，在那之后，输入以下内容：

```cs
    sudo apt-get update
```

1.  现在，我们可以通过输入以下内容来安装.NET Core 2.0 SDK：

```cs
    sudo apt-get install dotnet-sdk-2.0.0
```

1.  终端问我们是否要继续，我们要。所以，输入`Y`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6637c3ca-6c08-4303-8e0a-8030ed021670.png)

当这个过程完成时，你会看到光标准备好在`~$`旁边输入：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/596c89d6-1133-417a-9826-cf6866f3f434.png)

1.  要检查安装了哪个版本的.NET Core，请输入以下命令：

```cs
    dotnet --version  
```

1.  这应该显示 2.0.0。我们现在在我们的 Linux 机器上安装了.NET Core 2.0。作为一个快速开始，创建一个名为`testapp`的新目录，并通过输入以下内容将你的工作目录更改为`testapp`目录：

```cs
    mkdir testapp
    cd testapp  
```

考虑以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e59a2cb7-4e9b-4e4c-971b-b4205f046ee4.png)

1.  我们只是想看看.NET Core 是否在我们的 Linux 机器上工作，所以当你在`testapp`目录中时，输入以下内容：

```cs
    dotnet new razor
```

是的，就是这么简单。这刚刚在 Linux 上为我们创建了一个新的 MVC Web 项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ce22123e-4dfd-4512-ab10-45613f438473.png)

1.  就像我们在 Mac 上做的那样，输入以下命令：

```cs
    dotnet run  
```

看一下以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/30d2d43e-713b-4cda-a2a6-c1b0adea6372.png)

1.  在终端的输出中，你会注意到本地主机显示了相同的端口号。与 macOS 不同，在 Ubuntu 上我可以在终端窗口中点击`http://localhost:5000`。这将打开我们刚刚创建的应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/06247e66-347f-494b-98e1-d618a8e97e3c.png)

现在我们知道.NET Core 2.0 在 Linux 上正常运行了，让我们把项目文件复制到我们的 Linux 机器上：

1.  在桌面上创建一个文件夹；你可以随意命名。将.NET Core 应用程序的项目文件复制到该文件夹中（不要将发布的文件复制到此文件夹中）：

你会记得在 macOS 上，我们只复制了发布的文件。但在 Linux 上是不同的。在这里，你需要复制所有的项目文件。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/ae9ec898-2504-4f9d-bf4c-bba33f9d63f3.png)

1.  右键单击文件夹，选择在终端中打开。

现在我们在包含我们解决方案文件的文件夹中，输入以下内容：

```cs
    dotnet restore  
```

这个命令恢复了我们项目的依赖和工具：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/35fb27ba-59f9-4336-8443-c916776a7fbd.png)

1.  因为我们正在处理解决方案文件，所以我需要向下导航一个文件夹并输入以下内容：

```cs
dotnet run
```

看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/90b9e971-656c-4fda-83cb-e0bb7c91da44.png)

1.  导航到`http://localhost:50240`在终端窗口中显示，将我带到我的应用程序的起始页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a7261740-3045-486f-b517-99bf2ae47acb.png)

1.  点击信息仪表板菜单项将带我们到我们创建的页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b6709a9b-66d2-48ce-b661-f34c9fbd3862.png)

这就是全部。我们在 Windows PC 上使用 Visual Studio 2017 Enterprise 创建了一个 ASP.NET Core MVC 应用程序，该应用程序正在 Linux 机器上运行。最好的是，我们没有改变一行代码就让我们的应用程序在不同的平台上运行。

# 总结

回顾本章，我们看了一下在 Windows 上设置 ASP.NET Core 应用程序。我们看了添加视图和控制器，如果你熟悉 ASP.NET MVC，那么你会感到非常亲切。如果不熟悉，ASP.NET MVC 真的很容易。

最后，我们看了一下.NET Core 的强大之处，通过在 Windows、macOS 和 Linux 上运行相同的应用程序。

现在你应该明白.NET Core 的强大之处了。它允许开发人员使用.NET 编写真正的跨平台应用程序。这项技术是一个改变游戏规则的东西，每个开发人员都必须掌握。

接下来，你可能会想知道当我们想要将数据库连接到.NET Core 应用程序时，我们需要做什么。在下一章中，我们将看看如何在 ASP.NET Core MVC 应用程序上使用 MongoDB。

你可能会想为什么我们要使用 MongoDB？嗯，MongoDB 是免费的、开源的和灵活的。再说，我们为什么不想使用 MongoDB 呢？下一章见！


# 第四章：任务错误日志 ASP .NET Core MVC 应用程序

在这一章中，我们将通过创建一个任务/错误日志应用程序来看看如何在 ASP.NET Core MVC 中使用 MongoDB。个人任务管理器很有用，当你无法立即处理错误时，记录错误尤其方便。

在本章中，我们将涵盖以下主题：

+   在本地机器上设置 MongoDB

+   首次使用 MongoDB Compass

+   创建一个 ASP.NET Core MVC 应用程序并集成 MongoDB

你可能会想知道为什么我们会选择 MongoDB。你需要问的问题是，你想要花多少精力来创建一个简单的应用程序？

# 使用 MongoDB 的好处是什么？

为了回答这个问题，让我们来看看使用 MongoDB 的好处。

# 使用 MongoDB 可以加快开发速度

这可能在你的开发过程中变得更清晰，但让我们说一下，我不喜欢开发过程中的一部分是不得不为各种表单和字段创建数据表。你有没有不得不创建一个表来存储地址字段信息？没错，你需要添加类似以下的内容：

+   地址 1

+   地址 2

+   地址 3

+   地址 4

+   城市

+   状态

+   邮编

+   国家

这个表显然可以变得非常庞大。这取决于你需要存储什么。使用 MongoDB，你只需要传递地址数组。MongoDB 会处理剩下的事情。不再需要费力地创建表语句。

# 提升职业技能

越来越多的职业网站将 MongoDB 列为一个受欢迎的技能。它在公司中被更频繁地使用，新开发人员被期望具有一些 MongoDB 的经验。在 LinkedIn 的职位门户上快速搜索 MongoDB 关键词，仅在美国就返回了 7800 个工作。拥有 MongoDB 经验是一个很好的职业助推器，特别是如果你习惯使用 SQL Server。

# MongoDB 在行业中排名很高

为了进一步证明我的观点，MongoDB 在 DB-Engines 网站上排名第五（[`db-engines.com/en/ranking`](https://db-engines.com/en/ranking)），在文档存储类别下排名第一（[`db-engines.com/en/ranking/document+store`](https://db-engines.com/en/ranking/document+store)）。

这些统计数据在撰写时是正确的。事实上，MongoDB 的排名一直在稳步增长。

很明显，MongoDB 会一直存在，更重要的是，社区喜爱 MongoDB。这非常重要，因为它创造了一个健康的开发者社区，分享关于 MongoDB 的知识和文章。MongoDB 的广泛采用推动了技术的发展。

# 在本地机器上设置 MongoDB

前往[`www.mongodb.com/download-center#community`](https://www.mongodb.com/download-center#community)并下载 Windows 的最新版本的 MongoDB Community Server。安装程序然后给你安装 MongoDB Compass 的选项。

你也可以从上述链接或直接导航到[`www.mongodb.com/download-center?jmp=nav#compass`](https://www.mongodb.com/download-center?jmp=nav#compass)下载 Compass 作为单独的安装程序。

[`www.mongodb.com/download-center?jmp=nav#compass`](https://www.mongodb.com/download-center?jmp=nav#compass)。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/f2058a67-525c-4618-8692-0858423adc51.png)

查看 MongoDB Compass 的网页，[`docs.mongodb.com/compass/master/`](https://docs.mongodb.com/compass/master/)，MongoDB Compass 的描述非常清晰：

"MongoDB Compass 旨在允许用户轻松分析和理解 MongoDB 中数据集合的内容，并执行查询，而无需了解 MongoDB 查询语法。

MongoDB Compass 通过随机抽样数据集合中的一部分文档，为用户提供了 MongoDB 模式的图形视图。抽样文档可以最小化对数据库的性能影响，并可以快速产生结果。"

如果这是你第一次使用 MongoDB，我建议你安装 MongoDB Compass 并试着玩一下。

安装 MongoDB 后，您将在`C:\ProgramFiles\MongoDB`下找到它。我现在想做的是将完整的安装路径保存在一个环境变量中。这样可以更容易地从 PowerShell 或命令提示符中访问。`bin`文件夹的完整安装路径是`C:\Program\FilesMongoDBServer3.6bin`。

为了设置它，我们执行以下步骤：

1.  打开系统属性屏幕，然后单击“环境变量”按钮。

1.  在“系统变量”组下，选择“Path”变量，然后单击“编辑”按钮。将完整的安装路径添加到“Path”系统变量中。

1.  现在，我们需要去创建一个文件夹来存储 MongoDB 数据库。您可以在任何地方创建此文件夹，但无论您在哪里创建它，都需要在下一步中使用它。我在以下路径创建了我的 MongoDB 数据库文件夹：`D:\MongoTask`。

1.  要使用 MongoDB，您必须首先启动 MongoDB 服务器。无论这是在远程机器上还是在本地机器上都无所谓。打开 PowerShell 并运行以下命令：

```cs
     mongod -dbpath D:MongoTask
```

1.  运行上述命令后，按 Enter 键。您现在已经启动了 MongoDB 服务器。接下来，启动 MongoDB Compass。

1.  您会发现您还没有任何数据库。单击“创建数据库”按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c6e9c5b2-40fc-492a-bb6b-c2fbdb7dfe49.png)

1.  打开“创建数据库”窗口，在“数据库名称”下指定数据库名称，在“集合名称”下指定集合名称。

1.  最后，单击屏幕底部的“创建数据库”按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/fa9a7a71-3c48-455b-a3c1-d82bf147e79c.png)

1.  您会看到一个名为`TaskLogger`的新数据库已经创建，如果展开`TaskLogger`数据库节点，您将看到列出的 TaskItem 文档，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c1151c45-1839-4ab0-8384-061d3e43158b.png)

在本章中，我们不会过多关注 MongoDB Compass。目前，我想向您展示使用 MongoDB Compass 可以以可视化的方式管理 MongoDB 数据库。您可以继续并删除刚刚创建的 TaskItem 文档。稍后，您将看到，当您第一次向 MongoDB 数据库中插入数据时，应用程序会自动为您创建一个文档。

# 将您的 ASP.NET Core MVC 应用程序连接到 MongoDB

谈到在应用程序中使用 MongoDB 时，人们想知道将这个功能添加到新的 ASP.NET Core MVC 应用程序有多容易。这个过程真的很简单。首先，创建一个新的 ASP.NET Core Web 应用程序，并将其命名为`BugTracker`：

1.  在“新 ASP.NET Core Web 应用程序-BugTracker”屏幕上，确保您已从下拉列表中选择了 ASP.NET Core 2.0。

1.  选择 Web 应用程序（模型-视图-控制器）。

1.  取消选中启用 Docker 支持选项。最后，单击“确定”按钮。

1.  您的新 ASP.NET Core MVC 应用程序将以基本形式创建，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a5f8fef9-5bac-4bba-bfff-0e7836698341.png)

1.  在创建时可以轻松地为应用程序启用 Docker 支持。您还可以为现有应用程序启用 Docker 支持。

我将在后面的章节中介绍 Docker 以及如何使您的应用程序与 Docker 配合使用。目前，我们的应用程序不需要 Docker 支持。将其取消选中，并按照通常的方式创建您的应用程序。

# 添加 NuGet 包

由于本章主要讨论 MongoDB，我们需要将其添加到我们的项目中。最佳方法是通过添加 NuGet 包来实现。我们可以按照以下步骤进行：

1.  右键单击您的项目，然后从上下文菜单中选择“管理 NuGet 包...”，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0afe2b1b-7b07-46fc-85b6-dfad02aab8aa.png)

1.  在 NuGet 屏幕上，您将选择“浏览”选项卡，并输入`Mongodb.Driver`作为搜索词。

1.  选择 MongoDB.Driver by MongoDB 选项。

1.  单击“安装”按钮将最新的稳定包添加到您的项目中。如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/42c747f8-e3a4-47fe-83b2-cf6706877531.png)

1.  您可以在 Visual Studio 的输出窗口中查看进度。

1.  在将 MongoDB 添加到项目后，您将看到 MongoDB.Driver（2.5.0）添加到项目的 NuGet 依赖项下，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/373bfb37-72fc-4375-9935-fea10482b517.png)

1.  展开`Controllers`文件夹。您会看到，默认情况下，Visual Studio 已经创建了一个`HomeController.cs`文件。该文件中的代码应该类似于以下内容：

```cs
public class HomeController : Controller 
{ 
    public IActionResult Index() 
    { 
        return View(); 
    } 

    public IActionResult About() 
    { 
        ViewData["Message"] = "Your application description   
        page."; 

        return View(); 
    } 

    public IActionResult Contact() 
    { 
        ViewData["Message"] = "Your contact page."; 

        return View(); 
    } 

    public IActionResult Error() 
    { 
        return View(new ErrorViewModel { RequestId = 
         Activity.Current?.Id ?? HttpContext.TraceIdentifier }); 
    } 
} 
```

我们希望能够从这里连接到 MongoDB，因此让我们创建一些代码来连接到 Mongo 客户端。

您需要向您的类添加一个`using`语句，如下所示：

`using MongoDB.Driver;`

连接到 MongoDB 的步骤如下：

1.  通过键入片段短代码`ctor`并按两次制表键，或者通过明确键入代码来创建构造函数。您的构造函数需要创建`MongoClient`的新实例。完成后，您的代码应如下所示：

```cs
public HomeController() 
{ 
    var mclient = new MongoClient(); 
} 
```

1.  为了使`MongoClient`工作，我们需要为其提供一个连接字符串，以连接到我们创建的 MongoDB 实例。在“Bug Tracker”窗格的解决方案中打开`appsettings.json`文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/04e1852e-af64-4842-b6a5-cc23b490dca1.png)

1.  打开您的`appsettings.json`文件，它应该如下所示：

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

1.  修改文件并添加 MongoDB 连接详细信息，如下所示：

```cs
{ 
  "MongoConnection": { 
    "ConnectionString": "mongodb://localhost:27017", 
    "Database": "TaskLogger" 
  }, 
  "Logging": { 
    "IncludeScopes": false, 
    "LogLevel": { 
      "Default": "Warning" 
    } 
  } 
}
```

1.  现在我们要在`Models`文件夹中创建一个`Settings.cs`文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/89ad457a-5767-4615-83c8-723e5e77eabc.png)

1.  打开`Settings.cs`文件并将以下代码添加到其中：

```cs
public class Settings 
{ 
    public string ConnectionString { get; set; } 
    public string Database { get; set; } 
} 
```

1.  现在我们需要打开`Startup.cs`文件并修改`ConfigureServices`方法，如下所示以注册服务：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 
    services.AddMvc(); 

    services.Configure<Settings>(Options => 
    { 
        Options.ConnectionString = Configuration.GetSection
          ("MongoConnection:ConnectionString").Value; 
        Options.Database = Configuration.GetSection
         ("MongoConnection:Database").Value; 
    }); 

} 
```

1.  返回`HomeController.cs`文件并修改构造函数以将连接字符串传递给`MongoClient`：

```cs
public HomeController(IOptions<Settings> settings) 
{             
    var mclient = new 
     MongoClient(settings.Value.ConnectionString);     
} 
```

1.  此时，我想测试我的代码，以确保它实际访问我的 MongoDB 实例。为此，修改您的代码以返回集群描述：

```cs
IMongoDatabase _database; 

public HomeController(IOptions<Settings> settings) 
{             
    var mclient = new 
     MongoClient(settings.Value.ConnectionString);             
      _database = mclient.GetDatabase(settings.Value.Database); 
} 

public IActionResult Index() 
{ 
    return Json(_database.Client.Cluster.Description); 
}
```

1.  运行您的 ASP.NET Core MVC 应用程序，并在浏览器中查看输出的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/8e9435f8-0664-4f2f-afbc-49856662cf2d.png)

这一切都很好，但让我们看看如何将添加数据库连接的逻辑分离到自己的类中。

# 创建 MongoDbRepository 类

要创建`MongoDbRepository`类，我们需要执行以下步骤：

1.  在您的解决方案中创建一个名为`Data`的新文件夹。在该文件夹中，创建一个名为`MongoDBRepository`的新类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/9b98d23d-ef88-47ce-8300-b4a97979aaf0.png)

1.  在这个类中，添加以下代码：

```cs
public class MongoDBRepository 
{ 
    public readonly IMongoDatabase Database; 

    public MongoDBRepository(IOptions<Settings> settings) 
    { 
        try 
        { 
            var mclient = new 
             MongoClient(settings.Value.ConnectionString); 
            Database = 
             mclient.GetDatabase(settings.Value.Database); 
        } 
        catch (Exception ex) 
        { 
            throw new Exception("There was a problem connecting 
             to the MongoDB database", ex); 
        } 
    } 
} 
```

如果代码看起来很熟悉，那是因为它与我们在`HomeController.cs`类中编写的相同代码，只是这次有一些错误处理，并且它在自己的类中。这意味着我们还需要修改`HomeController`类。

1.  更改`HomeController`的构造函数中的代码以及`Index`操作。您的代码需要如下所示：

```cs
public MongoDBRepository mongoDb; 

public HomeController(IOptions<Settings> settings) 
{             
    mongoDb =  new MongoDBRepository(settings); 
} 
public IActionResult Index() 
{ 
    return Json(mongoDb.Database.Client.Cluster.Description); 
} 
```

1.  再次运行您的应用程序，您将在浏览器中看到先前显示的相同信息，因此再次输出到浏览器窗口。

唯一的区别是现在代码已经适当分离并且易于重用。因此，如果以后发生任何更改，只需在此处更新即可。

# 读取和写入数据到 MongoDB

在本节中，我们将看一下如何从 MongoDB 数据库中读取工作项列表，以及如何将新的工作项插入到数据库中。我称它们为工作项，因为工作项可以是任务或错误。可以通过执行以下步骤来完成：

1.  在 Models 文件夹中，创建一个名为`WorkItem`的新类，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e40dd635-6092-48ce-bbe6-1ebdd4aecfb5.png)

1.  将以下代码添加到`WorkItem`类中。您会注意到`Id`的类型是`ObjectId`。这代表了在 MondoDB 文档中创建的唯一标识符。

您需要确保将以下`using`语句添加到您的`WorkItem`类`using MongoDB.Bson;`。

查看以下代码：

```cs
public class WorkItem 
{ 
    public ObjectId Id { get; set; } 
    public string Title { get; set; } 
    public string Description { get; set; } 
    public int Severity { get; set; } 
    public string WorkItemType { get; set; } 
    public string AssignedTo { get; set; } 
}
```

1.  接下来，打开`MongoDBRepository`类并将以下属性添加到类中：

```cs
public IMongoCollection<WorkItem> WorkItems 
{ 
    get 
    { 
        return Database.GetCollection<WorkItem>("workitem"); 
    } 
} 
```

1.  由于我们至少使用 C# 6，我们可以通过将`WorkItem`属性更改为**表达式主体属性**来进一步简化代码。为此，将代码更改为如下所示：

```cs
public IMongoCollection<WorkItem> WorkItems => Database.GetCollection<WorkItem>("workitem"); 
```

1.  如果这看起来有点混乱，请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e5ea5b8d-a7ab-4ba7-b8d3-4b659c5d3e88.png)

花括号、`get`和`return`语句被`=>`lambda 运算符替换。被返回的对象（在这种情况下是`WorkItem`对象的集合）放在 lambda 运算符之后。这导致了**表达式主体属性**。

# 创建接口和 Work ItemService

接下来，我们需要创建一个接口。为此，我们需要执行以下步骤：

1.  在解决方案中创建一个名为 Interfaces 的新文件夹，并在 Interfaces 文件夹中添加一个名为`IWorkItemService`的接口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/cf94d147-351b-4b07-b4e5-7f07278d10be.png)

1.  将以下代码添加到`IWorkItemService`接口中：

```cs
public interface IWorkItemService 
{ 
    IEnumerable<WorkItem> GetAllWorkItems(); 
}
```

1.  在您的`Data`文件夹中，添加另一个名为`WorkItemService`的类，并使其实现`IWorkItemService`接口。

确保添加`using`语句以引用您的接口。在我的示例中，这是`using BugTracker.Interfaces;`语句。

1.  您会注意到 Visual Studio 提示您实现接口。要做到这一点，单击灯泡提示，然后单击上下文菜单中的 Implement interface，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/213bdf35-7625-4317-9da5-d869f222271e.png)

1.  完成此操作后，您的`WorkItemService`类将如下所示：

```cs
public class WorkItemService : IWorkItemService 
{ 
    public IEnumerable<WorkItem> GetAllWorkItems() 
    { 
        throw new System.NotImplementedException(); 
    } 
}
```

1.  接下来，添加一个构造函数并完成`GetAllWorkItems`方法，使您的类如下所示：

```cs
public class WorkItemService : IWorkItemService 
{ 
    private readonly MongoDBRepository repository; 

    public WorkItemService(IOptions<Settings> settings) 
    { 
        repository = new MongoDBRepository(settings); 
    } 

    public IEnumerable<WorkItem> GetAllWorkItems() 
    { 
        return repository.WorkItems.Find(x => true).ToList(); 
    } 
} 
```

1.  现在，您需要打开`Startup.cs`文件并编辑`ConfigureServices`方法以添加以下代码行：

```cs
services.AddScoped<IWorkItemService, WorkItemService>(); 
```

1.  您的`ConfigureServices`方法现在将如下所示：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 
    services.AddMvc(); 

    services.Configure<Settings>(Options => 
    { 
        Options.ConnectionString = Configuration.GetSection("MongoConnection:ConnectionString").Value; 
        Options.Database = Configuration.GetSection("MongoConnection:Database").Value; 
    }); 

    services.AddScoped<IWorkItemService, WorkItemService>(); 
} 
```

您所做的是将`IWorkItemService`接口注册到依赖注入框架中。有关依赖注入的更多信息，请参阅以下文章：

[`docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection)。

# 创建视图

当我们启动应用程序时，我们希望看到一个工作项列表。因此，我们需要为`HomeController`创建一个视图，以执行以下步骤显示工作项列表：

1.  在 Views 文件夹中，展开 Home 子文件夹，如果有`Index.cshtml`文件，则删除它。

1.  然后，右键单击 Home 文件夹，导航到上下文菜单中的 Add | View。将显示 Add MVC View 窗口。

1.  将视图命名为`Index`，并选择 List 作为模板。从 Model 类的下拉列表中，选择 WorkItem（BugTracker.Models）。

1.  将其余设置保持不变，然后单击添加按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7266ff9d-5940-404f-a7c1-d6e211246be2.png)

添加视图后，您的 Solution Explorer 将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7ca01f37-10d1-4b96-90d3-662e151187ee.png)

1.  仔细观察视图，您会注意到它使用`IEnumerable<BugTracker.Models.WorkItem>`作为模型：

```cs
@model IEnumerable<BugTracker.Models.WorkItem> 

@{ 
    ViewData["Title"] = "Work Item Listings"; 
} 
```

这允许我们迭代返回的`WorkItem`对象集合并在列表中输出它们。还请注意，`ViewData["Title"]`已从`Index`更新为`Work Item Listings`。

# 修改 HomeController

在我们运行应用程序之前，我们需要做的最后一件事是修改`HomeController`类以与`IWorkItemService`一起使用：

1.  修改构造函数和`Index`操作如下：

```cs
private readonly IWorkItemService _workItemService; 

public HomeController(IWorkItemService workItemService) 
{ 
    _workItemService = workItemService; 

} 

public IActionResult Index() 
{ 
    var workItems = _workItemService.GetAllWorkItems(); 
    return View(workItems); 
} 
```

1.  我们正在从 MongoDB 数据库中获取所有工作项，并将它们传递给视图以供模型使用。

确保您已经通过`mongod -dbpath <path>`命令格式启动了 MongoDB 服务器，就像本章前面解释的那样。

1.  完成后，运行您的应用程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3d21b20a-0bdc-4111-8591-b0b5738ef98d.png)

1.  此时，数据库中没有工作项，所以我们在浏览器中看到了这个空列表。接下来，我们将添加代码将工作项插入到我们的 MongoDB 数据库中。

# 添加工作项

让我们通过以下步骤添加工作项：

1.  要添加工作项，让我们首先在我们的 Models 文件夹中添加一个名为`AddWorkItem`的类，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/8ffb9df0-c730-4d32-9669-db8f462acfa1.png)

1.  修改类中的代码，使其基本上看起来像`WorkItem`类：

```cs
public class AddWorkItem 
{ 
    public string Title { get; set; } 
    public string Description { get; set; } 
    public int Severity { get; set; } 
    public string WorkItemType { get; set; } 
    public string AssignedTo { get; set; } 
}
```

1.  接下来，在 Views 文件夹下创建一个名为`AddWorkItem`的新文件夹。右键单击`AddWorkItem`文件夹，然后选择添加，然后在上下文菜单中单击“View”。

1.  将显示“添加 MVC 视图”窗口。将视图命名为`AddItem`，并选择“模板”中的“创建”。

1.  从 Model 类的下拉菜单中，选择 AddWorkItem（BugTracker.Models）。

1.  将其余设置保持不变，然后点击“添加”按钮，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/af962b1f-a9e3-47ae-9aba-20d27290b348.png)

1.  打开`AddItem.cshtml`文件，查看表单操作。确保它设置为`CreateWorkItem`。以下代码片段显示了代码应该是什么样子的：

```cs
<div class="row"> 
  <div class="col-md-4"> 
     <form asp-action="CreateWorkItem"> 
         <div asp-validation-summary="ModelOnly" class="text-danger"></div> @*Rest of code omitted for brevity*@ 
```

您的`Views`文件夹现在应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/1281dbd3-9bd8-4ece-a456-46445fd8acd7.png)

1.  现在，我们需要对我们的`IWorkItemService`接口进行一些小修改。修改接口中的代码如下所示：

```cs
public interface IWorkItemService 
{ 
    IEnumerable<WorkItem> GetAllWorkItems(); 
    void InsertWorkItem(WorkItem workItem); 
} 
```

我们刚刚指定实现`IWorkItemService`接口的类必须具有一个名为`InsertWorkItem`的方法，该方法接受`WorkItem`类型的参数。这意味着我们需要转到`WorkItemService`并添加一个名为`InsertWorkItem`的方法。我们的`WorkItemService`接口中的代码将如下所示：

```cs
private readonly MongoDBRepository repository; 

public WorkItemService(IOptions<Settings> settings) 
{ 
    repository = new MongoDBRepository(settings); 
} 

public IEnumerable<WorkItem> GetAllWorkItems() 
{ 
    return repository.WorkItems.Find(x => true).ToList(); 
} 

public void InsertWorkItem(WorkItem workItem) 
{ 
    throw new System.NotImplementedException(); 
} 
```

1.  更改`InsertWorkItem`方法以将`WorkItem`类型的单个对象添加到我们的 MongoDB 数据库中。更改代码如下所示：

```cs
public void InsertWorkItem(WorkItem workItem) 
{ 

} 
```

1.  现在，我们需要稍微修改我们的`WorkItem`类。向类中添加两个构造函数，一个带有`AddWorkItem`对象作为参数，另一个不带任何参数：

```cs
public class WorkItem 
{ 
    public ObjectId Id { get; set; } 
    public string Title { get; set; } 
    public string Description { get; set; } 
    public int Severity { get; set; } 
    public string WorkItemType { get; set; } 
    public string AssignedTo { get; set; } 

    public WorkItem() 
    { 

    } 

    public WorkItem(AddWorkItem addWorkItem) 
    { 
        Title = addWorkItem.Title; 
        Description = addWorkItem.Description; 
        Severity = addWorkItem.Severity; 
        WorkItemType = addWorkItem.WorkItemType; 
        AssignedTo = addWorkItem.AssignedTo; 
    } 
} 
```

我们添加第二个不带参数的构造函数的原因是为了让 MongoDB 反序列化`WorkItem`。

如果您想进一步了解为什么为反序列化添加一个无参数构造函数，请查看以下网址：[`stackoverflow.com/questions/267724/why-xml-serializable-class-need-a-parameterless-constructor`](https://stackoverflow.com/questions/267724/why-xml-serializable-class-need-a-parameterless-constructor)。

1.  现在我们需要向我们的项目添加另一个控制器。右键单击 Controllers 文件夹，然后添加一个名为`AddWorkItemController`的新控制器。随意将其添加为空控制器。我们将在下面自己添加代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d48a7da2-27c7-42bd-ac09-012a3f22f18a.png)

1.  在 AddWorkItemController 控制器中，添加以下代码：

```cs
private readonly IWorkItemService _workItemService; 

public AddWorkItemController(IWorkItemService workItemService) 
{ 
    _workItemService = workItemService; 
} 

public ActionResult AddItem() 
{ 
    return View(); 
} 

[HttpPost] 
public ActionResult CreateWorkItem(AddWorkItem addWorkItem) 
{ 
    var workItem = new WorkItem(addWorkItem); 
    _workItemService.InsertWorkItem(workItem); 
    return RedirectToAction("Index", "Home"); 
} 
```

您会注意到`HttpPost`操作被称为`CreateWorkItem`。这就是`AddItem.cshtml`文件中的表单操作称为`CreateWorkItem`的原因。它告诉视图在单击创建按钮时要调用控制器上的哪个操作。

# 重定向到工作项列表

另一个有趣的事情要注意的是，在我们调用`WorkItemService`上的`InsertWorkItem`方法之后，我们将视图重定向到`HomeController`上的`Index`操作。正如我们已经知道的，这将带我们到工作项列表：

1.  说到`HomeController`，修改那里的代码以添加另一个名为`AddWorkItem`的操作，该操作调用`AddWorkItemController`类上的`AddItem`操作：

```cs

public ActionResult AddWorkItem() 
{ 
    return RedirectToAction("AddItem", "AddWorkItem"); 
} 
Your HomeController code will now look as follows: 
private readonly IWorkItemService _workItemService; 

public HomeController(IWorkItemService workItemService) 
{ 
    _workItemService = workItemService;             
} 

public IActionResult Index() 
{ 
    var workItems = _workItemService.GetAllWorkItems(); 
    return View(workItems); 
} 

public ActionResult AddWorkItem() 
{ 
    return RedirectToAction("AddItem", "AddWorkItem"); 
} 
```

1.  现在，让我们稍微修改`Index.cshtml`视图。为了使“Index”视图上的列表更直观，修改`Index.cshtml`文件。

1.  添加一个`if`语句，以允许在列表为空时添加新的工作项。

1.  添加一个`ActionLink`，在单击时调用`HomeController`上的`AddWorkItem`操作：

```cs
@if (Model.Count() == 0)
@if (Model.Count() == 0)
{
    <tr>
        <td colspan="6">There are no Work Items in BugTracker. @Html.ActionLink("Add your first Work Item", "AddWorkItem") now.</td>
    </tr>
}
else
{

    @foreach (var item in Model)
    {
        <tr>
            <td>
                @Html.DisplayFor(modelItem => item.Title)
            </td>
            <td>
                @Html.DisplayFor(modelItem => item.Description)
            </td>
            <td>
                @Html.DisplayFor(modelItem => item.Severity)
            </td>
            <td>
                @Html.DisplayFor(modelItem => item.WorkItemType)
            </td>
            <td>
                @Html.DisplayFor(modelItem => item.AssignedTo)
            </td>
            <td>
            @Html.ActionLink("Edit", "Edit", new { /* 
             id=item.PrimaryKey */ }) |
            @Html.ActionLink("Details", "Details", new { /* 
             id=item.PrimaryKey */ }) |
            @Html.ActionLink("Delete", "Delete", new { /* 
             id=item.PrimaryKey */ })
            </td>
        </tr>
   }
}

```

1.  现在，将“Create New `asp-action`”包装在以下`if`语句中：

```cs
@if (Model.Count() > 0) 
{ 
<p> 
    <a asp-action="Create">Create New</a> 
</p> 
} 
```

我们稍后会看到这个。

在这一点上，我们将看到应用程序的逻辑，`HomeController``Index`操作列出了工作项。当我们单击“添加您的第一个工作项”链接时，我们调用了`HomeController`上的`AddWorkItem`操作。

`HomeController`上的`AddWorkItem`操作反过来调用`AddWorkItemController`上的`AddItem`操作。这只是返回`AddItem`视图，我们在其中输入工作项详细信息，然后单击“创建”按钮。

“创建”按钮反过来执行`HttpPost`，因为`AddItem`视图上的表单操作指向`AddWorkItemController`类上的`CreateWorkItem`操作，我们将工作项插入到我们的 MongoDB 数据库中，并通过执行`RedirectToAction`调用到`HomeController`上的`Index`操作重定向到工作项列表。

现在，在这一点上，如果您认为这是一个冗长的方式，将重定向回`HomeController`，然后重定向到`AddWorkItemController`上的`AddItem`操作，那么您是 100%正确的。我将向您展示一种快速的方法，当用户单击链接创建新工作项时，直接重定向到`AddWorkItemController`上的`AddItem`操作。现在，只需跟着我。我试图向您展示如何与控制器和操作进行交互。

现在，再次运行您的应用程序。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/b8ea9353-3b96-4109-a95a-835ffcb90cae.png)

您将看到列表中的一个链接允许您添加您的第一个工作项。

这是将重定向回`HomeController`上的`AddWorkItem`操作的链接。要运行它，请执行以下操作：

1.  单击链接，您将看到输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/20e97ab4-49a6-4a65-b97a-93566fee6be8.png)

1.  这将带您到添加新工作项的视图。在字段中输入一些信息，然后单击“创建”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c0c002c6-dc56-4a86-a511-3cc163e337c0.png)

1.  “创建”按钮调用`AddWorkItemController`上的`CreateWorkItem`操作，并在`HomeController`的`Index`操作上重定向回工作项列表。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/dd47eb65-9e94-497e-829a-e3c566be2891.png)

1.  您可以看到“创建新”链接现在显示在列表顶部。让我们修改“Index.cshtml”视图，使该链接直接重定向到`AddWorkItemController`类上的`AddItem`操作。更改 Razor 如下：

```cs
@if (Model.Count() > 0) 
{ 
<p> 
    @Html.ActionLink("Create New", "AddWorkItem/AddItem") 
</p> 
} 
```

您可以看到我们可以指定应用程序必须采取的路由以到达正确的操作。在这种情况下，我们说当单击“创建新”链接时，我们必须调用`AddWorkItemController`类上的`AddItem`操作。

再次运行您的应用程序，然后单击“创建新链接”。您会看到被重定向到我们之前添加工作项的输入表单。

视图的默认样式看起来不错，但肯定不是最美丽的设计。至少，这使您作为开发人员有能力返回并使用 CSS 样式屏幕，根据您的需求“美化”它们。目前，这些沉闷的屏幕完全功能，并且足够满足我们的需求。

打开 MongoDB Compass，您会看到那里有一个工作项文档。查看该文档，您将看到我们刚刚从 ASP.NET Core MVC 应用程序中添加的信息。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/1a35ffc6-26e6-444f-8c91-5f0190f7a1fc.png)

# 总结

在本章中，我们看了一下：

+   在本地机器上设置 MongoDB

+   使用 MongoDB Compass

+   创建连接到 MongoDB 的 ASP.NET Core MVC 应用程序

我们看到 MongoDB Compass 为开发人员提供了 MongoDB 数据的良好图形视图。因此，开发人员不需要了解任何 MongoDB 查询语法。但是，如果你想查看查询语法，请访问`https://docs.mongodb.com/manual/tutorial/query-documents/`。

在涉及 MongoDB 和 ASP.NET Core MVC 时，仍然有很多东西可以学习。单独一章几乎不足以涵盖所有内容。但可以肯定的是，MongoDB 非常强大，同时在应用程序中使用起来非常简单。MongoDB 有很好的文档，并且有一个蓬勃发展的社区可以在你的学习过程中提供帮助和指导。

在下一章中，我们将看一下 SignalR 以及如何创建实时聊天应用程序。


# 第五章：ASP.NET SignalR 聊天应用程序

想象一下，您有能力让服务器端代码实时推送数据到您的网页，而无需用户刷新页面。他们说，有很多种方法可以解决问题，但 ASP.NET SignalR 库为开发人员提供了一种简化的方法，可以向应用程序添加实时网络功能。

为了展示 SignalR 的功能，我们将构建一个简单的 ASP.NET Core SignalR 聊天应用程序。这将包括使用 NuGet 和**Node Package Manager**（**npm**）将所需的包文件添加到项目中。

在这一章中，我们将研究以下内容：

+   整体项目布局

+   设置项目

+   添加 SignalR 库

+   构建服务器

+   创建客户端

+   解决方案概述

+   运行应用程序

让我们开始吧。

# 项目布局

对于这个项目，我们需要以下元素：

+   **聊天服务器**：这将是我们的服务器端 C#代码，用于处理和指导从客户端发送的消息

+   **聊天客户端**：客户端将包括用于向服务器发送消息和接收消息的 JavaScript 函数，以及用于显示的 HTML 元素

我们将从服务器端代码开始，然后转移到客户端，构建一个简单的引导布局，并从那里调用一些 JavaScript 函数。

作为奖励，我们将包括一种方法来将我们的对话历史存档到文本文件中。

# 设置项目

让我们设置这个项目：

1.  使用 Visual Studio 2017，我们将创建一个 ASP.NET Core Web 应用程序。您可以随意命名应用程序，但我将其命名为`Chapter5`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3557b025-a04f-4f72-8743-84ab52c8f8e8.png)

1.  我们将使用一个空项目模板。确保从下拉菜单中选择 ASP.NET Core 2.0：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e4c9d023-7cfa-418b-8c99-d1cbb69f8fb5.png)

项目将被创建，并将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/0cfa0d0f-3d72-4ff5-9cca-bd328d2b6eda.png)

# 添加 SignalR 库

接下来，我们需要将 SignalR 包文件添加到我们的项目中。

在撰写本文时，通过 NuGet 包管理器浏览时找不到 ASP.NET Core SignalR 的包，因此我们将使用包管理器控制台添加所需的包。

1.  转到工具 | NuGet 包管理器 | 包管理器控制台：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/491113b9-d5af-4c63-9948-b5064f3f4b70.png)

1.  在控制台窗口中输入以下命令并按回车键：

```cs
Install-Package Microsoft.AspnetCore.SignalR -Version 1.0.0-alpha2-final
```

您应该看到一些响应行，显示成功安装的项目。

我们还需要 SignalR 客户端 JavaScript 库。为此，我们将使用一个`npm`命令。

npm 是一个包管理器，类似于 NuGet，但用于 JavaScript。欢迎访问[`www.npmjs.com`](https://www.npmjs.com)查看。

1.  在控制台窗口中输入以下命令并按*回车*键：

```cs
npm install @aspnet/signalr-client
```

这将下载一堆 js 文件到项目根目录下的`node_modules`文件夹中。输出可能会显示一些警告，但不用担心。如果`node_modules`目录存在，您可以确认下载成功。

有了我们的包，我们可以（终于）开始编写一些代码了。

# 构建服务器

我们需要为我们的聊天程序构建一个服务器，其中包含我们想要从连接的客户端调用的方法。我们将使用 SignalR Hubs API，该 API 提供了连接的客户端与我们的聊天服务器通信所需的方法。

# SignalR Hub 子类

现在我们需要创建 SignalR Hub。为此，请执行以下步骤：

1.  在项目中添加一个类来处理聊天的服务器端。我们将其称为`Chat`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c2a31c66-7397-4722-b6ce-e727742fd17a.png)

这将需要是 SignalR `Hub`类的子类。确保添加`Micosoft.AspNetCore.SignalR`的使用指令。Visual Studio 的*快速操作*对此效果很好：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/9d53e3e5-5541-47e5-afe1-dd58541b9a74.png)

1.  现在向类添加一个`Task`方法来处理消息的发送：

```cs
        public Task Send(string sender, string message) 
        { 
            return Clients.All.InvokeAsync("UpdateChat", sender, 
            message); 
        } 
```

这个方法将通过任何连接的客户端调用，并调用所有连接的客户端的`Send`函数，传递发送者和消息参数。

1.  现在添加一个`Task`方法来处理存档功能：

```cs
        public Task ArchiveChat(string archivedBy, string path, 
         string messages) 
        { 
            string fileName = "ChatArchive" + 
             DateTime.Now.ToString("yyyy_MM_dd_HH_mm") + ".txt"; 
            System.IO.File.WriteAllText(path + "\" + fileName, 
             messages); 
            return Clients.All.InvokeAsync("Archived", "Chat 
             archived by "+ archivedBy); 
        } 
```

正如您所看到的，这个方法只是简单地获取消息字符串参数的值，将其写入一个名为`ChatArchive_[date].txt`的新文本文件中，保存到给定路径，并调用客户端的`Archived`函数。

为了使这两个任务真正起作用，我们需要做一些更多的脚手架工作。

# 配置更改

在`Startup.cs`文件中，我们需要将 SignalR 服务添加到容器中，并配置 HTTP 请求管道。

1.  在`ConfigureServices`方法中，添加以下代码：

```cs
services.AddSignalR();
```

1.  在`Configure`方法中，添加以下代码：

```cs
app.UseSignalR(routes => 
      { 
          routes.MapHub<Chat>("chat"); 
      });
```

您的代码窗口现在如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/5021442e-5018-4ccb-ab30-91330c32d075.png)

这就是我们的服务器完成了。

您会注意到我已经在`Configure`方法中添加了以下代码行，`app.UseStaticFiles()`。静态文件是 ASP.NET Core 应用程序直接提供给客户端的资产。静态文件的示例包括 HTML、CSS、JavaScript 和图像。

我们可以（也将）稍后扩展我们服务器的功能，但是现在，让我们前往我们的客户端。

# 创建客户端

如我们的项目布局中所述，客户端将包括用于向服务器发送消息和接收消息的 JavaScript 函数，以及用于显示的 HTML 元素。

1.  在您的项目中，在`wwwroot`下添加一个新的文件夹，名为`scripts`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2e8d92dd-0328-41d7-b3f8-2552bd212de3.png)

还记得之前由我们的`npm`命令创建的`node_modules`目录吗？

1.  转到`node_modules`目录中的以下路径：

`\@aspnet\signalr-client\dist\browser`

查看以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/22acf021-0aa0-44fa-b909-b8c6fdf2fa1a.png)

1.  将`signalr-client-1.0.0-alpha2-final.min.js`文件复制到我们项目中刚创建的`scripts`文件夹中。我们将在我们的 HTML 文件中引用这个库，现在我们将创建这个文件。

1.  在`wwwroot`文件夹中添加一个 HTML 页面。我把我的命名为`index.html`。我建议您也这样命名。稍后我会解释：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/7fadb9f8-a9fc-4621-ad12-40dacf9fd110.png)

我们将保持客户端页面非常简单。我使用`div`标签作为面板，在页面上显示和隐藏不同的部分。我还使用 bootstrap 使其看起来漂亮，但您可以按自己的喜好设计它。我也不会让您对基础知识感到厌烦，比如在哪里指定页面标题。我们将坚持相关的元素。

让我展示整个 HTML 布局代码以及 JavaScript，然后我们将从那里开始分解：

```cs
<!DOCTYPE html> 
<html> 
<head> 
    <title>Chapter 5- Signal R</title> 
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"> 
    <script src="img/jquery.min.js"></script> 
    <script src="img/bootstrap.min.js"></script> 
    <script src="img/signalr-client-1.0.0-alpha2-final.min.js"></script> 

    <script type="text/javascript"> 
        let connection = new signalR.HubConnection('/chat'); 
        connection.start(); 

        connection.on('UpdateChat', (user, message) => { 
            updateChat(user, message); 
        }); 
        connection.on('Archived', (message) => { 
            updateChat('system', message); 
        }); 

        function enterChat() { 
            $('#user').text($('#username').val()); 
            sendWelcomeMessage($('#username').val()); 
            $('#namePanel').hide(); 
            $('#chatPanel').show(); 
        }; 

        function sendMessage() { 
            let message = $('#message').val(); 
            let user = $('#user').text(); 
            $('#message').val(''); 
            connection.invoke('Send', user, message); 
        }; 

        function sendWelcomeMessage(user) { 
            connection.invoke('Send','system',user+' joined the 
            chat'); 
        }; 

        function updateChat(user, message) { 
            let chat = '<b>' + user + ':</b> ' + message + 
            '<br/>' 
            $('#chat').append(chat); 
            if ($('#chat')["0"].innerText.length > 0) { 
                $('#historyPanel').show(); 
                $('#archivePanel').show(); 
            } 
        }; 

        function archiveChat() { 
            let message = $('#chat')["0"].innerText; 
            let archivePath = $('#archivePath').val(); 
            let archivedBy = $('#username').val(); 
            connection.invoke('ArchiveChat', archivedBy, 
             archivePath, message); 
        }; 
    </script> 

</head> 
<body> 
    <div class="container col-md-10"> 
        <h1>Welcome to Signal R <label id="user"></label></h1> 
    </div> 
    <hr /> 
    <div id="namePanel" class="container"> 
        <div class="row"> 
            <div class="col-md-2"> 
                <label for="username" class="form-
                  label">Username:</label> 
            </div> 
            <div class="col-md-4"> 
                <input id="username" type="text" class="form-
                 control" /> 
            </div> 
            <div class="col-md-6"> 
                <button class="btn btn-default" 
                  onclick="enterChat()">Enter</button> 
            </div> 
        </div> 
    </div> 
    <div id="chatPanel" class="container" style="display: none"> 
        <div class="row"> 
            <div class="col-md-2"> 
                <label for="message" class="form-label">Message: 
                </label> 
            </div> 
            <div class="col-md-4"> 
                <input id="message" type="text" class="form-
                 control" /> 
            </div> 
            <div class="col-md-6"> 
                <button class="btn btn-info" 
                 onclick="sendMessage()">Send</button> 
            </div> 
        </div> 
        <div id="historyPanel" style="display:none;"> 
            <h3>Chat History</h3> 
            <div class="row"> 
                <div class="col-md-12"> 
                    <div id="chat" class="well well-lg"></div> 
                </div> 
            </div> 
        </div> 
    </div> 
    <div id="archivePanel" class="container" style="display:none;"> 
        <div class="row"> 
            <div class="col-md-2"> 
                <label for="archivePath" class="form-
                 label">Archive Path:</label> 
            </div> 
            <div class="col-md-4"> 
                <input id="archivePath" type="text" class="form-
                 control" /> 
            </div> 
            <div class="col-md-6"> 
                <button class="btn btn-success" 
                 onclick="archiveChat()">Archive Chat</button> 
            </div> 
        </div> 
    </div> 
</body></html> 
```

# 包括的库

添加`link`和`script`标签以包含所需的库：

```cs
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/
bootstrap.min.css">
<script src="img/jquery.min.js">
</script>
<script src="img/bootstrap.min.js">
</script>
<script src="img/signalr-client-1.0.0-alpha2-final.min.js"> </script>
```

如果您不想使用 bootstrap 来进行外观和感觉，您就不需要 bootstrap JavaScript 库或 CSS，但请注意我们将在我们的脚本中使用 jQuery，所以请留下它。

# 命名部分

我们需要知道谁是我们的聊天室参与者。添加一个输入元素来捕获用户名，以及一个按钮来调用`enterChat`函数：

+   `<input id="username" type="text" class="form-control" />`

+   `<button class="btn btn-default" onclick="enterChat()">Enter</button>`

# 聊天输入

添加所需的元素，使我们的用户能够输入消息（输入）并将其发送到服务器（`sendMessage`的事件按钮）：

+   `<input id="message" type="text" class="form-control" />`

+   `<button class="btn btn-info" onclick="sendMessage()">Send</button>`

# 对话面板

添加一个带有 ID`"chat"`的`div`标签。我们将使用这个作为我们对话的容器（聊天历史）：

+   `<div id="chat" class="well well-lg"></div>`

# 存档功能

添加所需的元素，使我们的用户能够指定存档文件需要保存的路径（输入），并将消息发送到服务器（`archiveChat`的事件按钮）：

+   `<input id="archivePath" type="text" class="form-control" />`

+   `<button class="btn btn-info" onclick="archiveChat()">Archive Chat</button>`

# JavaScript 函数

我们的客户端需要一些代码来向服务器发送和接收消息。我尽量保持 JavaScript 尽可能简单，选择了 jQuery 代码以提高可读性：

1.  为我们的 SignalR Hub 服务器创建一个变量（我命名为`connection`）并调用其 start 函数：

```cs
let connection = new signalR.HubConnection('/chat');
connection.start();
```

`'/chat'`参数用于`signalR.HubConnection`，指的是我们的`Chat.cs`类，它继承了 SignalR 的 Hub 接口。

1.  添加`UpdateChat`和`Archived`方法，这些方法将由服务器调用：

```cs
connection.on('UpdateChat', (user, message) => {
updateChat(user, message);
});
connection.on('Archived', (message) => {
updateChat('system', message);
});
```

我们只是将从服务器获取的参数传递给我们的`updateChat`方法。我们稍后会定义这个方法。

1.  定义`enterChat`函数：

```cs
function enterChat() {
$('#user').text($('#username').val());
sendWelcomeMessage($('#username').val());
$('#namePanel').hide();
$('#chatPanel').show();
};
```

我们从用户名输入元素的值中设置`user`标签的文本，将其传递给我们的`sendWelcomeMessage`方法（我们稍后会定义），并切换相关面板的显示。

1.  定义`sendMessage`方法：

```cs
function sendMessage() {
let message = $('#message').val();
$('#message').val('');
let user = $('#user').text();
connection.invoke('Send', user, message);
};
```

我们从消息输入元素中设置`message`变量，然后清除它以便下一条消息使用，并从用户标签中设置`user`变量。然后我们使用`connection.invoke`方法调用服务器上的`Send`方法，并将我们的变量作为参数传递。

1.  定义`sendWelcomeMessage`函数：

```cs
function sendWelcomeMessage(user) {
connection.invoke('Send','system',user+' joined the chat');
};
```

就像步骤 4 中描述的`sendMessage`函数一样，我们将使用`connection.invoke`函数调用服务器上的`Send`方法。不过这次我们将字符串`'system'`作为用户参数传递，以及有关刚刚加入的用户的一些信息性消息。

1.  定义`updateChat`方法：

```cs
function updateChat(user, message) {
let chat = '<b>' + user + ':</b> ' + message + '<br/>'
$('#chat').append(chat);
if ($('#chat')["0"].innerText.length > 0) {
$('#historyPanel').show();
$('#archivePanel').show();
}
};
```

`updateChat`只是我们用来更新聊天历史面板的自定义函数。我们本可以在两个`connection.on`函数中内联执行这个操作，但这样就意味着我们会重复自己。在任何编码中，通常的规则是尽量避免重复代码。

在这个函数中，我们将`chat`变量设置为我们希望每条聊天历史记录的样式。在这种情况下，我们只是将我们的用户（带有冒号）加粗显示，然后消息不加样式，最后换行。几行聊天看起来会像这样：

+   **John**: 大家好

+   **Sarah**: 你好 John

+   **server**: Peter 加入了聊天

+   **John**: 你好 Sarah，你好 Peter

+   **Peter**: 大家好

我还检查了聊天 div 的`innerText`属性，以确定聊天历史和存档面板是否可见。

定义`archiveChat`函数：

```cs
function archiveChat() {
let message = $('#chat')["0"].innerText;
let archivePath = $('#archivePath').val();
connection.invoke('ArchiveChat', archivePath, message);
};
```

和其他一切一样，我尽量保持简单。我们获取聊天面板（div）的`innerText`和`archivePath`输入中指定的路径，然后将它们传递给服务器的`ArchiveChat`方法。

当然，这里我们有一个小错误的窗口：如果用户没有输入有效的文件保存路径，代码将抛出异常。我会留给你自己的创造力来解决这个问题。我只是在这里为了 SignalR 功能。

# 解决方案概述

现在你应该有一个完整的、可构建的解决方案。让我们快速查看一下解决方案资源管理器中的解决方案：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/01b3c3b0-90b7-4bc6-b9d5-130e1430940f.png)

从头开始，让我列出我们对`Chapter5`项目所做的更改：

1.  以下是我们通过 NuGet 添加的 SignalR Asp.NET Core 库：

`Dependencies/NuGet/Microsoft.AspNetCore.SignalR (1.0.0-alpha2-final)`

1.  我们手动从`node_modules`文件夹中复制了这个 JavaScript 库，之后使用`npm`下载了它：

`wwwroot/scripts/signalr-client-1.0.0-alpha2-final.min.js`

1.  我们的客户端页面包含了 HTML 标记、样式和 JavaScript：`one.wwwroot/index.html`

如果你要将这个应用程序作为基础并进行扩展，我建议将 JavaScript 代码移到一个单独的`.js`文件中。这样更容易管理，也是另一个良好的编码标准。

1.  `Chat.cs`：这是我们的聊天服务器代码，或者说是我们声明的任何自定义任务方法

1.  `Startup.cs`：这个文件在 Asp.NET Code web 应用程序中是标准的，但我们改变了配置以确保 SignalR 被添加为服务

1.  让我们构建我们的项目。在 Visual Studio 的顶部菜单中，单击“构建”菜单按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/4640cf57-8c48-48e4-905e-c13e61731f40.png)

您可以选择构建整个解决方案，也可以选择单独的项目。鉴于我们的解决方案中只有一个项目，我们可以选择任何一个。您还可以使用键盘快捷键*Ctrl* + *Shift* + *B*。

您应该在输出窗口中看到一些（希望成功的）构建消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/3ea60140-3380-4d22-88ce-b05b988eb1dc.png)

如果您遇到任何错误，请再次查看本章，看看您是否漏掉了什么。一个小刺可以引起很多不适。

# 展示和告知

是时候了。您已经创建了项目，添加了库，并编写了代码。现在让我们看看这个东西的表现。

# 运行应用程序

要运行应用程序，请按*F5*（或*Ctrl* + *F5*以无调试模式启动）。应用程序将在默认浏览器中打开，您应该看到这个：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/c3c3dad3-aa48-4ecb-931a-b904edf99865.png)

等等。什么？我们一定是漏掉了什么。

现在我们只需通过将我们的 URL 更改为`localhost:12709/index.html`（只需检查您的端口号），我们就可以导航到 index.html 页面了。

相反，让我们将我们的`index.html`页面指定为默认启动页面。

在`Startup.cs`类的`Configure`方法中，在顶部添加这一行：

`app.UseDefaultFiles();`

有了这个小宝石，对`wwwroot`文件夹的任何请求（随时导航到您的网站）都将搜索以下之一：

+   `default.htm`

+   `default.html`

+   `index.htm`

+   `index.html`

找到的第一个文件将作为您的默认页面提供。太棒了！

现在让我们再次运行我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a1bfe8fc-a929-49ad-95b2-670f290432ff.png)

即使我们的 URL 仍然不显示`/index.html`部分，我们的 Web 应用程序现在知道要提供哪个页面。现在我们可以开始聊天了。输入用户名并按*Enter*： 

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/d709f6ac-7698-4d04-8c10-bbf889d243f4.png)

如您所见，我们的名称面板现在被隐藏，我们的聊天和存档面板正在显示。

我们的服务器还友好地通知我们加入了聊天，感谢我们的`sendWelcomeMessage(user)`函数。

每次我们发送消息，我们的聊天历史都会更新：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/6b43327e-ef9d-455d-89bc-b6540065f0ab.png)

# 开始派对

只有多方参与，对话才是对话。所以让我们开始一个派对。

如果您在网络上发布应用程序，可以使用实际的网络客户端进行聊天，但我不在网络上（不是那个意思），所以我们使用另一个技巧。我们可以使用各种浏览器来代表我们不同的派对客人（网络客户端）。

复制您的应用程序 URL（再次检查端口号）并粘贴到其他几个浏览器中。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/a22f7279-49d4-4b86-9e0e-ce876ad1c5c8.png)

对于每个新客人（浏览器），您需要指定一个用户名。为了更容易跟踪，我将称我的其他客人为不同的浏览器名称。

当他们每个人进入聊天并开始发送消息时，您将看到我们的聊天历史增长：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/2dbcf2c4-7279-4912-9bbe-6a1fe131277f.png)

您可以将浏览器平铺（或将它们移动到其他显示器，如果您有额外的显示器）以查看由一个人发送的消息立即传递给所有人的数量，这正是 SignalR 的全部意义所在。

我们从 Microsoft Edge 中的 John Doe 开始，所以我们将在那里继续：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/85bad280-d76b-4bb9-9c8b-312f268c9c5c.png)

Opera 是第一个加入派对的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/131e397c-c19f-4f7e-ad53-4e7edf88b91e.png)

然后 Chrome 到达：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/320084a0-9cc5-4017-90ce-6a6053b87f93.png)

最后，Firefox 也加入了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/e09e7e15-e27f-4078-a751-a895b7e3b77b.png)

您还会注意到每个客人的聊天历史只有在他们加入聊天时才开始。这是有意设计的。我们不会在客户端加入时发送历史聊天记录。

# 存档聊天

要将聊天记录保存到文本文件中，请在`archivePath`输入元素中输入有效的本地文件夹路径，然后点击“存档聊天”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-bp/img/8b97673f-55c3-4f9c-8811-6da042913545.png)

如前所述，我们尚未为我们的路径构建适当的验证，因此请确保使用有效路径进行测试。如果成功，您应该在聊天窗口中看到这样的消息：

```cs
system: Chat archived by John Doe
```

您还将在指定路径中找到新创建的文本文件，文件名采用`ChatArchive_[date].txt`的命名约定。

# 总结

正如本章所示，SignalR 非常容易实现。我们创建了一个聊天应用程序，但有许多应用程序可以从实时体验中受益。这些包括股票交易、社交媒体、多人游戏、拍卖、电子商务、财务报告和天气通知。

列表可以继续。即使实时数据的需求不是必需的，SignalR 仍然可以使任何应用程序受益，使节点之间的通信变得无缝。

浏览 Asp.NET SignalR 的 GitHub 页面（[`github.com/aspnet/SignalR`](https://github.com/aspnet/SignalR)），显然该库正在不断地进行改进和完善，这是个好消息。

随着对快速、相关和准确信息的需求变得更加关键，SignalR 是您团队中的重要成员。
