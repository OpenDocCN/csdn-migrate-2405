# C++ 研讨会（七）

> 原文：[`annas-archive.org/md5/5ba4b421a6ba3d7c3a23406bab386ec0`](https://annas-archive.org/md5/5ba4b421a6ba3d7c3a23406bab386ec0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 ASP.NET 创建现代 Web 应用

概述

现在有许多类型的应用程序在使用，Web 应用程序位居最常用的应用程序之列。在本章中，您将了解到 ASP.NET，这是一个使用 C#和.NET 运行时构建的 Web 框架，旨在轻松创建 Web 应用程序。您还将了解基本 ASP.NET 应用程序的解剖学，服务器端渲染和单页应用程序等 Web 应用程序开发方法，以及 C#如何帮助实现这些方法来构建安全、高性能和可扩展的应用程序。

# 介绍

在*第一章*，*你好 C#*中，您了解到.NET 是如何使 C#生动起来的，因为它包含了用于构建代码的软件开发工具包（SDK）和执行代码的运行时。在本章中，您将了解 ASP.NET，它是嵌入在.NET 运行时中的开源跨平台框架。它用于构建 Web、移动和物联网设备的前端和后端应用程序。

它是这类开发的完整工具箱，因为它提供了几个内置功能，如轻量级和可定制的 HTTP 管道、依赖注入以及对现代托管技术的支持，如容器、Web UI 页面、路由和 API。一个著名的例子是 Stack Overflow；它的架构完全建立在 ASP.NET 之上。

本章的重点是让您熟悉 ASP.NET 的基础知识，并为您提供关于使用 Razor Pages 构建 Web 应用程序的介绍和全面概述，Razor Pages 是 ASP.NET 中包含的内置工具箱。

# ASP.NET Web 应用程序的解剖学

您将通过使用 ASP.NET 创建一个新的 Razor Pages 应用程序来开始本章。这只是 ASP.NET 可以创建的各种类型应用程序之一，但作为起点是非常有效的，因为它与框架可以构建的其他 Web 应用程序类型共享并展示了许多共同点。

1.  要创建一个新的 Razor Pages 应用程序，在 CLI 中输入以下命令：

```cpp
dotnet new razor -n ToDoListApp dotnet new sln -n ToDoList dotnet sln add ./ToDoListApp
```

在这里，您将使用 Razor Pages 创建一个待办事项列表应用程序。一旦执行了前面的命令，您将看到一个具有以下结构的文件夹：

```cpp
/ToDoListApp |-- /bin |-- /obj |-- /Pages
|-- /Properties |-- /wwwroot |-- appsettings.json |-- appsettings.Development.json |-- Program.cs
|-- ToDoListApp.csproj
|ToDoList.sln
```

1.  在 Visual Studio Code 中打开根文件夹。

这些文件夹中有一些文件将在接下来的部分中介绍。现在，考虑这个结构：

+   `bin`是应用程序构建后最终二进制文件所在的文件夹。

+   `obj`是编译器在构建过程中放置中间输出的文件夹。

+   `Pages`是应用程序 Razor Pages 将被放置的文件夹。

+   `Properties`是一个包含`launchSettings.json`文件的文件夹，该文件用于放置运行配置。在此文件中，您可以定义一些本地运行的配置，例如环境变量和应用程序端口。

+   `wwwroot`是应用程序的所有静态文件所在的文件夹。

+   `appsettings.json`是一个配置文件。

+   `appsettings.Development.json`是用于开发环境的配置文件。

+   `Program.cs`是您自*第一章*，*你好 C#*以来看到的程序类。它是应用程序的入口点。

现在你知道在.NET 6.0 中，是`Program.cs`文件，在文件夹的根目录创建，给`WebApplication`带来了生命，你可以在下一节深入探索`Program.cs`。

## Program.cs 和 WebApplication

如前所述，`Program.cs`是任何 C#应用程序的入口点。在本节中，您将看到一个典型的 ASP.NET 应用程序的`Program`类是如何构建的。考虑下面描述一个非常简单的 ASP.NET 应用程序的`Program.cs`的示例：

```cpp
Program.cs
var builder = WebApplication.CreateBuilder(args);
// Add services to the container.
builder.Services.AddRazorPages();
var app = builder.Build();
// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
app.UseExceptionHandler("/Error");
// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
The complete code can be found here: https://packt.link/tX9iK.
```

这里做的第一件事是创建一个`WebApplicationBuilder`对象。这个对象包含了在 ASP.NET 中引导基本 Web 应用程序所需的一切——配置、日志、DI 和服务注册、中间件和其他主机配置。这个主机负责 Web 应用程序的生命周期管理；它们设置了一个 Web 服务器和一个基本的 HTTP 管道来处理 HTTP 请求。

正如您所看到的，用几行代码就可以完成许多事情，使您能够运行一个结构良好的 Web 应用程序。ASP.NET 完成了所有这些工作，以便您可以专注于通过您将构建的功能提供价值。

注意

Bootstrap 是用于美化 Web 内容的 CSS 库。您可以在官方网站上了解更多信息。

## 中间件

将中间件视为连接在一起形成处理 HTTP 请求和响应的管道的小型应用程序片段。每个片段都是一个组件，可以在另一个组件在管道上执行之前或之后执行一些工作。它们也通过`next()`调用连接在一起，如*图 7.1*所示：

![图 7.1：HTTP 管道的中间件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_01.jpg)

图 7.1：HTTP 管道的中间件

中间件本身就是一个完整的宇宙。以下列表定义了构建 Web 应用程序的显著特点：

+   中间件的放置顺序很重要。因为它们一个接一个地链接在一起，每个组件的放置方式都会影响管道的处理方式。

+   `before`逻辑，如*图 7.1*所示，直到最终到达终点。一旦到达终点，管道将继续使用`after`逻辑处理响应。

+   `next()`是一个方法调用，将执行管道中的下一个中间件，然后执行当前中间件的`after`逻辑。

在 ASP.NET 应用程序中，中间件可以在`Program.cs`文件中定义，之后`WebApplicationBuilder`调用`Build`方法并使用`WebApplication?`对象作为此操作的结果。

在*Program.cs 和 WebApplication*部分创建的应用程序已经包含了一组中间件，用于新的样板 Razor Pages 应用程序，当**HTTP 请求**到达时将按顺序调用。

这很容易配置，因为`WebApplication`对象包含一个通用的`UseMiddleware<T>`方法。这个方法允许您创建中间件，嵌入到 HTTP 管道中处理请求和响应。当在`Configure`方法中使用时，每次应用程序接收到传入请求时，该请求将按照在`Configure`方法中放置请求的顺序经过所有中间件。默认情况下，ASP.NET 提供基本的错误处理、自动重定向到 HTTPS，并提供静态文件，以及一些基本的路由和授权。

但是，您可能会注意到在您的`Program.cs`文件中，*Program.cs 和 WebApplication*部分中没有`UseMiddleware<>`调用。这是因为您可以编写扩展方法，为代码提供更简洁的名称和可读性，ASP.NET 框架已经默认为一些内置中间件提供了这样的方法。例如，考虑以下示例：

```cpp
using Microsoft.AspNetCore.HttpsPolicy;
public static class HttpsPolicyBuilderExtensions
{
public static IApplicationBuilder UseHttpsRedirection(this WebApplication app)
      { 
           app.UseMiddleware<HttpsRedirectionMiddleware>();
           return app;
}
}
```

在这里，使用了内置的`UseHttpsRedirection`扩展方法的示例，用于启用重定向中间件。

## 日志

日志可能被理解为将应用程序执行的所有操作写入输出的简单过程。这个输出可以是控制台应用程序、文件，甚至是第三方日志监视应用程序，比如 ELK Stack 或 Grafana。日志在吸收应用程序行为方面有重要地位，特别是在错误跟踪方面。这使得它成为一个重要的概念需要学习。

使 ASP.NET 成为企业应用程序的有效平台之一的因素之一是其模块化。由于它是建立在抽象之上的，任何新的实现都可以很容易地完成，而不会对框架造成太大的负担。**日志**抽象就是其中之一。

默认情况下，在`Program.cs`中创建的`WebApplication`对象会在这些日志抽象之上添加一些日志提供程序，包括`Console`、`Debug`、`EventSource`和`EventLog`。后者——`EventLog`——是仅适用于 Windows 操作系统的高级功能。这里的重点将是`Console`日志提供程序。顾名思义，这个提供程序将把所有记录的信息输出到您的应用程序控制台。您将在本节的后面学到更多关于它的知识。

由于日志基本上记录了应用程序的所有操作，您可能会想知道这些日志是否会变得非常庞大，特别是对于大型应用程序。它们可能会，但在编写应用程序日志时一个重要的事情是要理解日志的**严重性**。可能有一些需要记录的关键信息，比如意外异常。也可能有一些信息，您只想在开发环境中记录，以更好地了解一些行为。也就是说，在.NET 中，日志有七个可能的级别，它们是：

+   `跟踪` = 0

+   `调试` = 1

+   `信息` = 2

+   `警告` = 3

+   `错误` = 4

+   `关键` = 5

+   `无` = 6

输出到提供程序的级别是通过设置环境变量或通过`appSettings.json`文件中的`Logging:LogLevel`部分来定义的，如下例所示：

```cpp
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "ToDoListApp": "Warning",
      "ToDoListApp.Pages": "Information"
    }
  }
}
```

在这个文件中，有日志类别，它们要么是`默认`类别，要么是想要设置日志的类型的命名空间的一部分。这正是这些命名空间存在的原因。例如，您可以为命名空间内的文件设置两个不同级别的日志记录。

在前面的示例配置中，整个`ToDoListApp`是一个设置命名空间，只有`LogLevel`等于或高于`Warning`时才会写日志。您还指定了对于`ToDoListApp.Pages`类别/命名空间，应用程序将写入所有级别等于或高于`Information`的日志。这意味着更具体的命名空间上的更改会覆盖在更高级别设置的设置。

本节向您展示了如何为应用程序配置日志级别。有了这个知识，您现在可以理解下一节中讨论的 DI 的概念。

## 依赖注入

依赖注入（DI）是 ASP.NET 框架本身支持的一种技术。它是实现面向对象编程中著名概念控制反转（IoC）的一种形式。

对象需要的任何组件都可以称为依赖关系。对于类来说，这可能指的是需要构造的参数。对于方法来说，可能是执行所需的方法。使用 IoC 与依赖关系意味着将创建类的责任委托给框架，而不是手动完成所有操作。

在*第二章*，*构建高质量的面向对象的代码*中，您学习了关于接口的知识。接口基本上是一种建立合同的常见形式。它们允许您专注于调用的结果，而不是它是如何执行的。当您使用 IoC 时，您的依赖关系现在可以是接口，而不是具体的类。这使得您的类或方法可以专注于这些接口建立的合同，而不是实现细节。这带来了以下优势：

+   您可以轻松地替换实现，而不会影响任何依赖于合同的类。

+   它解耦了应用程序的边界和模块，因为合同通常不需要任何硬性依赖。

+   这使得测试变得更容易，允许您创建这些显式依赖关系作为模拟，或者伪造，并专注于行为而不是真正的实现细节。

现在想象一下，要创建应用程序的中间件，您需要构造它们的每个依赖项，并且您在构造函数上有很多中间件链接在一起。显然，这将是一个繁琐的过程。此外，测试任何这些中间件都将是一个繁琐的过程，因为您需要依赖于每个具体的实现来创建一个对象。

通过注入依赖项，您告诉编译器如何构造一个在构造函数上声明了其依赖项的类。DI 机制在运行时执行此操作。这相当于告诉编译器，每当它找到某种类型的依赖项时，它应该使用适当的类实例来解析它。

ASP.NET 提供了一个本地的 DI 容器，它存储有关如何解析类型的信息。接下来，您将学习如何将此信息存储在容器中。

在`Program.cs`文件中，您将看到调用`builder.Services.AddRazorPages()`。`Services`属性是`IServiceCollection`类型，并且它保存了整套依赖项（也称为服务），这些依赖项被注入到容器中。用于 ASP.NET 应用程序运行的许多所需依赖项已经在`Program.cs`文件顶部调用的`WebApplication.CreateBuilder(args)`方法中注入。例如，对于一些本地日志记录依赖项，您将在下一个练习中看到这一点。

## 练习 7.01：创建自定义日志记录中间件

在这个练习中，您将创建自定义的日志记录中间件，以便将 HTTP 请求的详细信息和持续时间输出到控制台。创建完成后，将其放置在 HTTP 管道中，以便它被应用程序接收到的每个请求调用。目的是让您对中间件、日志记录和 DI 的概念有一个初步的实际介绍。

以下步骤将帮助您完成此练习：

1.  创建一个名为`Middlewares`的新文件夹。

1.  在此文件夹中，创建一个名为`RequestLoggingMiddleware`的新类。

1.  创建一个名为`RequestDelegate`的新私有只读字段，并在构造函数中初始化该字段：

```cpp
private readonly RequestDelegate _next;
public RequestLoggingMiddleware(RequestDelegate next)
{
    _next = next; 
}
```

这是 ASP.NET 收集的作为 HTTP 管道上要执行的下一个中间件的引用。通过初始化此字段，您可以调用下一个注册的中间件。

1.  添加一个`using`语句到`System.Diagnostics`命名空间，以便可以添加一个名为`Stopwatch`的特殊类，它将用于测量请求的时间长度：

```cpp
using System.Diagnostics;
```

1.  创建一个私有的`readonly ILogger`字段。`ILogger`接口是.NET 提供的手动记录信息的默认接口。

1.  之后，在构造函数中为`ILoggerFactory`类型添加第二个参数。这个接口是.NET 提供的另一个接口，允许您创建`ILogger`对象。

1.  使用此工厂的`CreateLogger<T>`方法创建一个记录器对象：

```cpp
private readonly ILogger _logger;
private readonly RequestDelegate _next;
public RequestLoggingMiddleware(RequestDelegate next, ILoggerFactory loggerFactory)
{
    _next = next; 
    _logger = loggerFactory.CreateLogger<RequestLoggingMiddleware>();
}
```

在这里，`T`是一个泛型参数，指的是日志类别，如*Logging*部分所示。在这种情况下，类别将是进行日志记录的类的类型，即`RequestLoggingMiddleware`类。

1.  字段初始化完成后，创建一个具有以下签名的新方法：

```cpp
public async Task InvokeAsync(HttpContext context) { }
```

1.  在此方法中，声明一个名为`Stopwatch`的变量，并将`Stopwatch.StartNew()`的值赋给它：

```cpp
var stopwatch = Stopwatch.StartNew();
```

`Stopwatch`类是一个辅助类，用于测量从调用`.StartNew()`方法开始的执行时间。

1.  在此变量之后，编写一个带有代码的`try-catch`块，用于调用下一个请求，以及调用`stopwatch`的`.Stop()`方法来测量`_next()`调用所花费的时间：

```cpp
using System.Diagnostics;
namespace ToDoListApp.Middlewares;
public class RequestLoggingMiddleware
{
    private readonly ILogger _logger;
    private readonly RequestDelegate _next;
    public RequestLoggingMiddleware(RequestDelegate next, ILoggerFactory loggerFactory)
    {
        _next = next;
        _logger = loggerFactory.CreateLogger<RequestLoggingMiddleware>();
    }
```

您还可以在这里处理可能的异常。因此，最好将这两个调用包装在`try-catch`方法中。

1.  在`Program.cs`文件中，通过以下方式放置声明来调用自定义中间件：

```cpp
var app = builder.Build();
// Configure the HTTP request pipeline.app.UseMiddleware<RequestLoggingMiddleware>();
```

将其写在分配`app`变量的下一行。

1.  最后，在`Program.cs`文件中，添加一个`using`语句到`ToDoListApp.Middlewares`：

```cpp
Program.cs
using ToDoListApp.Middlewares;
var builder = WebApplication.CreateBuilder(args);
// Add services to the container.
builder.Services.AddRazorPages();
var app = builder.Build();
// Configure the HTTP request pipeline.
app.UseMiddleware<RequestLoggingMiddleware>();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
```

```cpp
The complete code can be found here: https://packt.link/tX9iK.
```

1.  要在 Web 浏览器上看到应用程序运行和在 Visual Studio Code 中看到其输出，可以在地址栏中输入以下命令：

```cpp
localhost:####
```

在这里`####`代表端口号。这对于不同的系统来说是不同的。

1.  按下回车后，会显示以下屏幕：

![图 7.2：应用程序在浏览器上运行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_02.jpg)

图 7.2：应用程序在浏览器上运行

1.  在 VS Code 中执行练习/活动后，每次执行*步骤 13*。

1.  在执行另一个练习/活动之前，在 VS Code 终端内按下`Control+C`来中断任务。

1.  在浏览器中执行应用程序后，您将在 Visual Studio Code 终端中看到类似的输出：

```cpp
info: ToDoListApp.Middlewares.RequestLoggingMiddleware[0]
      HTTP GET request for path / with status 200 executed in 301 ms
info: ToDoListApp.Middlewares.RequestLoggingMiddleware[0]
      HTTP GET request for path /lib/bootstrap/dist/css/bootstrap.min.css with status 200 executed in 18 ms
info: ToDoListApp.Middlewares.RequestLoggingMiddleware[0]
      HTTP GET request for path /css/site.css with status 200 executed in 1 ms
info: ToDoListApp.Middlewares.RequestLoggingMiddleware[0]
      HTTP GET request for path /favicon.ico with status 200 executed in 1 ms
```

您会注意到控制台上的输出记录了中间件管道中 HTTP 请求的经过时间。由于您已经在方法中声明了它，它应该考虑所有管道链的执行时间。

在这个练习中，您创建了您的第一个中间件——`RequestLoggingMiddleware`。这个中间件测量了 HTTP 请求在您的 HTTP 管道中的执行时间。通过将它放在所有其他中间件之前，您将能够测量通过整个中间件管道的请求的整个执行时间。

注意

您可以在[`packt.link/i04Iq`](https://packt.link/i04Iq)找到此练习使用的代码。

现在想象一下，您有 10 到 20 个中间件用于 HTTP 管道，每个中间件都有自己的依赖项，您必须手动实例化每个中间件。在这种情况下，IoC 非常方便，通过委托给 ASP.NET 来实例化这些类，并注入它们的依赖项。您已经看到了如何创建使用本机 ASP.NET 日志机制和 DI 的自定义中间件。

在 ASP.NET 中，日志记录和 DI 是强大的机制，允许您为应用程序创建非常详细的日志。正如您所见，通过构造函数注入`logger`实现了这一点。对于这些记录器，您可以通过两种方式创建一个日志类别的对象：

+   如练习所示，一种方式是注入`ILoggerFactory`。您可以调用`CreateLogger(categoryName)`方法，该方法接收一个字符串作为参数。您还可以调用`CreateLogger<CategoryType>()`方法，该方法接收一个泛型类型。这种方法更可取，因为它将`logger`的类别设置为类型的完整名称（包括命名空间）。

+   另一种方式是通过注入`ILogger<CategoryType>`。在这种情况下，类别类型通常是您注入记录器的类的类型，就像在上一个练习中看到的那样。在上一个练习中，您可以用`ILogger<RequestLoggingMiddleware>`替换`ILoggerFactory`的注入，并将这个新注入的依赖直接分配给`ILogger`私有字段，如下所示：

```cpp
private readonly ILogger _logger;
private readonly RequestDelegate _next;
public RequestLoggingMiddleware(RequestDelegate next, ILogger< RequestLoggingMiddleware> logger)
{
    _next = next; 
    _logger = logger;
}
```

您现在知道日志记录和 DI 是强大的机制，允许您为应用程序创建非常详细的日志。在转向 Razor 页面之前，了解应用程序中对象的生命周期是很重要的。这被称为依赖生命周期。

## 依赖生命周期

在转向本章的下一个主题之前，重要的是要谈论依赖生命周期。在上一个练习中使用的所有依赖项都是通过构造函数注入的。但是这些依赖项的解析之所以可能，是因为 ASP.NET 事先注册了这些依赖项，就像在`Program.cs`部分中提到的那样。在下面的代码中，您可以看到内置于 ASP.NET 中处理日志依赖注册的示例，通过向服务容器添加`ILoggerFactory`依赖项：

```cpp
LoggingServiceCollectionExtensions.cs
public static IServiceCollection AddLogging(this IServiceCollection services, Action<ILoggingBuilder> configure)
{T
if (services == null)
     {
     throw new ArgumentNullException(nameof(services));
     }
     services.AddOptions();
     services.TryAdd(ServiceDescriptor.Singleton<ILoggerFactory, LoggerFactory>());

services.TryAdd(ServiceDescriptor.Singleton(typeof(ILogger<>), typeof(Logger<>)));
services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<LoggerFilterOptions>>(new DefaultLoggerLevelConfigureOptions(LogLevel.Information)));
configure(new LoggingBuilder(services));
return services;
}
The complete code can be found here: https://packt.link/g4JPp.
```

注意

上述代码是一个标准库和内置于 ASP.NET 中处理日志依赖注册的示例。

这里有很多事情要做，但需要考虑的两个重要事项如下：

+   这里的方法是`TryAdd`，它在 DI 容器中注册依赖项。

+   `ServiceDescriptor.Singleton`方法定义了依赖项的生命周期。这是本章*依赖注入*部分的最后一个重要概念。

依赖项生命周期描述了应用程序中对象的生命周期。ASP.NET 有三种默认生命周期可用于注册依赖项：

+   瞬态：具有这种生命周期的对象在每次被请求时都会被创建，并在使用后被处理。这对于无状态依赖项非常有效，这些依赖项在被调用时不需要保持状态。例如，如果需要连接到 HTTP API 请求一些信息，可以使用这种生命周期注册依赖项，因为 HTTP 请求是无状态的。

+   Scoped：具有作用域生命周期的对象是为每个客户端连接创建一次。例如，在 HTTP 请求中，作用域依赖项将在整个请求期间具有相同的实例，无论调用多少次。这种依赖项在一定时间内携带一些状态。在连接结束时，依赖项被处理。

+   Singleton：具有单例生命周期的对象是在整个应用程序生命周期中创建一次。一旦它们被请求，它们的实例将在应用程序运行时被携带。这种生命周期应该仔细考虑，因为它可能消耗大量内存。

如前所述，这些依赖项的手动注册可以在`Startup`类中的`ConfigureServices`方法中完成。任何未由 ASP.NET 提供和自动注册的新依赖项都应在那里手动注册，了解这些生命周期很重要，因为它们允许应用程序以不同的方式管理依赖项。

你已经学到了这些依赖项的解析只有因为 ASP.NET 注册了三种默认的生命周期，可以用来注册依赖项。现在你将继续学习 Razor 页面，它可以构建基于页面的应用程序，并且具有由 ASP.NET 提供和支持的所有功能。

## Razor 页面

现在你已经涵盖了与 ASP.NET 应用程序相关的主要方面，你将继续构建在本章开头开始的应用程序。这里的目标是构建一个待办事项列表应用程序，在这个 Kanban 风格的面板上，你可以轻松地创建和管理任务列表。

之前的部分提到了 Razor 页面，但它到底是什么？Razor 页面是一个框架，可以构建基于页面的应用程序，并具有由 ASP.NET 提供和支持的所有功能。它被创建用于构建具有明确关注点分离的动态数据驱动应用程序，即每个方法和类具有单独但互补的责任。

### 基本的 Razor 语法

Razor 页面使用 Razor 语法，这是由 Microsoft 提供的一种语法，可以让页面具有静态 HTML/CSS/JS、C#代码和自定义标签助手，这些是可重用的组件，可以在页面中渲染 HTML 片段。

如果你查看你在第一个练习中运行的`dotnet new`命令生成的`.cshtml`文件，你会注意到大量的 HTML 代码，以及在这些代码中带有`@`前缀的一些方法和变量。在 Razor 中，一旦你写下这个符号，编译器就会检测到将写入一些 C#代码。你已经知道 HTML 是一种用于构建网页的标记语言。Razor 与 C#一起使用，创建强大的标记与服务器渲染的代码结合。

如果要放置一块代码，可以用括号括起来，如：

```cpp
@{ … }
```

在此块中，您可以做基本上可以使用 C#语法做的任何事情，从局部变量声明到循环等等。如果要放置一个`static @`，您必须通过放置两个`@`符号来转义它，以便在 HTML 中呈现。例如，在电子邮件 ID 中会发生这种情况，例如`james@@bond.com`。

### 文件结构

Razor 页面以`.cshtml`扩展名结尾，可能还有另一个文件，通常称为`.cshtml.cs`扩展名。如果您转到应用程序的根文件夹并导航到`Pages`文件夹，您将看到在创建页面时生成的以下结构：

```cpp
|-- /Pages
|---- /Shared |------ _Layout.cshtml |------ _ValidationScriptsPartial.cshtml |---- _ViewImports.cshtml
|---- _ViewStart.cshtml
|---- Error.cshtml
|---- Error.cshtml.cs
|---- Index.cshtml
|---- Index.cshtml.cs
|---- Privacy.cshtml
|---- Privacy.cshtml.cs
```

`Index`，`Privacy`和`Error`页面在项目创建后会自动生成。简要查看这里的其他文件。

`/Shared`文件夹包含一个默认在应用程序中使用的共享`Layout`页面。该页面包含一些共享部分，例如导航栏、标题、页脚和元数据，几乎在每个应用程序页面中都重复出现：

```cpp
_Layout.cshtml
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>@ViewData["Title"] - ToDoListApp</title>    <link rel="stylesheet" href="~/lib/bootstrap/dist/css/bootstrap.min.css" />
    <link rel="stylesheet" href="~/css/site.css" asp-append-version="true" />
    <link rel="stylesheet" href="~/ToDoListApp.styles.css" asp-append-version="true" />
</head>
<body>
    <header>
        <nav class="navbar navbar-expand-sm navbar-toggleable-sm navbar-light bg-white border-bottom box-shadow mb-3">
            <div class="container">
                <a class="navbar-brand" asp-area="" asp-page="/Index">ToDoListApp</a>
The complete code can be found here: https://packt.link/2Hb8r.
```

将这些共享部分放在单个文件中使得可重用性和可维护性更容易。如果您查看在您的样板中生成的`Layout`页面，有一些值得注意的地方：

+   默认情况下，Razor 页面应用程序使用 Twitter Bootstrap 进行设计 - 用于编写美观、简单和响应式网站的库 - 和 jQuery 进行基本脚本编写。这可以根据每个应用程序进行自定义，因为这些只是静态文件。

+   有一个特殊的`RenderBody()`方法，指示应用程序页面的生成 HTML 将放置在哪里。

+   另一个名为`RenderSection()`的方法，用于在每个页面上呈现预定义的部分。例如，当某些静态文件，例如图像、脚本或样式表，仅在某些页面上需要时，这是有用的。通过这种方式，您可以将这些文件放置在仅在需要它们的页面中的特定部分，并在您希望它们呈现的 HTML 级别调用`RenderSection`方法。这是在`_Layout.cshtml`页面上完成的。

`_ViewImports.cshtml`文件是另一个重要文件；它使应用程序页面可以共享常见指令，并通过在每个页面上放置这些指令来减少工作量。其中定义了所有全局使用的命名空间、标签助手和全局`Pages`命名空间。该文件支持的一些指令如下：

+   `@namespace`：用于为`Pages`设置基本命名空间。

+   `@inject`：用于在页面中放置依赖注入。

+   `@model`：包括`PageModel`，一个将确定页面将处理的信息的类。

+   `@using`：类似于`.cs`文件，此指令允许您在 Razor 页面的顶层完全限定命名空间，以避免在整个代码中重复这些命名空间。

`_ViewStart.cshtml`文件用于放置将在每个页面调用开始时执行的代码。在此页面上，您定义`Layout`属性同时设置`Layout`页面。

现在您已经熟悉了 Razor 页面的基础知识，是时候开始在您的应用程序上工作并深入一些更有趣的主题了。您将首先创建待办事项列表应用程序的基本结构。

## 练习 7.02：使用 Razor 创建看板

本练习的目标是开始创建待办事项应用程序的第一个组件 - 看板。该看板用于控制工作流程，人们可以将他们的工作分成卡片，并在不同状态之间移动这些卡片，例如待办、进行中和已完成。一个使用这种方法的流行应用是 Trello。在*练习 7.01*中创建的相同`ToDoListApp`项目将在本章中用于学习新概念并逐步发展应用程序，包括本练习。执行以下步骤：

1.  转到应用程序的根文件夹并创建一个名为`Models`的文件夹。

1.  在`Models`文件夹中，创建一个名为`ETaskStatus`的新枚举，其中包括`ToDo`，`Doing`和`Done`选项：

```cpp
public enum ETaskStatus {
ToDo,
Doing,
Done
}
```

1.  再次，在 `Models` 文件夹中创建一个名为 `ToDoTask` 的新类，该类将用于为您的待办事项列表创建一个新任务，具有以下属性：

```cpp
namespace ToDoListApp.Models;
public class ToDoTask
{
    public Guid Id { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? DueTo { get; set; }
    public string Title { get; set; }
    public string? Description { get; set; }
    public ETaskStatus Status { get; set; }
}
```

1.  按照以下方式为 `ToDoTask` 类创建两个构造函数：

```cpp
ToDoTask.cs
namespace ToDoListApp.Models;
public class ToDoTask
{
    public ToDoTask()
    {
        CreatedAt = DateTime.UtcNow;
        Id = Guid.NewGuid();
    }
    public ToDoTask(string title, ETaskStatus status) : this()
    {
        Title = title;
        Status = status;
    }
```

```cpp
The complete code can be found here: https://packt.link/nFk00.
```

创建一个没有参数的构造函数，为 `Id` 和 `CreatedAt` 属性设置默认值，另一个使用小写命名参数的构造函数，用于初始化 `Title` 和 `Status` 属性。

`Pages`/ `Index.cshtml` 是在您的应用程序样板中自动生成的。这个页面将是您的应用程序的入口点。

1.  现在，通过编辑 `Pages`/ `Index.cshtml.cs` 文件并用以下代码替换样板代码来自定义它：

```cpp
Index.cshtml.cs
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ToDoListApp.Models;
namespace ToDoListApp.Pages;
public class IndexModel : PageModel
{
    public IList<ToDoTask> Tasks { get; set; } = new List<ToDoTask>();
    public IndexModel()
    {
    }
```

```cpp
The complete code can be found here: https://packt.link/h8mni.
```

基本上，这段代码填充了您的模型。在这里，`PageModel` 的 `OnGet` 方法用于告诉应用程序，当页面加载时，它应该用分配给 `Task` 的属性填充模型。

1.  用以下代码替换`Pages`/ `Index.cshtml`中的代码，以创建您的看板并添加任务卡：

```cpp
Index.cshtml
@page
@using ToDoListApp.Models
@model IndexModel
@{
    ViewData["Title"] = "My To Do List";
}
<div class="text-center">
    <h1 class="display-4">@ViewData["Title"]</h1>
    <div class="row">
        <div class="col-4">
            <div class="card bg-light">
                <div class="card-body">
                    <h6 class="card-title text-uppercase text-truncate py-2">To Do</h6>
                    <div class="border border-light">
```

```cpp
The complete code can be found here: https://packt.link/IhELU.
```

这个页面是您的视图。它与 `Pages`/ `Index.cshtml.cs` 类（也称为代码后台类）共享属性。当您在代码后台类中为 `Tasks` 属性分配一个值时，它将对视图可见。通过这个属性，您可以填充页面的 HTML。

1.  现在，使用 `dotnet run` 命令运行您的应用程序。当应用程序在浏览器上加载时，您将在 `Index` 页面上看到以下内容：

![图 7.3：显示您的第一个应用程序，看板](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_03.jpg)

图 7.3：显示您的第一个应用程序，看板

请注意，目前应用程序不包含任何逻辑。您在这里构建的只是一个由 `PageModel` 数据驱动的用户界面。

注意

您可以在[`packt.link/1PRdq`](https://packt.link/1PRdq)找到此练习中使用的代码。

如您在*练习 7.02*中所见，对于每个创建的页面，都有两种主要类型的文件，即 `.cshtml` 和 `.cshtml.cs` 文件。这些文件构成了每个 Razor 页面的基础。下一节将详细介绍文件名后缀的区别以及这两个文件如何相互补充。

## PageModel

在您在*练习 7.02*中创建的 `Index.cshtml.cs` 文件中，您可能已经注意到其中的类继承自 `PageModel` 类。拥有这个代码后台类提供了一些优势——比如客户端和服务器之间的关注点清晰分离——这使得维护和开发更容易。它还使您能够为放置在服务器上的逻辑创建单元测试和集成测试。您将在*第十章* *自动化测试*中了解更多关于测试的内容。

`PageModel` 可能包含一些绑定到视图的属性。在*练习 7.02*中，`IndexModel` 页面有一个 `List<ToDoTask>` 类型的属性。当页面在 `OnGet()` 方法上加载时，这个属性就会被填充。那么填充是如何发生的呢？下一节将讨论填充属性的生命周期以及在 `PageModel` 中使用它们。

### 带有页面处理程序的生命周期

处理程序方法是 Razor 页面的一个核心特性。当服务器接收到页面的请求时，这些方法会自动执行。例如，在*练习 7.02*中，`OnGet` 方法将在每次页面接收到 `GET` 请求时执行。

按照约定，处理程序方法将根据请求的 HTTP 动词进行响应。例如，如果您希望在 `POST` 请求之后执行某些操作，您应该有一个 `OnPost` 方法。同样，在 `PUT` 请求之后，您应该有一个 `OnPut` 方法。每个方法都有一个异步等效方法，它改变了方法的签名；方法名称后面添加了 `Async` 后缀，并且返回一个 `Task` 属性而不是 `void`。这也使得 `await` 功能对该方法可用。

然而，有一种棘手的情况，您可能希望一个表单执行相同的 HTTP 动词进行多个操作。在这种情况下，您可能需要在后端执行一些混乱的逻辑来处理不同的输入。然而，Razor Pages 为您提供了一个名为`asp-page-handler`的功能，允许您指定在服务器上调用的处理程序的名称。标签助手将在下一节中讨论，但现在，请将以下代码视为示例。该代码包含一个 HTML 表单，其中包含两个提交按钮，用于执行两个不同的操作——一个用于创建订单，另一个用于取消订单。

```cpp
<form method="post">
    <button asp-page-handler="PlaceOrder">Place Order</button>
    <button asp-page-handler="CancelOrder">Cancel Order</button>
</form>
```

在服务器端，您只需要有两个处理程序，一个用于每个操作，如下面的代码所示：

```cpp
public async Task<IActionResult> OnPostPlaceOrderAsync()
{
    // …
}
public async Task<IActionResult> OnPostCancelOrderAsync()
{
    // …
}
```

在这里，页面的代码与`.cshtml`文件上的`form`方法和`asp-page-handler`标签的值匹配到代码后台文件上的方法名称。这样，您可以在同一个表单中为相同的 HTTP 动词拥有多个操作。

关于这个主题的最后一点是，在这种情况下，服务器上的方法名称应该写成：

```cpp
On + {VERB} + {HANDLER}
```

这是带有或不带有`Async`后缀的。在前面的示例中，`OnPostPlaceOrderAsync`方法是`PlaceOrder`按钮的`PlaceOrder`处理程序，`OnPostCancelOrderAsync`是`CancelOrder`按钮的处理程序。

### 使用标签助手渲染可重用的静态代码

您可能已经注意到以前编写的 HTML 很长。您创建了看板卡、列表和一个包装所有内容的看板。如果您仔细查看代码，会发现整个代码都是重复的相同模式。这带来了一个主要问题，即维护。很难想象要处理、维护和演变所有这些纯文本。

幸运的是，标签助手在这方面可以极大地帮助。它们基本上是渲染静态 HTML 代码的组件。ASP.NET 具有一组内置的标签助手，具有自定义服务器端属性，如锚点、表单和图像。标签助手是一个核心功能，有助于处理高级概念，如模型绑定，稍后将进一步讨论。

除了它们为内置 HTML 标签添加了渲染功能之外，它们还是实现静态和重复代码可重用的一种令人印象深刻的方式。在下一个练习中，您将学习如何创建自定义标签助手。

## 练习 7.03：使用标签助手创建可重用组件

在这个练习中，您将改进之前的工作。这里的改进将是通过将可重用的部分移动到自定义标签助手来简化 HTML 代码。

为此，请执行以下步骤：

1.  打开您的应用程序创建的`_ViewImports.cshtml`文件。

1.  在末尾添加以下行来定义自定义标签助手的内容`@addTagHelper`指令：

```cpp
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
@addTagHelper *, ToDoListApp 
```

在上述代码中，您使用星号（`*`）添加了此命名空间中存在的所有自定义标签助手。

1.  现在，在项目的根目录（`ToDoApp`）下创建一个名为`TagHelpers`的新文件夹。

1.  在此文件夹内创建一个名为`KanbanListTagHelper.cs`的新类。

1.  使这个类继承自`TagHelper`类：

```cpp
namespace ToDoListApp.TagHelpers;
```

1.  这种继承是 ASP.NET 识别内置和自定义标签助手的关键。

1.  现在为`Microsoft.AspNetCore.Razor.TagHelpers`命名空间添加一个`using`语句：

```cpp
using Microsoft.AspNetCore.Razor.TagHelpers;
namespace ToDoListApp.TagHelpers;
public class KanbanListTagHelper : TagHelper
{
}
```

1.  对于`KanbanListTagHelper`类，创建两个名为`Name`和`Size`的字符串属性，带有 getter 和 setter：

```cpp
using Microsoft.AspNetCore.Razor.TagHelpers;
namespace ToDoListApp.TagHelpers;
public class KanbanListTagHelper : TagHelper
{
    public string? Name { get; set; }
    public string? Size { get; set; }
}
```

1.  用以下代码覆盖基本的异步`ProcessAsync（TagHelperContext context`，`TagHelperOutput）`输出方法：

```cpp
KanbanListTagHelper.cs
public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
{
     output.TagName = "div";
     output.Attributes.SetAttribute("class", $"col-{Size}");
     output.PreContent.SetHtmlContent(
     $"<div class=\"card bg-light\">"
          + "<div class=\"card-body\">"
          + $"<h6 class=\"card-title text-uppercase text-truncate py-     2\">{Name}</h6>"
          + "<div class \"border border-light\">");
     var childContent = await output.GetChildContentAsync();
     output.Content.SetHtmlContent(childContent.GetContent());
```

```cpp
The complete code can be found here: https://packt.link/bjFIk.
```

每个标签助手都有一个标准的 HTML 标签作为输出。这就是为什么在你的方法开始时，从`TagHelperOutput`对象中调用`TagName`属性来指定将用作输出的 HTML 标签。此外，您可以通过从`TagHelperOutput`对象调用`Attributes`属性和其`SetAttribute`方法来设置此 HTML 标签的属性。这就是在指定 HTML 输出标签之后你所做的。

1.  现在，创建另一个名为`KanbanCardTagHelper.cs`的类，使用相同的继承和命名空间，使用类似于之前的语句：

```cpp
namespace ToDoListApp.TagHelpers;
using Microsoft.AspNetCore.Razor.TagHelpers;
public class KanbanCardTagHelper: TagHelper
{
    public string? Task { get; set; }
}
```

对于这个类，创建一个具有公共 getter 和 setter 的`string`属性，名为`Task`。

1.  在这个新类中，重写基本的同步`Process(TagHelperContext context, TagHelperOutput output)`方法。在这个方法中，编写以下代码：

```cpp
public override void Process(TagHelperContext context, TagHelperOutput output)
{
     output.TagName = "div";
     output.Attributes.SetAttribute("class", "card");
     output.PreContent.SetHtmlContent(
     "<div class=\"card-body p-2\">"
          + "<div class=\"card-title\">");
     output.Content.SetContent(Task);
     output.PostContent.SetHtmlContent(
     "</div>"
          + "<button class=\"btn btn-primary btn-sm\">View</button>"
          + "</div>");
output.TagMode = TagMode.StartTagAndEndTag;
}
```

一个重要的概念是要知道 HTML 内容如何放置在标签助手中。正如你所看到的，代码使用了`TagHelperOutput`对象的三个不同属性来放置内容：

+   `PreContent`

+   `Content`

+   `PostContent`

预和后属性对于设置生成的内容之前和之后非常有用。它们的一个用例是当您想要设置固定内容作为`div`容器、标题和页脚时。

您在这里做的另一件事是设置标签助手将通过`Mode`属性呈现的方式。您使用了`TagMode.StartTagAndEndTag`作为值，因为您使用`div`容器作为标签助手的输出标签，并且`div`元素在 HTML 中既有开始标签又有结束标签。如果输出标签是其他 HTML 元素，例如 email，它是自闭合的，那么您将使用`TagMode.SelfClosing`。

1.  最后，转到 Pages 文件夹下的`Index.cshtml`文件，并用标签助手替换*练习 7.02*中创建的 HTML，使您的代码更加简洁：

```cpp
Index.cshtml 
@page
@using ToDoListApp.Models
@model IndexModel
@{
    ViewData["Title"] = "My To Do List";
}
<div class="text-center">
    <h1 class="display-4">@ViewData["Title"]</h1>
    <div class="row">
        <kanban-list name="To Do" size="4">
            @foreach (var task in Model.Tasks.Where(t => t.Status == ETaskStatus.ToDo))
            {
                <kanban-card task="@task.Description">
                </kanban-card>
```

```cpp
The complete code can be found here: https://packt.link/YIgdp.
```

1.  现在使用以下命令运行应用程序：

```cpp
dotnet run
```

1.  在浏览器中，导航到 Visual Studio 控制台输出提供的 localhost:####地址，就像您在上一个练习中所做的那样：

![图 7.4：浏览器中显示的前端](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_04.jpg)

图 7.4：浏览器中显示的前端

您将在前端看到与之前相同的结果，如*图 7.3*所示。改进之处在于，即使输出相同，您现在有一个更模块化和简洁的代码来维护和发展。

注意

您可以在[`packt.link/YEdiU`](https://packt.link/YEdiU)找到此练习中使用的代码。

在这个练习中，您使用标签助手创建了可重用的组件，生成静态 HTML 代码。现在您可以看到 HTML 代码更加清晰和简洁。下一节将详细介绍通过将 Code Behind 上的内容与 HTML 视图链接起来，使用模型绑定的概念来创建交互式页面。

## 模型绑定

到目前为止，您已经涵盖了帮助创建待办事项应用程序的基础概念。简要回顾一下，主要要点如下：

+   `PageModel`用于向页面添加数据。

+   标签助手为服务器生成的 HTML 添加了自定义静态呈现。

+   处理程序方法定义了页面与 HTTP 请求交互的方式。

构建 Razor Pages 应用程序的一个最终的概念是模型绑定。在处理程序方法中使用的数据以及通过页面模型传递的数据都是通过这种机制呈现的。它包括从 HTTP 请求中提取数据的键/值对，并将它们放置在客户端 HTML 或服务器端代码中，具体取决于绑定的方向，即数据是从客户端到服务器还是从服务器到客户端。

这些数据可能放置在路由、表单或查询字符串中，并绑定到.NET 类型，可以是原始的或复杂的。*练习 7.04*将帮助澄清模型绑定是如何从客户端到服务器的工作的。

## 练习 7.04：创建一个新页面来提交任务

这个练习的目标是创建一个新页面。它将用于创建新的任务，这些任务将显示在看板上。执行以下步骤来完成这个练习：

1.  在项目根文件夹中，运行以下命令：

```cpp
dotnet add package Microsoft.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
```

1.  在项目的根目录下，创建一个名为`Data`的新文件夹，并在其中放置一个`ToDoDbContext`类。这个类将继承自 Entity Framework 的`DbContext`，并将用于访问数据库。

1.  现在在其中添加以下代码：

```cpp
using Microsoft.EntityFrameworkCore;
using ToDoListApp.Models;
namespace ToDoListApp.Data;
public class ToDoDbContext : DbContext
{
    public ToDoDbContext(DbContextOptions<ToDoDbContext> options) : base(options)
    {
    }
    public DbSet<ToDoTask> Tasks { get; set; } 
}
```

1.  更新您的`Program.cs`文件以匹配以下内容：

```cpp
Program.cs
using Microsoft.EntityFrameworkCore;
using ToDoListApp.Data;
using ToDoListApp.Middlewares;
var builder = WebApplication.CreateBuilder(args);
// Add services to the container.builder.Services.AddRazorPages();
builder.Services.AddDbContext<ToDoDbContext>(opt => opt.UseSqlite("Data Source=Data/ToDoList.db")); 
var app = builder.Build();
// Configure the HTTP request pipeline.app.UseMiddleware<RequestLoggingMiddleware>();
```

```cpp
The complete code can be found here: https://packt.link/D4M8o.
```

此更改将在 DI 容器中注册`DbContext`依赖项，并设置数据库访问。

1.  在终端上运行以下命令以安装`dotnet ef`工具。这是一个 CLI 工具，将帮助您与数据库助手进行迭代，例如模式创建和更新：

```cpp
dotnet tool install --global dotnet-ef
```

1.  现在，构建应用程序并在终端上运行以下命令：

```cpp
dotnet ef migrations add 'FirstMigration'
dotnet ef database update
```

这些命令将创建一个新的迁移，该迁移将从您的数据库创建模式，并将此迁移应用到您的数据库。

1.  迁移运行并且数据库更新后，在`Pages`文件夹内创建一个名为`Tasks`的新文件夹。

1.  将 Index 页面文件`index.cshtml`和`index.cshtml.cs`移动到`Tasks`文件夹中。

1.  接下来，在`Program.cs`中用以下调用替换`AddRazorPages`调用：

```cpp
builder.Services.AddRazorPages(opt =>{    opt.Conventions.AddPageRoute("/Tasks/Index", ""); });
```

这将添加一个页面路由的约定。

1.  替换`_Layout.cshtml`文件（在`Pages/Shared/`下）中的标题标签，以创建应用程序的共享`navbar`：

```cpp
<header>
        <nav class="navbar navbar-expand-sm navbar-toggleable-sm navbar-light bg-white border-bottom box-shadow mb-3">
            <div class="container">
                <a class="navbar-brand" asp-area="" asp-page="/Index">MyToDos</a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target=".navbar-collapse" aria-controls="navbarSupportedContent"
                        aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="navbar-collapse collapse d-sm-inline-flex flex-sm-row-reverse">
                    <ul class="navbar-nav flex-grow-1">
                        <li class="nav-item">
                            <a class="nav-link text-dark" asp-area="" asp-page="/tasks/create">Create Task</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
    </header>
```

这个`navbar`将允许您访问新创建的页面。

1.  创建`Create.cshtml`页面（在`Pages/Tasks/`下）并添加以下代码：

```cpp
Create.cshtml
@page "/tasks/create"
@model CreateModel
@{
    ViewData["Title"] = "Task";
}
<h2>Create</h2>
<div>
    <h4>@ViewData["Title"]</h4>
    <hr />
    <dl class="row">
        <form method="post" class="col-6">
            <div class="form-group">
                <label asp-for="Task.Title"></label>
                <input asp-for="Task.Title" class="form-control" />
```

```cpp
The complete code can be found here: https://packt.link/2NjdN.
```

这应该包含一个表单，将使用`PageModel`类来创建新的任务。对于每个表单输入字段，在`input`标签助手内部使用`asp-for`属性。该属性负责在`name`属性中填充 HTML 输入的正确值。

由于您正在绑定到页面模型内的复杂属性`Task`，因此名称值是使用以下语法生成的：

```cpp
{PREFIX}_{PROPERTYNAME} pattern
```

这里`PREFIX`是`PageModel`上的复杂对象名称。因此，对于任务的 ID，客户端会生成一个带有`name="Task_Id"`的输入，并且该输入会使用`value`属性填充，该属性具有来自服务器的`Task.Id`属性值。在页面的情况下，由于您正在创建一个新任务，该字段不会预先填充。这是因为在`OnGet`方法中，您为`PageModel`类的`Task`属性分配了一个新对象。

1.  现在，创建名为`CreateModel.cshtml.cs`的代码后台页面（放在`Pages/Tasks/`中）：

```cpp
Create.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ToDoListApp.Data;
using ToDoListApp.Models;
namespace ToDoListApp.Pages.Tasks;
public class CreateModel : PageModel {
    private readonly ToDoDbContext _context;
    public CreateModel(ToDoDbContext context)
    {
        _context = context;
    }
```

```cpp
The complete code can be found here: https://packt.link/06ciR.
```

提交表单时，表单中的所有值都放在传入的`HttpRequest`中。对`TryUpdateModelAsync`的调用尝试使用这些值填充对象，该对象是请求从客户端带来的。由于表单是使用输入元素中的`name`属性创建的，该方法知道如何提取这些值并将它们绑定到对象。简而言之，这就是模型绑定背后的魔力。

1.  现在，用以下代码替换`Index.cshtml`（在`Pages/Tasks/`下）的代码：

```cpp
Index.cshtml
@page
@using ToDoListApp.Models
@model IndexModel
@{
    ViewData["Title"] = "My To Do List";
}
<div class="text-center">
    @if (TempData["SuccessMessage"] != null)
    {
        <div class="alert alert-success" role="alert">
            @TempData["SuccessMessage"]
        </div>
    }
    <h1 class="display-4">@ViewData["Title"]</h1>
```

```cpp
The complete code can be found here: https://packt.link/hNOTx.
```

此代码添加了一个部分，如果`TempData`字典中存在`SuccessMessage`键的条目，则会显示一个警报。

1.  最后，通过数据注释为`Models/ToDoTask.cs`类的属性添加一些显示和验证规则：

```cpp
ToDoTask.cs
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
namespace ToDoListApp.Models;
public class ToDoTask
{
    public ToDoTask()
    {
        CreatedAt = DateTime.UtcNow;
        Id = Guid.NewGuid();
    }
    public ToDoTask(string title, ETaskStatus status) : this()
    {
```

```cpp
The complete code can be found here: https://packt.link/yau4p.
```

这里对属性使用`Required`数据注释是为了确保该属性设置为有效值。在这个练习中，您使用 Entity Framework Core 和 SQLite 添加了持久性，并创建了一个为待办应用程序创建任务的新页面，最终将其保存到数据库中。

1.  现在在 VS Code 中运行代码。

1.  要在 Web 浏览器中查看输出，请在地址栏中键入以下命令：

```cpp
Localhost:####
```

这里`####`代表端口号。这对不同的系统来说是不同的。

按下回车键后，将显示以下屏幕：

![图 7.5：导航栏中带有创建任务按钮的主页](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_05.jpg)

图 7.5：导航栏中带有创建任务按钮的主页

1.  单击`创建任务`按钮，您将看到刚刚创建的页面，可以在其中向您的看板添加新卡片：

![图 7.6：创建任务页面](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_06.jpg)

图 7.6：创建任务页面

注意

您可以在[`packt.link/3FPaG`](https://packt.link/3FPaG)找到此练习中使用的代码。

现在，您将深入了解模型绑定如何将所有内容整合在一起，使您能够在客户端和服务器之间传输数据。您还将在下一节中了解更多关于验证的内容。

## 验证

验证数据是您在开发应用程序时经常需要执行的操作。验证字段可能意味着它是一个必填字段，或者它应该遵循特定格式。您可能已经注意到在上一个练习的最后部分中，您在最后一步中的某些模型属性顶部放置了一些`[Required]`属性。这些属性称为数据注释，用于创建服务器端验证。此外，您可以结合此技术添加一些客户端验证。

请注意，在*练习 7.04*的*步骤 10*中，前端具有一些 span 标签助手，其中`asp-validation-for`属性指向模型属性。有一件事将所有这些联系在一起——包含`_ValidationScriptsPartial.cshtml`部分页面。部分页面是下一节讨论的主题，但目前只需知道它们是可以在其他页面内重用的页面。刚才提到的页面包含页面的默认验证。

将这三个元素放在一起（即必需注释、`asp-validation-for`标签助手和`ValidationScriptsPartial`页面），就在客户端创建了验证逻辑，防止使用无效值提交表单。如果要在服务器上执行验证，可以使用内置的`TryValidateModel`方法，将要验证的模型传递给它。

## 动态行为与部分页面

到目前为止，您已经构建了一个显示任务和创建和编辑任务的看板。但是，对于待办事项应用程序来说，还有一个重要功能需要添加——一种在看板上移动任务的方法。您可以从简单的一种方式开始——从待办到进行中，从进行中到已完成。

到目前为止，您的任务卡是使用标签助手构建的。但是，标签助手被呈现为`静态`组件，并且在呈现过程中不允许添加任何动态行为。您可以直接将标签助手添加到页面，但是您必须为每个看板列表重复此操作。这正是 Razor Pages 的一个重要功能发挥作用的地方，即部分页面。它们允许您以较小的片段创建可重用的页面代码片段。这样，您可以共享基本页面动态实用程序，同时避免在应用程序中重复代码。

这结束了本节的理论部分。在下一节中，您将通过练习将其付诸实践。

## 练习 7.05：将标签助手重构为具有自定义逻辑的部分页面

在本练习中，您将创建一个部分页面来替换`KanbanCardTagHelper`，并为您的任务卡添加一些动态行为，例如根据自定义逻辑更改内容。您将看到部分页面如何帮助减少重复代码并使其更容易重用。执行以下步骤以完成此练习：

1.  在`Pages/Tasks`文件夹中，创建一个名为`_TaskItem.cshtml`的新文件，内容如下：

```cpp
_TaskItem.cshtml
@model ToDoListApp.Models.ToDoTask
<form method="post">
    <div class="card">
        <div class="card-body p-2">
            <div class="card-title">
                @Model.Title
            </div>
            <a class="btn btn-primary btn-sm" href="/tasks/@Model.Id">View</a>
            @if (Model.Status == Models.ETaskStatus.ToDo)
            {
                <button type="submit" class="btn btn-warning btn-sm" href="@Model.Id" asp-page-handler="StartTask" asp-route-id="@Model.Id">
                    Start 
                </button>
```

```cpp
The complete code can be found here: https://packt.link/aUOcj.
```

`_TaskItem.cshtml`基本上是一个包含看板卡片的`.cshtml`代码的部分页面。

1.  现在，使用以下代码替换`Index.cshtml.cs`文件中的代码，该代码可以从数据库中读取保存的任务，并将您在部分页面上创建的操作放置在其中：

```cpp
Index.cshtml.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ToDoListApp.Data;
using ToDoListApp.Models;
namespace ToDoListApp.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ToDoDbContext _context;
        public IndexModel(ToDoDbContext context)
```

```cpp
The complete code can be found here: https://packt.link/Tqgup.
```

此代码创建了三个 HTTP 请求的处理程序方法——一个 GET 请求和两个 POST 请求。它还放置了要在这些处理程序上执行的逻辑。您将从数据库中读取值并用 POST 将其保存回去。

1.  最后，使用以下代码更新`Index.cshtml`页面，以替换标记助手的使用，使用您的看板卡的部分 Razor 页面：

```cpp
Index.cshtml
@page
@using ToDoListApp.Models
@model IndexModel
@{
    ViewData["Title"] = "MyToDos";
}
<div class="text-center">

    @if(TempData["SuccessMessage"] != null)
    {
        <div class="alert alert-success" role="alert">
            @TempData["SuccessMessage"]
        </div>
```

```cpp
The complete code can be found here: https://packt.link/9SRsY.
```

这样做，您将注意到有多少重复代码被消除了。

1.  现在使用以下命令运行应用程序：

```cpp
dotnet run
```

1.  接下来点击“创建任务”按钮并填写表单。创建任务后，您将看到确认消息，如*图 7.7*所示。

![图 7.7：创建任务后的主屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_07.jpg)

图 7.7：创建任务后的主屏幕

注意

如果您在上一个屏幕上创建了一些任务，则您的系统上的屏幕显示可能会有所不同。

在这个练习中，您创建了一个几乎完全功能的待办事项应用程序，您可以在其中创建任务并将其保存到数据库中，甚至记录您的请求以查看它们花费了多长时间。

注意

您可以在[`packt.link/VVT4M`](https://packt.link/VVT4M)找到此练习使用的代码。

现在，是时候通过一个活动来增强功能了。

## 活动 7.01：创建页面以编辑现有任务

现在是时候通过一个新的基本功能来增强之前的练习，即在看板上移动任务。您必须使用本章涵盖的概念构建此应用程序，例如模型绑定、标记助手、部分页面和 DI。

要完成此活动，您需要添加一个页面来编辑任务。以下步骤将帮助您完成此活动：

1.  创建一个名为`Edit.cshtml`的新文件，其表单与`Create.cshtml`相同。

1.  将页面指令中的路由更改为接收`"/tasks/{id}"`。

1.  创建代码后端文件，通过`DbContext`模式的`OnGet ID`加载任务。如果 ID 没有返回任务，则将其重定向到`Create`页面。

1.  在 Post 表单上，从数据库中恢复任务，更新其值，发送成功消息，然后重定向到 Index 视图。

页面的输出如下所示：

![图 7.8：作为活动输出的编辑任务页面](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_08.jpg)

图 7.8：作为活动输出的编辑任务页面

注意

此活动的解决方案可在[`packt.link/qclbF`](https://packt.link/qclbF)找到。

通过迄今为止的示例和活动，您现在知道如何使用 Razor 开发页面。在下一节中，您将学习如何使用一个具有更小范围的隔离和可重用逻辑的工具，即视图组件。

# 视图组件

到目前为止，您已经看到了两种创建可重用组件的方法，以提供更好的维护并减少代码量，即标记助手和部分页面。虽然标记助手主要生成静态 HTML 代码（因为它将自定义标记转换为带有一些内容的现有 HTML 标记），但`部分页面`是另一个 Razor 页面，它共享页面数据绑定机制，并且可以执行一些操作，例如表单提交。`部分页面`唯一的缺点是其动态行为依赖于包含它的页面。

本节介绍了另一种工具，允许您创建可重用组件，即视图组件。视图组件与部分页面有些相似，因为它们也允许您提供动态功能并在后端具有逻辑。但是，它们更加强大，因为它们是自包含的。这种自包含性使它们能够独立于页面开发，并且可以完全在其自身上进行测试。

创建视图组件有几个要求，如下所示：

+   自定义组件类必须继承自`Microsoft.AspNetCore.Mvc.ViewComponent`。

+   它必须在类名中具有`ViewComponent`后缀，或者用`[ViewComponent]`属性进行修饰。

+   这个类必须实现一个`IViewComponentResult Invoke()`同步方法或一个`Task<IViewComponentResult> InvokeAsync()`异步方法（当您需要从中调用异步方法时）。

+   前两种方法的结果通常是`View(model)`方法，其中视图组件模型作为参数。在前端，默认视图文件名应按照惯例称为`Default.cshtml`。

+   为了渲染视图，它必须位于`Pages/Components/{MY_COMPONENT_NAME}/Default.cshtml`或`/Views/Shared/Components/{MY_COMPONENT_NAME}/Default.cshtml`中。

+   如果不位于前述路径中的任何位置，则必须在`Invoke`或`InvokeAsync`方法中返回的`View`方法的参数中显式传递视图的位置。

这结束了本节的理论部分。在接下来的部分中，您将通过一个练习将这些理论付诸实践。

## 练习 7.06：创建一个视图组件来显示任务统计

在这个练习中，您将创建一个视图组件，允许您在应用程序的导航栏上显示有关延迟任务的一些统计信息。通过完成这个练习，您将学习视图组件的基本语法以及如何将它们放置在 Razor 页面中。执行以下步骤来完成：

1.  在`ToDoListApp`项目的根目录下，创建一个名为`ViewComponents`的新文件夹。

1.  在这个文件夹内，创建一个名为`StatsViewComponent`的新类：

```cpp
namespace ToDoListApp.ViewComponents;
public class StatsViewComponent
{
}
```

1.  再次，在`ViewComponents`文件夹内，创建一个名为`StatsViewModel`的新类，具有两个名为`Delayed`和`DueToday`的公共`int`属性。

```cpp
namespace ToDoListApp.ViewComponents;
public class StatsViewModel
{
    public int Delayed { get; set; }
    public int DueToday { get; set; }
}
```

1.  编辑`StatsViewComponent`类，使其继承自`Microsoft.AspNetCore.Mvc`命名空间中包含的`ViewComponent`类：

```cpp
using Microsoft.AspNetCore.Mvc;
public class StatsViewComponent : ViewComponent
{
}
```

1.  通过构造函数注入`ToDoDbContext`，初始化一个`private readonly`字段：

```cpp
public class StatsViewComponent : ViewComponent
{
    private readonly ToDoDbContext _context;
    public StatsViewComponent(ToDoDbContext context) => _context = context;
}
```

放置正确的`using`命名空间。

1.  创建一个名为`InvokeAsync`的方法，具有以下签名和内容：

```cpp
StatsViewComponent.cs
using ToDoListApp.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
namespace ToDoListApp.ViewComponents;
public class StatsViewComponent : ViewComponent
{
    private readonly ToDoDbContext _context;
    public StatsViewComponent(ToDoDbContext context) => _context = context;
    public async Task<IViewComponentResult> InvokeAsync()
    {
        var delayedTasks = await _context.Tasks.Where(t =>
```

```cpp
The complete code can be found here: https://packt.link/jl2Ue.
```

这个方法将使用`ToDoDbContext`来查询数据库并检索延迟的任务，以及当天到期的任务。

1.  现在，在`Pages`文件夹下，创建一个名为`Components`的新文件夹。

1.  在其下创建一个名为`Stats`的文件夹。

1.  然后，在`Stats`文件夹内，创建一个名为`default.cshtml`的新文件，内容如下：

```cpp
@model ToDoListApp.ViewComponents.StatsViewModel
<form class="form-inline my-2 my-lg-0">
    @{
         var delayedEmoji = Model.Delayed > 0 ? "" : "";
         var delayedClass = Model.Delayed > 0 ? "btn-warning" : "btn-success";
         var dueClass = Model.DueToday > 0 ? "btn-warning" : "btn-success";
     }
    <button type="button" class="btn @delayedClass my-2 my-sm-0">
        <span class="badge badge-light">@Model.Delayed</span> Delayed Tasks @delayedEmoji
    </button>
    &nbsp;
    <button type="button" class="btn @dueClass my-2 my-sm-0">
        <span class="badge badge-light">@Model.DueToday</span> Tasks Due Today 
    </button>
</form>
```

`default.cshtml`将包含视图组件类的视图部分。在这里，您基本上是根据指定的模型创建了一个`.cshtml`文件。

1.  最后，在`_Layout.cshtml`（在`Pages/Shared/`下），通过在导航栏内添加`<vc:stats></vc:stats>`标签来调用`ViewComponent`。用以下代码替换页面代码：

```cpp
_Layout.cshtml
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>@ViewData["Title"] - ToDoListApp</title>
    <link rel="stylesheet" href="~/lib/bootstrap/dist/css/bootstrap.min.css" />
    <link rel="stylesheet" href="~/css/site.css" asp-append-version="true" />
    <link rel="stylesheet" href="~/ToDoListApp.styles.css" asp-append-version="true" />
</head>
<body>
    <header>
        <nav class="navbar navbar-expand-sm navbar-toggleable-sm navbar-light bg-white border-bottom box-shadow mb-3">
```

```cpp
The complete code can be found here: https://packt.link/DNUBC.
```

1.  运行应用程序，查看您的导航栏，如*图 7.8*所示：

图 7.9：任务统计视图组件



图 7.9：任务统计视图组件

在这个练习中，您创建了您的第一个视图组件，它是一个显示在导航栏上的任务统计。正如您可能已经注意到的那样，关于视图组件的一个高效的事情是，它们与显示在上面的页面是独立的。您可以在组件内部构建前端和后端，而不依赖于页面上的外部依赖。

注意

您可以在[`packt.link/j9eLW`](https://packt.link/j9eLW)找到此练习中使用的代码。

本练习涵盖了视图组件，它允许您在应用程序的导航栏上显示有关延迟任务的一些统计信息。有了这些知识，您现在将完成一个活动，在其中您将在一个视图组件中工作以显示日志历史记录。

## 活动 7.02：编写一个视图组件来显示任务日志

作为本章的最后一步，这个活动将基于现实世界应用中的常见任务——记录用户活动日志。在这种情况下，您将把用户对字段所做的每一次更改写入数据库，并在视图中显示出来。为此，您需要使用一个视图组件。

以下步骤将帮助您完成此活动：

1.  在`Models`文件夹下创建一个名为`ActivityLog`的新类。该类应具有以下属性：`Guid Id`、`String EntityId`、`DateTime` `Timestamp`、`String Property`、`String OldValue`和`String NewValue`。

1.  为此模型在`ToDoDbContext`下创建一个新的`DbSet<ActivityLog>`属性。

1.  在您的`DbContext`下，创建一个方法，为 Entity Framework 的`ChangeTracker`下的`Entries`的修改属性生成活动日志。

1.  在`DbContext`中覆盖`SaveChangesAsync()`，在调用`base`方法之前将生成的日志添加到`DbSet`中。

1.  创建一个新的 Entity Framework Core 迁移，并更新数据库以支持此迁移。

1.  创建`ViewComponent`类，应在调用时加载给定`taskId`的所有日志，并将它们返回给`ViewComponent`。

1.  创建`ViewComponent`视图，应以`ActivityLog`的集合作为模型，并在 Bootstrap 表中显示它们（如果存在）。如果没有记录日志，则显示一个警报，说明没有可用的日志。

1.  将视图组件添加到“编辑”页面，传递`taskId`属性。

1.  运行应用程序并通过打开任务的详细信息来检查最终输出。您将在右侧看到一个框，其中包含您的活动日志，或者如果尚未记录该任务的任何活动日志，则显示一个没有日志的消息。

![图 7.10：显示没有日志的活动日志](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_07_10.jpg)

图 7.10：显示没有日志的活动日志

在这个活动中，您能够创建一个独立的视图组件，具有全新的功能，与页面解耦，使其能够一次处理一个功能。

注意

可以在[`packt.link/qclbF`](https://packt.link/qclbF)找到此活动的解决方案。

# 总结

在本章中，您学习了使用 C#和 Razor Pages 构建现代 Web 应用程序的基础知识。您在本章的开头专注于重要概念，如中间件、日志记录、DI 和配置。接下来，您使用 Razor Pages 创建了 CRUD 模型，还使用了一些更高级的功能，如自定义标签助手、部分页面和视图组件，这些功能使您能够创建更易于维护的应用程序功能。

最后，您了解了 ASP.NET 模型绑定的工作原理，以便在客户端和服务器之间实现双向数据绑定。到目前为止，您应该已经具备了使用 ASP.NET 和 Razor Pages 构建现代 Web 应用程序的有效基础。

在接下来的两章中，您将学习有关构建和与 API 进行通信的内容。


# 第八章：创建和使用 Web API 客户端

概述

在本章中，您将通过使用 Web 浏览器、自己的 HTTP 客户端和 NuGet 软件包以多种方式与 Web API 进行交互，进入 HTTP 实践的世界。您将学习涉及 Web API 的安全基础知识，使用 PayPal 进行沙盒支付，并探索云服务，如 Azure 文本分析和 Azure Blob 存储。

在本章结束时，您将能够阅读 HTTP 请求和响应消息，调用任何 Web API，并创建自己的 HTTP 客户端以简化与复杂 API 的工作。您还将能够解剖和学习任何形式的传入 HTTP 请求和传出 HTTP 响应，并使用 Chrome 浏览器中的开发工具检查在浏览您喜爱的网站时来回移动的流量。

# 介绍

万维网（WWW）（或者只是网络）是各种文档（XML、JSON、HTML、MP3、JPG 等）的大型存储库，可通过统一资源定位符（URL）访问。在网络上下文中，文档通常称为资源。一些资源不会改变。它们存储在某个地方，每次请求时都会返回相同的资源。这些资源称为静态资源。其他资源是动态的，这意味着它们将根据需要生成。

网络通信通过协议进行。在检索文档的情况下，您使用超文本传输协议（HTTP）。超文本是一种特殊的文本，其中包含指向网络资源的链接。单击它会打开它指向的资源。HTTP 基于客户端-服务器架构。简单来说，客户端发送请求，服务器响应。实践中的一个例子是浏览器（客户端）与网站（托管在服务器上）之间的通信。通常，一个服务器为多个客户端提供服务：

![图 8.1：客户端-服务器架构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_01.jpg)

图 8.1：客户端-服务器架构

当您导航到一个网站时，您发送一个`HTTP GET`请求，服务器通过在浏览器中显示相关站点内容来做出响应。`GET`是一个 HTTP 动词，用于标识请求应该如何处理。常见的 HTTP 动词如下：

+   `GET`: 获取资源。

+   `POST`: 创建资源或发送复杂查询。

+   `PUT`: 更新所有资源字段。

+   `PATCH`: 更新单个字段。

+   `DELETE`: 删除资源。

# 浏览器

现代浏览器不仅是访问互联网内容的工具。它包括用于解剖网站元素、检查流量甚至执行代码的工具。浏览器的这一方面称为开发者工具。确切的键绑定可能有所不同，但按下`F12`或`Control + Shift + I`应该调出开发者工具选项卡。执行以下步骤以更好地了解它：

1.  打开谷歌浏览器或任何其他浏览器。

1.  导航到[google.com](http://google.com)。按下键`Control + Shift + I`。

1.  转到`Network`（`1`）。应该显示以下窗口：

![图 8.2：打开带有 google.com 的开发者工具的 Chrome](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_02.jpg)

图 8.2：打开带有 google.com 的开发者工具的 Chrome

1.  选择第一个条目，[www.google.com](http://www.google.com)（`2`）。

1.  点击`Headers`（`3`）。

1.  在`General`（`4`）部分，您可以观察到当您导航到[google.com](http://google.com)时的效果。发生的第一件事是发送了`HTTP GET`请求到[`www.google.com/`](https://www.google.com/)。

1.  在`Request Headers`部分（`5`），您可以看到与请求一起发送的元数据。

1.  要查看谷歌的响应，请点击`Response`部分（`6`）。

这种流程称为客户端-服务器架构，以下内容适用：

+   客户端是 Chrome 浏览器，它向[google.com](http://google.com)发送请求。

+   服务器是托管[google.com](http://google.com)并响应[google.com](http://google.com)网站内容的机器（S）。

# Web API

应用程序编程接口（API）是一个通过代码调用某些功能的接口。它可以是 C#中的类或接口，也可以是浏览器（您可以通过其自己的接口提供的代码与其交互），但在 HTTP 的上下文中，它是一个 Web 服务。Web 服务是托管在远程计算机上通过 HTTP 可访问的 API。用于在 Web API 上调用单个功能的访问点称为端点。最常用的 Web API 类型是 RESTful。

## RESTful API

表述状态转移（REST）API 是建立在以下六个原则上的 API。无论您使用何种框架实现 RESTful API，都应该预期四个原则：

+   客户端-服务器：客户端和服务器之间建立连接。客户端发送请求以获取服务器的响应。

+   无状态：服务器将能够处理请求，而不考虑之前的请求。这意味着每个请求都应包含所有信息，而不是依赖服务器记住之前发生的事情。

+   可缓存：能够指定可以使用 HTTP 方法或标头缓存哪些请求。

+   按需代码（可选）：REST 允许在客户端上下载并执行脚本。在互联网主要由静态页面组成的早期，这是有用的，但现在要么不需要，要么被视为安全风险。

然而，另外两个原则（客户端-服务器和无状态）取决于您，因此您将希望更加关注它们。分层系统是由层构成的系统，每个层只与直接下面的层通信。这的典型例子是三层架构，其中您将分离表示、业务逻辑和数据存储。从实际角度来看，这意味着 RESTful API（业务逻辑层）不应发送 HTML 作为响应，因为呈现输出的责任在于客户端（表示层）。

最后一个原则称为统一接口。它定义了 API 的一组规则：

+   资源的识别：

其中一些例子是获取资源的所有实例（`/resource`）、创建资源（`/resource`）、获取单个资源（`/resource/id`）以及获取资源中子资源的所有实例（`/resource/subresource/`）。

+   通过这些表示来操作资源：

使用代表创建、读取、更新和删除（CRUD）的 HTTP 动词来操作资源——`GET`、`UPDATE`、`PUT`、`PATCH`、`DELETE`。

+   自描述消息：

响应包含所有所需信息，没有任何额外的文档，并指示消息应如何处理（标头、媒体类型等）。

+   超媒体作为应用状态的引擎（HATEOAS）：

响应中包含所有相关资源的超链接，以便您可以导航到它们。通常会忽略这个指南。

REST 不同于 HTTP。REST 是一组指南，而 HTTP 是一种协议。两者可能会混淆，因为 HTTP 的约束与 REST 的约束（方法、标头等）有很大的重叠。然而，RESTful API 不必使用 HTTP 才能成为 RESTful，同时 HTTP 也可以通过使用会话或查询参数来违反 REST 的约束，以提供要执行的操作。RESTful API 可以使用 XML 和 JSON 数据格式。然而，几乎所有的场景都涉及 JSON。

## Postman

Postman 是用于测试不同类型 Web API 的最流行工具之一。它易于设置和使用。Postman 就像浏览器一样，充当 HTTP 客户端。要下载 Postman，请转到[`www.postman.com/`](https://www.postman.com/)。您需要注册然后下载安装程序。安装了 Postman 后，请执行以下步骤：

1.  打开 Postman。

1.  通过单击“工作区”然后单击“创建工作区”来创建您的工作区。

1.  在新窗口中，转到`Collections`选项卡（`2`），并点击`Create new Collection`（+）按钮（`3`）。

1.  创建一个`New Collection`（`4`）。

1.  点击`Add a request`（`5`）：

![图 8.3：没有请求的新 Postman 集合](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_03.jpg)

图 8.3：没有请求的新 Postman 集合

一个新的请求窗口将打开。

1.  点击`New Request`旁边的编辑符号，并将新请求命名为`Users`（`6`）。

1.  选择`GET` HTTP 动词并复制粘贴 URL [`api.github.com/users/github-user`](https://api.github.com/users/github-user) (`7`)。

注意

在这里，以及所有接下来的地方，用你自己的 GitHub 用户名替换`github-user`。

1.  点击`Send`按钮（`8`）。

1.  现在向下滚动以查看返回的响应结果（`9`）：

![图 8.4：在 Postman 中获取 GitHub 用户请求](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_04.jpg)

图 8.4：在 Postman 中获取 GitHub 用户请求

当涉及到充当 HTTP 客户端时，Postman 比浏览器更优越。它专注于形成 HTTP 请求，并紧凑地显示响应信息，提供多种输出格式。在 Postman 中，你可以使用多个环境，设置请求的前后条件，自动化调用等等，但是深入了解这些高级功能超出了本章的范围。现在，了解 Postman 是一个用于手动测试 Web API 的必备工具就足够了。

## 客户端

REST 需要客户端和服务器之间的通信。在前面的示例中，客户端角色由浏览器或 Postman 扮演。然而，既不是浏览器也不是 Postman 可以在你的代码中替代客户端。相反，你需要使用 C#创建一个 HTTP 请求。

流行的 Web API 通常会为你创建一个客户端（在大多数常见的语言中也是如此）。Web API 客户端的目的是简化与底层 API 的交互。例如，不是在不支持的端点上发送`DELETE`请求并收到响应`Method Not Allowed`，你在自定义客户端上甚至不会有这样的选项。

## Octokit

Octokit 是一个 GitHub API 客户端。它通过一个 C#类公开，通过该类你可以传递对象来调用 GitHub。这样一个客户端的好处是你不需要担心要传递哪些头部或者如何命名事物以便它们被正确序列化。API 客户端会为你处理所有这些。

你可以通过在 VS Code 终端或命令提示符中运行以下命令来在项目中安装 Octokit 客户端：

```cpp
dotnet add package Octokit
```

一旦你安装了 Octokit 客户端，你就可以使用它来创建一个 GitHub 客户端，如下所示：

```cpp
var github = new GitHubClient(new ProductHeaderValue("Packt"));
```

在前面的片段中，你需要一个新的`ProductHeaderValue`，因为 GitHub 需要一个`UserAgent`头部。正如前面提到的，自定义 HTTP 客户端可以在你发出请求之前防止错误发生。在这种情况下，不提供`UserAgent`头部（通过`ProductHeaderValue`）不是一个选项。

要查看客户端是否工作，请尝试获取有关用户名`github-user`的信息：

```cpp
const string username = "github-user";
var user = await github.User.Get(username);
```

注意

在 GitHub 中，`github-user`显示为`Almantask`。最好将其更改为你个人的 GitHub 用户名以使代码正常工作。

要打印用户创建日期，输入以下代码：

```cpp
Console.WriteLine($"{username} created profile at {user.CreatedAt}");
```

你将看到以下输出：

```cpp
github-user created profile at 2018-06-22 07:51:56 +00:00
```

GitHub API 上的每个可用方法也都可以在**GitHub 客户端 Octokit**上使用。你不需要担心端点、强制头部、响应或请求格式；这一切都由强类型的客户端定义。

注意

你可以在[`packt.link/DK2n2`](https://packt.link/DK2n2)找到本示例使用的代码。

## API 密钥

对于许多公共免费的 API，你可能会面临以下问题：

+   你如何控制大量的请求？

+   在什么时候应该收费哪个客户端？

如果所有这些公共 API 只提供匿名访问，您将无法识别客户端或确定每个客户端进行了多少次调用。API 密钥作为身份验证（识别客户端）和授权（授予他们对 API 执行某些操作的访问权限）的最基本手段。简而言之，API 密钥允许您调用 API。没有它，您几乎无法访问 API。

为了更好地理解 API 密钥的使用，下一节将介绍一个需要 API 密钥的 Web API，即 Azure 文本分析。

## Azure 文本分析

Azure 文本分析是用于以下方式分析文本的 Azure API：

+   识别命名实体（人物、事件、组织）

+   解释文本的情绪（积极、消极、中性）

+   生成文档摘要或突出关键短语

+   处理非结构化的医疗数据，例如识别人员、分类诊断等

为了演示 Azure 文本分析 API，您将专注于情感分析。这是根据积极、消极或中性置信度评估文本的过程：

+   1 分的得分表示 100%的概率，即预测（消极、积极、中性）是正确的。

+   0 分的得分表示 0%的概率，即是不可能的预测。

注意

使用 Azure 文本分析是免费的，直到您分析超过 30 天内的 5000 个单词。

在开始编码之前，您需要在 Azure 云上设置 Azure 文本分析。毕竟，您需要端点和 API 密钥才能调用此 API。

注意

确保您已设置了 Azure 订阅。如果没有，请转到[`azure.microsoft.com/en-gb/free/search`](https://azure.microsoft.com/en-gb/free/search)并按照那里的说明创建一个**免费**订阅。Azure 免费试用提供许多免费服务。其中一些服务甚至在一年后仍然免费。学生订阅是获得 Azure 积分和免费服务更长时间的选项。创建 Azure 订阅需要信用卡或借记卡；但是，除非超出免费服务限制的给定 Azure 积分，否则不会收费。

Azure 文本分析可以用于对正面和负面反馈进行分类的一种方法是确定您写的内容是被动攻击还是友好的。要了解这一点，请按照以下步骤创建一个分析您输入到控制台的任何文本的小应用程序：

1.  首先，转到[`portal.azure.com/#create/Microsoft.CognitiveServicesTextAnalytics`](https://portal.azure.com/#create/Microsoft.CognitiveServicesTextAnalytics)。

1.  单击“继续创建您的资源”而不使用任何其他功能：

![图 8.5：Azure 文本分析资源创建](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_05.jpg)

图 8.5：Azure 文本分析资源创建

1.  在创建文本分析窗口中，单击“基本”选项卡。这是在创建新资源时打开的第一个选项卡。

1.  在“订阅”和“资源组”字段中选择一个选项：

![图 8.6：输入新资源创建的项目详细信息](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_06.jpg)

图 8.6：输入新资源创建的项目详细信息

1.  然后，选择地区，例如“北欧”。

1.  输入名称，例如`Packt-Test`。

1.  然后，选择“免费 F0”定价层，并单击“审核+创建”按钮：

![图 8.7：Azure 文本分析定价层](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_07.jpg)

图 8.7：Azure 文本分析定价层

将显示一个确认您输入的新窗口。

1.  单击“创建”选项。文本分析 API 将开始部署。服务部署完成后，将打开一个新窗口，显示“您的部署已完成”。

1.  单击“转到资源”按钮：

![图 8.8：文本分析 API 显示部署已完成](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_08.jpg)

图 8.8：文本分析 API 显示部署已完成

显示文本分析资源窗口。

1.  单击`Keys and Endpoint`选项。您将看到`Endpoint`选项以及`KEY 1`和`KEY 2`，以调用此 API。您可以从这两个密钥中选择一个：

![图 8.9：带有 API 密钥超链接的 Azure Text Analytics 快速入门窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_09.jpg)

图 8.9：带有 API 密钥超链接的 Azure Text Analytics 快速入门窗口

1.  跟踪`KEY 1`（API 密钥）。API 密钥是一个秘密，不应以纯文本形式暴露。您将再次使用环境变量来存储它。

创建具有键和值对的环境变量。值将是连接到 Azure Text Analytics 所需的端点 API 密钥。为了帮助识别缺失的环境变量，使用一个辅助类。`GetOrThrow`方法将获取用户环境变量，如果不存在，将抛出异常：

```cpp
    public static class EnvironmentVariable
    {
        public static string GetOrThrow(string environmentVariable)
        {
            var variable = Environment.GetEnvironmentVariable(environmentVariable, EnvironmentVariableTarget.User);
            if (string.IsNullOrWhiteSpace(variable))
            {
                throw new ArgumentException($"Environment variable {environmentVariable} not found.");
            }
            return variable;
        }
    }
```

1.  跟踪`Endpoint`选项。您将在即将进行的练习中使用它来调用刚刚部署的 API。

本节帮助您在 Azure 云上设置 Azure Text Analytics，除了设置端点和 API 密钥以调用 API 之外。在接下来的练习中，您将使用 Azure Text Analytics 客户端调用 API。

## 练习 8.01：对任何文本进行情感文本分析

Azure Text Analytics 只是另一个 REST API。再次向其发出 HTTP 调用并获得响应。这次，您将发送一段文本以获取其情感分析。再次练习使用强类型客户端并从 C#调用 RESTful API。

使用最近部署的 Azure Text Analytics 服务（在本例中为`Pack-Test`），对您想要的任何文本进行情感分析。执行以下步骤完成此练习：

1.  安装`Azure.AI.TextAnalytics` NuGet 包，以获取 Azure Text Analytics API 客户端，如下所示：

```cpp
dotnet add package Azure.AI.TextAnalytics
```

1.  添加`TextAnalysisApiKey`环境变量。

1.  然后添加`TextAnalysisEndpoint`环境变量。

1.  创建一个`Demo`类，并添加对您最近添加的两个环境变量的引用：

```cpp
public class Demo
{
    private static string TextAnalysisApiKey { get; } = EnvironmentVariable.GetOrThrow("TextAnalysisApiKey");
    private static string TextAnalysisEndpoint { get; } = EnvironmentVariable.GetOrThrow("TextAnalysisEndpoint");
```

这些属性用于隐藏 API 密钥和端点的敏感值。

1.  创建一个新的`BuildClient`方法来构建 API 客户端：

```cpp
static TextAnalyticsClient BuildClient()
{
    var credentials = new AzureKeyCredential(TextAnalysisApiKey);
    var endpoint = new Uri(TextAnalysisEndpoint);
    var client = new TextAnalyticsClient(endpoint, credentials);
    return client;
}
```

API 客户端在初始化期间需要基本 URL（一种统一资源标识符（URI））和 API 密钥，这两者都将在初始化期间传递给它。

1.  使用客户端，创建`PerformSentimentalAnalysis`方法来分析文本：

```cpp
private static async Task<DocumentSentiment> PerformSentimentalAnalysis(TextAnalyticsClient client, string text)
{
    var options = new AnalyzeSentimentOptions { IncludeOpinionMining = true };
    DocumentSentiment documentSentiment = await client.AnalyzeSentimentAsync(text, options: options);
    return documentSentiment;
}
```

在这里，您正在使用配置对象`AnalyzeSentimentOptions`来提取目标和对它们的意见。客户端具有`AnalyzeSentimentAsync`和`AnalyzeSentiment`方法。对于公共客户端库，公开同一方法的异步和非异步版本是非常常见的情况。毕竟，并不是每个人都会对异步 API 感到舒适。但是，当调用另一个机器（数据库、API 等）时，最好使用异步 API。这是因为异步调用不会阻塞进行调用的线程，而是在等待 API 响应时。

1.  现在创建`DisplaySentenceSymmary`函数来显示句子的整体评估：

```cpp
private static void DisplaySentenceSummary(SentenceSentiment sentence)
{
    Console.WriteLine($"Text: \"{sentence.Text}\"");
    Console.WriteLine($"Sentence sentiment: {sentence.Sentiment}");
    Console.WriteLine($"Positive score: {sentence.ConfidenceScores.Positive:0.00}");
    Console.WriteLine($"Negative score: {sentence.ConfidenceScores.Negative:0.00}");
    Console.WriteLine($"Neutral score: {sentence.ConfidenceScores.Neutral:0.00}{Environment.NewLine}");
}
```

1.  创建`DisplaySentenceOpinions`函数，以显示句子中每个目标的`Opinions`消息：

```cpp
private static void DisplaySentenceOpinions(SentenceSentiment sentence)
{
    if (sentence.Opinions.Any())
    {
        Console.WriteLine("Opinions: ");
        foreach (var sentenceOpinion in sentence.Opinions)
        {
            Console.Write($"{sentenceOpinion.Target.Text}");
            var assessments = sentenceOpinion
                .Assessments
                .Select(a => a.Text);
            Console.WriteLine($" is {string.Join(',', assessments)}");
            Console.WriteLine();
        }
    }
}
```

句子的目标是具有应用于它的意见（语法修饰语）的主题。例如，对于句子**a beautiful day**，**day**将是一个目标，**beautiful**是一个意见。

1.  要在控制台中对文本进行情感分析，请创建一个`SentimentAnalysisExample`方法：

```cpp
static async Task SentimentAnalysisExample(TextAnalyticsClient client, string text)
{
    DocumentSentiment documentSentiment = await PerformSentimentalAnalysis(client, text);
    Console.WriteLine($"Document sentiment: {documentSentiment.Sentiment}\n");
    foreach (var sentence in documentSentiment.Sentences)
    {
        DisplaySentenceSummary(sentence);
        DisplaySentenceOpinions(sentence);
    }
}
```

在上述代码片段中，分析文本评估了整体文本的情绪，然后将其分解为句子，并对每个句子进行评估。

1.  为了演示您的代码如何工作，创建一个静态的`Demo.Run`方法：

```cpp
public static Task Run()
{
    var client = BuildClient();
    string text = "Today is a great day. " +
                       "I had a wonderful dinner with my family!";
    return SentimentAnalysisExample(client, text);
}
```

正确设置环境变量后，应显示以下输出：

```cpp
Document sentiment: Positive
Text: "Today is a great day."
Sentence sentiment: Positive
Positive score: 1,00
Negative score: 0,00
Neutral score: 0,00
Text: "I had a wonderful dinner with my family!"
Sentence sentiment: Positive
Positive score: 1,00
Negative score: 0,00
Neutral score: 0,00
Opinions:
dinner is wonderful
```

在这里没有硬编码 API 密钥的值，因为公开的 API 密钥使用不当可能会带来风险。如果被盗，可能会产生灾难性后果（例如被滥用、创建虚假资源、泄露数据、删除数据等）。这就是为什么在处理机密信息时，使用尽可能少的对策，也就是环境变量。

环境变量的另一个好处是在不同环境（本地、集成、系统测试、生产等）中具有不同的值的能力。不同的环境通常使用不同的资源。因此，通过环境变量指向这些资源将不需要对代码进行任何更改。

为了运行这个练习，去[`packt.link/GR27A`](https://packt.link/GR27A)并注释掉`static void` `Main(string[] args)`体内的所有行，除了`await Exercises.Exercise01.Demo.Run();`。同样，在执行每个练习/示例/活动之前，取消注释`Program.cs`中相应的练习/示例/活动的代码行。

注意

你可以在[`packt.link/y1Bqy`](https://packt.link/y1Bqy)找到用于这个练习的代码。

这个练习只是你使用公共 Web API 的众多练习之一。Azure 充满了这样的服务。使用强类型客户端调用 API 很简单；然而，并非所有 API 都有。在下一节中，你将学习如何创建自己的 Web API 客户端。

# 你自己的客户端

到目前为止，你只使用了一个预制的客户端来消费 Web API。然而，对于不太流行的 API，可能没有客户端供你使用。在这种情况下，你将不得不自己进行 HTTP 调用。在.NET 中，进行调用的方式已经有了很大的发展。如果你不想使用第三方库，你可以使用`HttpClient`类。

## HttpClient

在这一节中，你将重复 GitHub`Users`示例（来自*Postman*部分），但这次使用`HttpClient`。这个流程非常简单，并且在下面的示例中为你详细描述：

1.  在`GitHttp`静态类中，创建`GetUser`方法：

```cpp
public static async Task GetUser()
```

1.  在`GitExamples`方法中，首先创建一个客户端：

```cpp
client = new HttpClient { BaseAddress = new Uri("https://api.github.com") };
client.DefaultRequestHeaders.Add("User-Agent", "Packt");
```

几乎总是需要指定特定基本 URL 来创建客户端。通常，Web API 要求传递强制性标头，否则它们将使请求无效（`400 Bad Request`）。对于 GitHub，你需要发送`User-Agent`标头来标识调用 API 的客户端。将`Packt`用户代理标头添加到默认标头将在每个请求发送到客户端时发送该标头。

1.  然后，你可以按以下方式创建一个请求：

```cpp
const string username = "github-user"; //replace with your own
var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"users/{username}", UriKind.Relative));
```

记得用你自己的 GitHub 用户名替换`github-user`。在这里，你指定要创建一个`GET`请求。你没有指定完整的路径，而是只指定了你要访问的端点；因此，你必须将`UriKind`标记为`Relative`。

1.  接下来，使用客户端发送请求：

```cpp
var response = await client.SendAsync(request);
```

只有一个发送 HTTP 请求消息的异步版本，所以你需要等待它。发送`HttpRequestMessage`的结果是`HttpResponseMessage`。

1.  然后，按以下方式将内容反序列化为可用对象：

```cpp
var content = await response.Content.ReadAsStringAsync();
var user = JsonConvert.DeserializeObject<User>(content);
```

反序列化是将结构化文本（如 JSON）转换为内存对象的行为。为此，你需要将内容转换为字符串，然后进行反序列化。你可以使用 Octokit NuGet 中的用户模型。由于你已经在进行自定义调用，那么你可能也会使用自定义模型。对于最基本的（只使用的字段），你的模型可能如下所示：

```cpp
public class User
{
    public string Name { get; set; }
    [JsonProperty("created_at")]
    public DateTime CreatedAt { get; set; }
}
```

在`public DateTime CreatedAt { get; set; }`上面的`[JsonProperty("created_at")]`一行将 JSON 字段绑定到 C#属性。这种绑定是必需的，因为名称不匹配。

如果你想创建自己的客户端（用于调用 GitHub），那么你有责任暴露 API 返回的所有数据，而不仅仅是你可能需要的特定场景的数据。

1.  使用 Postman 中的先前调用的消息从 GitHub 用户响应主体生成要反序列化的模型。在这种情况下，响应消息如下（为了清晰起见，消息已截断）：

```cpp
{
   "login":"github-user",
   "id":40486932,
   "node_id":"MDQ6VXNlcjQwNDg2OTMy",
   "name":"Kaisinel",
   "created_at":"2018-06-22T07:51:56Z",
   "updated_at":"2021-08-12T14:55:29Z"
}
```

有许多可用的工具可以将 JSON 转换为 C#模型。

1.  在这种情况下，使用[`json2csharp.com/`](https://json2csharp.com/)将 JSON 转换为 C#模型代码。

1.  复制响应（`GET github/user`）并转到[`json2csharp.com/`](https://json2csharp.com/)。

1.  将响应粘贴到左侧的文本框中，然后单击“转换”按钮：

![图 8.10：将 JSON 转换为 C#模型代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_10.jpg)

图 8.10：将 JSON 转换为 C#模型代码

左侧显示了 JSON 的模型，右侧显示了从 JSON 生成的代码（C#类）。

1.  复制右侧的内容并粘贴到您的代码中：

```cpp
public class Root
{
    public string login { get; set; }
    public int id { get; set; }
    public string node_id { get; set; }
    public string name { get; set; }
    public DateTime created_at { get; set; }
    public DateTime updated_at { get; set; }
}
```

这是您的模型。请注意，在上述代码中，`Root`是一个不可读的类名。这是因为转换器无法知道 JSON 代表什么类。`Root`类代表一个用户；因此，请将其重命名为`User`。

最后，转换器可能是在.NET 5 之前创建的，这就是为什么它没有记录功能。记录是用于序列化目的的一个很好的类，也是数据传输对象（DTO）的一个很好的候选者。DTO 是一个没有逻辑但只是数据的类，有时还有用于绑定序列化的属性。您获得的好处如下：

+   值相等

+   `ToString`将返回属性及其值

+   以更简洁的语法定义它们的能力

因此，尽可能在应用程序中使用记录来定义 DTO。

1.  将（`Root`更名为`User`）并将类型从`class`更改为`record`。代码行看起来像这样，不需要更改属性：

```cpp
public record User
```

1.  最后，运行以下代码行：

```cpp
Console.WriteLine($"{user.Name} created profile at {user.CreatedAt}");
```

输出显示如下：

```cpp
Kaisinel created profile at 2018-06-22 07:51:56
```

为了运行此练习，请转到[`packt.link/GR27A`](https://packt.link/GR27A)，并在`static void` `Main(string[] args)`体内注释掉所有行，除了`await Examples.GitHttp.Demo.Run();`。同样，在执行之前，取消注释`Program.cs`中相应练习/示例/活动的代码行。

注意

您可以在[`packt.link/UPxmW`](https://packt.link/UPxmW)找到此示例使用的代码。

现在您已经看到了在使用`HttpClient`类而不是第三方库时的好处，现在可以在以下部分探索`IDisposable`模式。

### HttpClient 和 IDisposable

`HttpClient`实现了`IDisposable`模式。一般来说，在您使用实现了`IDisposable`的对象之后，您应该清理并调用`Dispose`方法，或者将调用包装在`using`块中。但是，`HttpClient`是特殊的，您不应该频繁地创建和处理它。处理和重新初始化`HttpClient`的问题在于，`HttpClient`管理它与其他 API 建立的连接，并且处理`HttpClient`不会正确关闭这些连接（或套接字）。

最危险的部分是，由于可用连接数量庞大，您在本地开发应用程序时不会注意到任何差异。但是，当将应用程序部署到实时环境时，您可能会耗尽免费的套接字连接。再次强调，避免调用`Dispose`方法并重新初始化`HttpClient`。如果必须这样做，请使用`HttpClientFactory`。`HttpClientFactory`不仅通过管理`HttpClientMessageHandler`（负责发送 HTTP 请求和接收响应的组件）来管理套接字连接的生命周期，还提供日志记录功能，允许对客户端的配置进行集中管理，支持向客户端注入中间件等。如果您在企业环境中使用`HttpClient`，则上述好处非常重要。您可以在*第九章* *创建 API 服务*中了解有关`HttpClientFactory`的更多信息。

理想情况下，您应该有一个静态的`HttpClient`，可以在整个应用程序中重复使用来调用 Web API。但是，您不应该为所有事情都有一个单独的`HttpClient`。不释放`HttpClient`并拥有一个静态的`HttpClient`并不是一个硬性规定。如果您调用许多不同的 API，它们将有自己的基本地址、强制性标头等。为所有这些使用一个对象并不是一个可行的情况。

到目前为止，您处理的请求是公开可访问的，没有安全性。然而，Web API 中的昂贵或私有操作通常是受保护的。通常，保护是使用授权标头设置的。在许多情况下，授权标头涉及某种 ID 和密钥。在 GitHub API 的情况下，它涉及客户端 ID 和客户端密钥。但是，要获得它们，您需要创建一个 OAuth 应用程序。

不过，在做这些之前，您需要熟悉 OAuth。

## OAuth

OAuth 是一种开放标准的授权协议，允许代表用户委派访问权限。本节将探讨两个示例：

+   现实生活类比

+   API 类比

### 现实生活类比

想象一个在学校的孩子。那个孩子的老师正在组织去另一个城市的旅行。需要父母的许可证。父母给了一张纸条：*可以让我的孩子去 X 地方。*孩子把纸条给老师，获得了去 X 目的地的实地考察的许可。

### API 类比

许多应用程序是相互连接的，彼此集成。例如，著名的社交平台 Discord 允许您显示您在其他社交媒体上拥有的任何帐户。但是，为了做到这一点，您需要连接到您想要显示的社交媒体平台。例如，当您在 Discord 上尝试链接 Twitter 帐户时，您将需要在 Twitter 上登录。登录将需要一定范围的访问权限（在这种情况下是您的个人资料名称）。成功登录证明已经授予了访问权限，Discord 将能够代表您在 Twitter 上显示您的个人资料信息。

## GitHub 的 OAuth 应用程序

回到 GitHub 的主题，OAuth 应用程序是什么？它是一个单一安全点的注册。它充当您的应用程序身份。GitHub 用户可能有零个或多个应用程序。如前所述，OAuth 应用程序包括客户端 ID 和密钥。通过它们，您可以使用 GitHub API。换句话说，您可以设置它来请求访问 GitHub 的安全功能，例如更改 GitHub 上的个人数据。

GitHub 有一个有趣的 API 限制。如果来自同一 IP 的未经身份验证的请求超过 60 个，它将阻止接下来的请求长达一小时。但是，可以通过授权请求来删除速率限制。这就是为什么您将为否则公共端点使用授权的主要原因。

OAuth 通常涉及两个客户端应用程序：

+   一个代表某人请求权限

+   另一个授予该权限

因此，设置 OAuth 时，您很可能需要创建一个 URL，以便在客户端授予权限后返回。在 GitHub 上设置 OAuth 应用程序涉及以下步骤：

1.  在右上角，单击您的个人资料图片，然后单击“设置”：

![图 8.11：GitHub 中的帐户设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_11.jpg)

图 8.11：GitHub 中的帐户设置

1.  在左侧，向下滚动到菜单的几乎底部，然后单击“开发者设置”选项：

![图 8.12：GitHub 中的开发者设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_12.jpg)

图 8.12：GitHub 中的开发者设置

1.  现在选择`Oauth Apps`选项：

![图 8.13：在 GitHub 的开发者设置中选择 OAuth 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_13.jpg)

图 8.13：在 GitHub 的开发者设置中选择 OAuth 应用程序

1.  然后点击“注册新应用”按钮：

![图 8.14：在 GitHub 中创建一个新的 OAuth 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_14.jpg)

图 8.14：在 GitHub 中创建一个新的 OAuth 应用程序

注意

如果您之前创建过 OAuth 应用程序，那么此窗口将显示所有已列出的应用程序。为了创建一个新的应用程序，您将需要点击`新的 OAuth 应用程序`。

1.  在下一个窗口中，您将完成表格。首先填写`应用程序名称`（`5`）。避免使用特殊字符。

1.  接下来，填写`主页 URL`（`6`）。

此 URL 通常指向一个网站，描述了为特定情况使用 OAuth 的情况以及为什么需要它。即使您没有描述这种情况的网站，您也可以输入一个占位符 URL（在本例中为`myapp.com`）。只要是有效的 URL，该字段就接受任何内容。

1.  填写`授权回调 URL`（`7`）字段。这可以是任何您想要的。在这里，使用了`myapp.com/home`。使用一个有效的回调 URL。

1.  点击`注册应用程序`（`8`）：![图 8.15：GitHub 中的新 OAuth 应用程序窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_15.jpg)

图 8.15：GitHub 中的新 OAuth 应用程序窗口

1.  在新窗口中，您将看到`客户端 ID`和`客户端密钥`：

![图 8.16：GitHub 上一个新的 OAuth 应用程序的详细信息凭据——客户端 ID 和客户端密钥](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_16.jpg)

图 8.16：GitHub 上一个新的 OAuth 应用程序的详细信息凭据——客户端 ID 和客户端密钥

最好将客户端密钥存储在一个安全的地方以备将来参考，因为您只会在 GitHub 上看到它一次。如果您忘记了它，您将不得不创建一个新的密钥并删除旧的密钥。

现在您已成功在 GitHub 上创建了一个 OAuth 应用程序。客户端密钥在此截图中部分隐藏是有原因的。您不应该公开它。为了在演示中使用它，您将首先使用环境变量来隐藏它们。

1.  因此，将值存储在环境变量`GithubClientId`和`GithubSecret`中。

1.  然后通过`Demo.cs`中的静态属性公开这两个值（前面已经解释过）：

```cpp
private static string GitHubClientId { get; } = Environment.GetEnvironmentVariable("GithubClientId", EnvironmentVariableTarget.User);
private static string GitHubSecret { get; } = Environment.GetEnvironmentVariable("GithubSecret", EnvironmentVariableTarget.User);
```

本节介绍了在 GitHub 中设置 OAuth 应用程序的步骤，该应用程序可用于请求访问 GitHub 的安全功能，例如更改个人数据。有了这些知识，您现在可以使用客户端 ID 和客户端密钥来创建 GitHub API 上的授权调用，如下一节所示。

## 授权标头

授权标头有三种形式——基本的、API 密钥（或个人访问令牌）和第三方认证。GitHub API 不允许来自相同来源的无限次调用。就像 Azure 文本分析客户端一样，它也使用 API 密钥。然而，在这种情况下，API 密钥用于速率限制（一个小时内可以进行多少次调用）。对于匿名调用，它只允许每小时 60 次调用。然而，通过使用有效的授权标头，这个数量增加到了 5,000。

在下面的示例中，您将进行比速率限制允许的调用次数多一次的调用（60 + 1 = 61）。这样，您将获取用户信息 61 次。为了实现这一点，您还需要确保`CacheControl`标头设置为`NoCache`，因为您不希望在连续 60 次调用后被忽略：

```cpp
public static async Task GetUser61Times()
{
    const int rateLimit = 60;
    for (int i = 0; i < rateLimit + 1; i++)
    {
        const string username = "github-user";
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"users/{username}", UriKind.Relative));
        request.Headers.CacheControl = new CacheControlHeaderValue(){NoCache = true};

        var response = await client.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            throw new Exception(response.ReasonPhrase);
        }
```

此代码块是从*HttpClient*部分的`GetUser`方法进行了调整。这里有三个主要的调整：

+   首先是循环中的所有内容运行了 61 次。

+   您还添加了一个错误处理程序，这意味着如果响应不成功，您将打印 API 返回的错误消息。

+   最后，您添加了一个`CacheControl`标头来忽略缓存（因为您不希望服务器忽略 61 次调用）。

运行此代码会导致在第 61 次调用时出现错误消息，这证明了 API 的速率限制（出于清晰起见，错误消息已被截断）：

```cpp
60) Kaisinel created profile at 2018-06-22 07:51:56
Unhandled exception. System.Exception: rate limit exceeded
```

为了解决这个问题，您需要添加一个`Authorization`标头（您将在`CacheControl`标头下面添加它）：

```cpp
GitHttp.cs
public static async Task GetUser61Times(string authHeader)
{
    const int rateLimit = 60;
            for (int i = 0; i < rateLimit + 1; i++)
            {
                const string username = "github-user"; // replace with your own
                var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"users/{username}", UriKind.Relative));
               request.Headers.CacheControl = new CacheControlHeaderValue(){NoCache = true};
               request.Headers.Add("Authorization", authHeader);
               var response = await client.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception(response.ReasonPhrase);
                }
The complete code can be found here: https://packt.link/1C5wb.
```

由于 GitHub 对匿名调用的限制（例如，您每小时只能发出 60 个请求以获取用户配置文件信息），因此最好提供授权标头，以便您被识别，从而摆脱这些严格的限制。在接下来的示例中，您将获得一个授权令牌，然后将其提供给这个方法，从而展示授权如何帮助您克服速率限制。

当运行放置在[`packt.link/Uz2BL`](https://packt.link/Uz2BL)的演示代码时，建议您一次运行一个示例（即取消注释一个行并在`Run`方法中注释其余部分）。这是因为`Demo.cs`文件是授权和匿名调用的混合体，您可能会得到意外的结果。但是，请保留获取令牌的行，因为个别示例可能需要它。

在本节结束时，您应该已经掌握了授权标头及其三种形式（基本、API 密钥（或个人访问令牌）和第三方身份验证）背后的逻辑，并了解到，与 Azure 文本分析客户端一样，GitHub API 使用 API 密钥。现在您可以继续进行基本身份验证。

## 基本身份验证

基本身份验证涉及用户名和密码。这两者通常组合在一个字符串中，并使用以下格式进行编码：

```cpp
Basic username:password
```

以下是用于生成基本身份验证授权令牌的代码：

```cpp
public static string GetBasicToken()
{
    var id = GitHubClientId;
    var secret = GitHubSecret;
    var tokenRaw = $"{id}:{secret}";
    var tokenBytes = Encoding.UTF8.GetBytes(tokenRaw);
    var token = Convert.ToBase64String(tokenBytes);
    return "Basic " + token;
}
```

使用用户名和密码获取基本令牌。然后将其传递给`GetUser61Times`方法：

```cpp
var basicToken = GitExamples.GetBasicToken();
await GitExamples.GetUser61Times(basicToken);
```

调用`GetUser61Times`不再显示错误，因为通过提供授权标头避免了速率限制。

注意

您可以在[`packt.link/Uz2BL`](https://packt.link/Uz2BL)和[`packt.link/UPxmW`](https://packt.link/UPxmW)找到此示例使用的代码。

下一节将介绍更专业的 API 密钥和个人访问令牌，它们非常相似，因为它们都可以访问受保护的数据。

### API 密钥和个人访问令牌

个人访问令牌仅限于个人数据。但是，API 密钥可以用于整个 API。除了可以访问的范围之外，它们在使用方式上没有区别。您可以将 API 密钥或个人访问令牌添加到授权标头中。

但是，当然，要使用特定 API 的访问令牌，您首先需要创建它。您可以通过以下步骤完成：

1.  转到 GitHub 的“设置”窗口下的“开发人员设置”选项。

1.  转到“个人访问令牌”（`1`）。

1.  选择“生成新令牌”按钮（`2`）：

![图 8.17：创建新的个人访问令牌](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_17.jpg)

图 8.17：创建新的个人访问令牌

1.  接下来，输入您的 GitHub 密码。

1.  添加一个注释（可以是任何内容）并向下滚动。此屏幕将帮助您修改用户数据，因此勾选“用户”复选框（`4`）以获取访问权限。

1.  点击“生成令牌”按钮（`5`）：

![图 8.18：为个人访问令牌配置的访问范围](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_18.jpg)

图 8.18：为个人访问令牌配置的访问范围

在新窗口中，您将看到所有个人访问令牌，以及新添加的令牌：

![图 8.19：在 GitHub 上创建的新个人访问令牌](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_19.jpg)

图 8.19：在 GitHub 上创建的新个人访问令牌

注意

请记住，您只能看到令牌的值一次。因此，请确保您安全地复制和存储它。另外，请注意，个人访问令牌在一个月后会过期，届时您需要重新生成它。

1.  创建一个名为`GitHubPersonalAccess`的环境变量。

1.  将个人访问令牌添加到`Demo.cs`：

```cpp
private static string GitHubPersonAccessToken { get; } = Environment.GetEnvironmentVariable("GitHubPersonalAccess", EnvironmentVariableTarget.User);
```

1.  运行以下代码：

```cpp
await GetUser61Times(GitHubPersonAccessToken);
```

您将注意到调用`GetUser61Times`方法不会失败。

访问令牌、授权令牌、API 密钥和 JWT（将在以下部分进一步介绍）是证明您已被授予对 API 的访问权限并拥有您想要的资源的不同手段。但无论您使用哪种特定类型的授权，它们通常都会到达同一个地方——即 Authorization 标头。

接下来的部分将详细介绍一个名为 OAuth2 的授权协议。

## 第三方认证——OAuth2

GitHub 是授权服务器的一个示例。它允许以所有者的名义访问资源或功能。例如，只有登录用户才能更新用户的就业状态。但是，只要用户已被授予执行此操作的访问权限，这就可以直接完成。代表某人获取访问权限是 OAuth2 的核心。

执行以下步骤来修改用户的就业状态：

1.  导航到此 URL 或发送 HTTP `GET`请求：

```cpp
https://github.com/login/oauth/authorize?client_id={{ClientId}}&redirect_uri={{RedirectUrl}}
```

在这里，`{{ClientId}}`和`{{RedirectUrl}}`是您在 OAuth2 GitHub 应用程序中设置的值。

注意

用您的 GitHub OAuth 应用程序中的值替换占位符`{{ClientId}}`和`{{RedirectUrl}}`。

以下屏幕提示您登录到您的 GitHub 应用程序：

![图 8.20：登录到 OAuth2 GitHub 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_20.jpg)

图 8.20：登录到 OAuth2 GitHub 应用程序

1.  完成`用户名`和`密码`。

1.  接下来，点击`登录`按钮登录。

成功登录后，您将被重定向到 OAuth2 应用程序中指定的 URL。

1.  通过向以下格式的 URI 发送 HTTP `POST`请求来为令牌创建请求：

```cpp
{tokenUrl}?client_id={clientId}&redirect_uri={redirectUri}&client_secret={secret}&code={code}:
```

其代码如下：

```cpp
private static HttpRequestMessage CreateGetAccessTokenRequest()
{
    const string tokenUrl = "https://github.com/login/oauth/access_token";
    const string code = "2ecab6ecf412f28f7d4d";
    const string redirectUri = "https://www.google.com/";
    var uri = new Uri($"{tokenUrl}?client_id={GitHubClientId}&redirect_uri={redirectUri}&client_secret={GitHubSecret}&code={code}");
    var request = new HttpRequestMessage(HttpMethod.Post, uri);
    return request;
}
```

在这种情况下，重定向 URL 是[`www.google.com`](https://www.google.com)。您最终得到的 URI 是[`www.google.com/?code=a681b5126b4d0ba160ba`](https://www.google.com/?code=a681b5126b4d0ba160ba)。`code=`部分是获取`OAuth`访问令牌所需的代码。令牌以以下格式返回：

```cpp
access_token=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&scope=user&token_type=bearer
```

1.  在此令牌可以使用之前，您需要从响应中解析它。因此，创建一个函数来解析令牌响应：

```cpp
private static Dictionary<string, string> ConvertToDictionary(string content)
{
    return content
        .Split('&')
        .Select(kvp => kvp.Split('='))
        .Where(kvp => kvp.Length > 1)
        .ToDictionary(kvp => kvp[0], kvp => kvp[1]);
}
```

这将每个`=`属性放入字典中。`=`之前的字符串是键，`=`之后的字符串是值。

1.  使用`GetToken`函数创建并发送请求并解析响应，然后格式化令牌并返回它：

```cpp
private static async Task<string> GetToken()
{
    HttpRequestMessage request = CreateGetAccessTokenRequest();
    var response = await client.SendAsync(request);
    var content = await response.Content.ReadAsStringAsync();
    Dictionary<string, string> tokenResponse = ConvertToDictionary(content);
    // ValidateNoError(tokenResponse);
    var token = $"{tokenResponse["token_type"]} {tokenResponse["access_token"]}";
    return token;
}
```

在这里，您创建了一个请求，将其发送给客户端，将响应解析为令牌，然后返回。`ValidateNoError`现在被注释掉了。您稍后会回来处理它。返回的令牌应该看起来像这样：

```cpp
bearer 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
```

此令牌是一个持有者令牌，是由授权服务器（在本例中是 GitHub）生成的，代表您（或用于登录 GitHub 的任何其他用户名）授予对 GitHub 的访问权限。您可以使用它发送需要特殊访问权限的请求。例如，更新用户的就业状态。

1.  要更新用户的就业状态，使用`UpdateEmploymentStatus`函数：

```cpp
public static async Task UpdateEmploymentStatus(bool isHireable, string authToken)
{
    var user = new UserFromWeb
    {
        hireable = isHireable
    };
    var request = new HttpRequestMessage(HttpMethod.Patch, new Uri("/user", UriKind.Relative));
    request.Headers.Add("Authorization", authToken);
    var requestContent = JsonConvert.SerializeObject(user, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
    request.Content = new StringContent(requestContent, Encoding.UTF8, "application/json");
    var response = await client.SendAsync(request);
    var responseContent = await response.Content.ReadAsStringAsync();
    Console.WriteLine(responseContent);
}
```

此代码块将用户的属性`isHireable`设置为`true`并打印更新后的用户信息。这里重要的部分是内容；当发送`PUT`、`PATCH`或`POST`请求时，通常需要一个请求体（或者换句话说，内容）。

将内存中的对象转换为结构化文本（例如 JSON）的行为称为序列化。在这种情况下，body 是用户更新。您发送一个`PATCH`请求，因为您只想更改更新的值。如果内容中没有提供值，它就不应该改变。这是`PATCH`和`POST`请求之间的关键区别——成功的请求会覆盖所有值（即使您没有提供它们）。

您使用了`new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }`来避免提供`null`值。这是因为您不想更新所有字段，只想更新您提供的字段。

在创建 HTTP 内容时，您还需要提供一个 MIME 类型（一种随请求发送的媒体类型）。这是必需的，以便服务器有一个提示，表明它应该如何处理请求。MIME 类型遵循这种格式：

```cpp
type/subtype
```

在这种情况下，`application/json`表示客户端应该从服务器期望 JSON。`application`是最常见的 MIME 类型，表示二进制数据。

还有`StringContent`，它是一种序列化内容的类型，通常是 JSON 或 XML。或者，您可以使用`StreamContent`或`ByteContent`，但这些类型稍微罕见，通常在性能或数据量成为关注点时使用。

以下代码显示了完整的演示：

```cpp
public static async Task Run()
{
    var oathAccessToken = await GitExamples.GetToken();
    await GitExamples.UpdateEmploymentStatus(true, oathAccessToken);
}
```

在`GetToken`方法（在*第三方身份验证（OAuth2）*部分的*步骤 6*中使用）中，有一行被注释掉的代码`ValidateNoError`。取消注释并实现`GetToken`方法，因为您不总是会得到成功的响应，而在这种情况下解析令牌将失败（即，它不存在）。因此，验证服务器响应并在发生意外情况时抛出异常总是一个好主意。看一下以下 GitHub 错误格式：

```cpp
error=bad_verification_code&error_description=The+code+passed+is+incorrect+or+expired.&error_uri=https%3A%2F%2Fdocs.github.com%2Fapps%2Fmanaging-oauth-apps%2Ftroubleshooting-oauth-app-access-token-request-errors%2F%23bad-verification-code
```

这不太可读。`ValidateNoError`将格式化响应并将其作为异常抛出，而不是让它悄悄失败：

```cpp
private static void ValidateNoError(Dictionary<string, string> tokenResponse)
{
    if (tokenResponse.ContainsKey("error"))
    {
        throw new Exception(
            $"{tokenResponse["error"].Replace("_", " ")}. " +
            $"{tokenResponse["error_description"].Replace("+", " ")}");
    }
}
```

如果您再次运行代码并且出现相同的原因失败，错误消息现在将如下所示：

```cpp
bad verification code. The code passed is incorrect or expired.
```

本节介绍了如何在发送带有某种安全性的 HTTP 请求的基础知识。在接下来的章节（*Restsharp*和*Refit*）中，您将使用第三方库创建客户端，以消除`HttpClient`所需的一些样板代码。

注意

您可以在[`packt.link/UPxmW`](https://packt.link/UPxmW)找到此示例使用的代码。

## 请求幂等性

幂等的 HTTP 请求是一种总是产生相同结果的请求。只有`GET`、`PUT`和`PATCH`请求是幂等的，因为它们要么不做任何更改，要么再次做相同的更改，但该更改永远不会导致错误并且产生相同的数据。`DELETE`不是幂等的，因为删除已经删除的项目将产生错误。`POST`可能是幂等的，但这完全取决于实现。

### PUT、PATCH 或 POST

`PUT`、`PATCH`和`POST`之间的区别可以总结如下：

+   `PUT`用于覆盖模型中的字段。即使提供了单个值，整个模型也将具有未提供的值（或者至少是期望如此）。例如，如果您想要通过首先获取旧详细信息然后发送修改后的版本来更新用户详细信息，您将使用`PUT`。

+   `PATCH`用于仅更新显式提供的单个值。例如，如果您想要更新用户名，发送`PATCH`请求而不是`PUT`请求是有意义的。

+   `POST`用于创建项目或发送复杂查询。无论哪种方式，此动词的默认期望是具有副作用。例如，如果您想要创建一个用户，您将使用`POST`请求。

## 练习 8.02：使用 HttpClient 调用星球大战 Web API

你可能熟悉星球大战。有电影、游戏和电视系列。但是，你知道它也有多个 API 来检索数据吗？即将进行的练习将向你介绍 API 的不同格式，并让你熟悉反序列化稍微复杂的响应。

在这个练习中，您将创建一个强类型的 API 客户端，它将在幕后使用`HttpClient`。客户端将用于返回星球大战电影。您将使用星球大战 API（SWAPI）（[`swapi.dev/`](https://swapi.dev/)）。所需的端点是[`swapi.dev/api/films/`](https://swapi.dev/api/films/)。执行以下步骤来完成这个练习：

1.  创建一个新的类来保存带有基本 URL 的`HttpClient`：

```cpp
public class StarWarsClient
    {
        private readonly HttpClient _client;
        public StarWarsClient()
        {
            _client = new HttpClient {BaseAddress = new Uri("https://swapi.dev/api/")};
        }
```

这将作为一个强类型的 API 客户端。

注意

URI 末尾的`/`表示 URI 将被附加更多文本（在`api`之后而不是在`dev`之后）。

1.  创建一个用于表示电影的类型：

```cpp
Film.cs
public record Film
{
    public string Title { get; set; }
    public int EpisodeId { get; set; }
    public string OpeningCrawl { get; set; }
    public string Director { get; set; }
    public string Producer { get; set; }
    [JsonProperty("release_date")]
    public string ReleaseDate { get; set; }
    public string[] Characters { get; set; }
    public string[] Planets { get; set; }
    public string[] Starships { get; set; }
    public string[] Vehicles { get; set; }
    public string[] Species { get; set; }
    public DateTime Created { get; set; }
```

```cpp
The complete code can be found here: https://packt.link/tjHLa.
```

这是一个用于在响应中反序列化电影的类。`ReleaseDate`属性的上方有`[JsonProperty("release_date")]`，以指定`"release_date"` JSON 字段将映射到`ReleaseDate` C#属性。

1.  创建一个用于存储结果的类型：

```cpp
public record ApiResult<T>
{
    public int Count { get; set; }
    public string Next { get; set; }
    public string Previous { get; set; }
    [JsonProperty("results")]
    public T Data { get; set; }
}
```

这也是一种用于反序列化电影响应的类型；但是，星球大战 API 以分页格式返回结果。它包含指向上一页和下一页的`Previous`和`Next`属性。例如，如果您没有提供要获取的页面，它将返回一个`null`值。但是，如果还有剩余元素，下一个属性将指向下一页（否则它也将是`null`）。使用下一个或上一个作为 URI 查询 API 将返回该页面的资源。您在`T Data`上方使用`JsonProperty`属性来提供 JSON 到属性的映射，因为属性和 JSON 名称不匹配（JSON 字段名为`results`，而`Data`是属性名）。

注意

您可以将`ApiResult`更改为具有`Results`属性而不是`Data`。但是，`ApiResult.Results`有点令人困惑。在编写代码时，选择易于维护和可读性而不是自动化的便利性（在这种情况下是序列化）。因此，*步骤 3*中选择的名称不同但更清晰。

1.  现在，创建一个获取多部电影的方法：

```cpp
public async Task<ApiResult<IEnumerable<Film>>> GetFilms()
{
```

您返回了一个任务，以便其他人可以等待此方法。几乎所有的 HTTP 调用都将是`async Task`。

1.  创建一个 HTTP 请求以获取所有电影：

```cpp
var request = new HttpRequestMessage(HttpMethod.Get, new Uri("films", UriKind.Relative));
```

URI 是相对的，因为您是从已经设置了基本 URI 的`HttpClient`中调用它。

1.  要查询星球大战 API 的电影，请发送此请求：

```cpp
var response = await _client.SendAsync(request);
```

1.  它返回`HttpResponseMessage`。这有两个重要部分：状态码和响应体。C#有一个方法可以根据状态码确定是否有任何错误。要处理错误，请使用以下代码：

```cpp
if (!response.IsSuccessStatusCode)
{
      throw new HttpRequestException(response.ReasonPhrase);
}
```

错误处理很重要，因为失败的 HTTP 请求通常会导致错误状态码而不是异常。建议在尝试反序列化响应体之前执行类似的操作，因为如果失败，您可能会得到一个意外的响应体。

1.  现在，调用`ReadAsStringAsync`方法：

```cpp
var content = await response.Content.ReadAsStringAsync();
var films = JsonConvert.DeserializeObject<ApiResult<Film>>(content);
    return films;
}
```

响应的内容更可能是一种流的形式。要将`HttpContent`转换为字符串，请调用`ReadAsStringAsync`方法。这将返回一个字符串（JSON），允许您将 JSON 转换为 C#对象并反序列化结果。最后，通过反序列化响应内容体并将其全部转换为`ApiResult<Film>`来获取结果。

1.  为了演示，创建客户端并使用它获取所有星球大战电影，然后打印它们：

```cpp
public static class Demo
{
    public static async Task Run()
    {
        var client = new StarWarsClient();
        var filmsResponse = await client.GetFilms();
        var films = filmsResponse.Data;
        foreach (var film in films)
        {
            Console.WriteLine($"{film.ReleaseDate} {film.Title}");
        }
    }
}
```

如果一切正常，您应该看到以下结果：

```cpp
1977-05-25 A New Hope
1980-05-17 The Empire Strikes Back
1983-05-25 Return of the Jedi
1999-05-19 The Phantom Menace
2002-05-16 Attack of the Clones
2005-05-19 Revenge of the Sith
```

这个练习说明了如何创建强类型的 HTTP 客户端以简化操作。

注意

您可以在[`packt.link/2CHpb`](https://packt.link/2CHpb)找到此练习中使用的代码。

您可能已经注意到，发送 HTTP 请求并使用 HTTP 客户端与将简单文本文件发送到 GitHub API 的方式非常相似。即使它不同，同一 API 中的端点通常共享相同的要求。但是，如果您每次需要调用 API 时手动创建 HTTP 请求，那么效率并不高。更好的方法是创建可重用的东西。一个常见的方法是创建`BaseHttpClient`。您将在接下来的活动中实践这一点。

## 活动 8.01：重用 HttpClient 快速创建 API 客户端

`HttpClient`的问题在于您仍然必须自己管理许多事情：

+   错误处理

+   序列化和反序列化

+   强制头

+   授权

在团队中工作或在一个更大的项目上工作时，您可能会进行多个 HTTP 调用。不同调用之间的一致性和相同要求需要进行管理。

此活动的目的是展示简化重复 HTTP 调用的许多方法之一。您将使用首先创建的`BaseHttpClient`类。该类将概括错误处理和反序列化响应和请求，这将大大简化您进行的不同 HTTP 调用。在这里，您将学习如何通过重写`StarWarsClient`使用`BaseHttpClient`来实现基本客户端。

执行以下步骤以完成此活动：

1.  创建一个基本的`HttpClient`类。基本客户端包装`HttpClient`。因此，您将持有对它的私有引用，并允许从 URL 创建它。内部的`HttpClient`通常还包括基本标头，但在这种情况下并不是必需的。

1.  定义一种为每种方法创建请求的方式。为简洁起见，坚持使用`GET`请求。在`GET`请求中，定义默认标头是一种常见做法，但在本例中并不是强制性的。

1.  创建一个方法来发送请求并包括错误处理和反序列化。

1.  在 SWAPI 中，如果您查询多个结果，您将获得用于分页的`ApiResult<IEnumerable<T>>`。创建一个`SendGetManyRequest`方法。

1.  使用您创建的基本客户端简化*Exercise 8.02*中的客户端。

1.  通过相同的演示代码运行代码，但使用新版本的`StarWarsClient`。

1.  如果您使用新的`StarWarsClient`再次运行演示，您应该会看到相同的电影返回：

```cpp
1977-05-25 A New Hope
1980-05-17 The Empire Strikes Back
1983-05-25 Return of the Jedi
1999-05-19 The Phantom Menace
2002-05-16 Attack of the Clones
2005-05-19 Revenge of the Sith
```

要运行此活动，请转到[`packt.link/GR27A`](https://packt.link/GR27A)，并在`static void` `Main(string[] args)`主体中注释所有行，除了`await Activities.Activity01.Demo.Run();`。

注意

可以在[`packt.link/qclbF`](https://packt.link/qclbF)找到此活动的解决方案。

像这样重用`HttpClient`非常有用，因为它消除了代码重复。但是，调用 Web API 并消除重复代码是一个常见的问题，很可能会以某种方式由某些库解决。接下来的部分将探讨如何使用两个流行的 NuGet 包简化对 Web API 的调用：

+   RestSharp

+   Refit

# RestSharp

RestSharp 的思想与基本`HttpClient`非常相似——减少代码重复。它简化了请求的创建，并提供了许多实用程序来进行 HTTP 调用。使用`RestSharp`重新编写`StarWarsClient`，但首先，您需要安装`RestSharp` NuGet：

```cpp
dotnet add package RestSharp
```

现在创建一个与*Activity 8.01*中创建的非常相似的客户端：

```cpp
    public class StarWarsClient
    {
        private readonly RestClient _client;
        public StarWarsClient()
        {
            _client = new RestClient("https://swapi.dev/api/");
        }
```

创建`RestSharp`后，您可以立即获得响应序列化。它还能够猜测您将使用哪种 HTTP 方法：

```cpp
        public async Task<ApiResult<IEnumerable<Film>>> GetFilms()
        {
            var request = new RestRequest("films");
            var films = await _client.GetAsync<ApiResult<IEnumerable<Film>>>(request);
            return films;
        }
    }
```

您传递了进行 HTTP 请求所需的最低信息（调用电影，返回`ApiResult<IEnumerable<Film>>`），其余工作已完成。这与您之前编写的基本客户端非常相似。

注意

`ApiResult`是*Exercise 8.02*中使用的相同类型。

但是，如果您对您的演示运行此代码，您会注意到`Data`属性（在 JSON 上）返回为`null`。这是因为在`response`和`film`类上有一个`JsonProperty`属性。RestSharp 使用不同的序列化程序，不知道这些属性。要使其工作，您可以将所有属性更改为 RestSharp 理解的属性，或者使用与之前相同的序列化程序。您正在使用`Newtonsoft.Json`，为了在 RestSharp 中使用它，您需要调用`UseSerializer`方法，选择`JsonNetSerializer`：

```cpp
        public StarWarsClient()
        {
            _client = new RestClient("https://swapi.dev/api/");
            _client.UseSerializer(() => new JsonNetSerializer());
        }
```

运行演示后，将显示以下输出：

```cpp
1977-05-25 A New Hope
1980-05-17 The Empire Strikes Back
1983-05-25 Return of the Jedi
1999-05-19 The Phantom Menace
2002-05-16 Attack of the Clones
2005-05-19 Revenge of the Sith
```

结果与*练习 8.02*中的结果相同；然而，不同之处在于在前面的示例中使用了`Newtonsoft`序列化程序。`RestSharp`可能是`HttpClient`的最佳抽象，因为它最大程度地减少了您需要编写的代码量，同时保持与`HttpClient`的相似之处。

注意

您可以在[`packt.link/f5vVG`](https://packt.link/f5vVG)找到此示例使用的代码。

该示例旨在使用 HTTP 请求与 Web API 进行通信。尽管演示文件看起来相同，但它们使用的是不同的库或设计模式。在接下来的活动中，您将练习使用 RestSharp 来消耗更多的 API。

## 活动 8.02：使用 RestSharp 列出所有国家的国家 API

地址[`restcountries.com/v3/`](https://restcountries.com/v3/)是一个公共 Web API，提供了所有现有国家的列表。假设使用该 API，您需要获取所有国家的列表，按其首都城市（例如 Vilnius）查找国家，并找到所有使用特定语言（例如立陶宛语）的国家。您只需要打印前两个国家的名称、地区和首都，并实现一个强类型的客户端来访问此 API，使用`RestSharp`。

此活动的目的是让您在进行 HTTP 调用时更加舒适地使用第三方库（`RestSharp`）。使用第三方库通常可以节省大量时间。它允许您重用已经可用的东西。

执行以下步骤以完成此活动：

1.  使用 URL[`restcountries.com/v3/`](https://restcountries.com/v3/)创建一个基本客户端类。

注意

导航到[`restcountries.com/v3/`](https://restcountries.com/v3/)将返回 HTTP 状态码`404`和`Page Not Found`消息。这是因为基本 API URI 不包含有关资源的任何信息；它尚未完成，只是资源的完整 URI 的开始。

1.  创建用于序列化的模型。

1.  使用示例[`restcountries.com/v3/name/peru`](https://restcountries.com/v3/name/peru)来获取响应。

1.  复制响应，然后使用类生成器，例如[`json2csharp.com/`](https://json2csharp.com/)，将 JSON（响应）转换为模型。

1.  在客户端内创建以下方法：`Get`，`GetByCapital`和`GetByLanguage`。

1.  创建一个调用所有三种方法的演示。

1.  打印每个响应中的国家。

结果应该如下：

```cpp
All:
Aruba Americas Oranjestad
Afghanistan Asia Kabul
Lithuanian:
Lithuania Europe Vilnius
Vilnius:
Lithuania Europe Vilnius
```

注意

可以在[`packt.link/qclbF`](https://packt.link/qclbF)找到此活动的解决方案。

现在您知道 RestSharp 简化了请求的创建，并提供了大量用于进行 HTTP 调用的实用程序。接下来的部分将帮助您练习使用 Refit，这是另一种消耗 API 的方式。

# Refit

Refit 是最聪明的客户端抽象，因为它从接口生成客户端。您只需提供一个抽象：

1.  要使用`Refit`库，首先安装`Refit` NuGet：

```cpp
dotnet add package Refit
```

1.  要在 Refit 中创建客户端，首先创建一个带有 HTTP 方法的接口：

```cpp
public interface IStarWarsClient
{
    [Get("/films")]
    public Task<ApiResult<IEnumerable<Film>>> GetFilms();
}
```

请注意，此处的端点是`/films`而不是`films`。如果您使用`films`运行代码，将会收到一个异常，建议您使用前导`/`更改端点。

1.  要解析客户端，只需运行以下代码：

```cpp
var client = RestService.For<IStarWarsClient>("https://swapi.dev/api/");
```

运行演示后，将显示以下输出：

```cpp
1977-05-25 A New Hope
1980-05-17 The Empire Strikes Back
1983-05-25 Return of the Jedi
1999-05-19 The Phantom Menace
2002-05-16 Attack of the Clones
2005-05-19 Revenge of the Sith
```

结果与*练习 8.02*中看到的结果相同；然而，不同之处在于实现。

注意

您可以在[`packt.link/cqkH5`](https://packt.link/cqkH5)找到此示例使用的代码。

只有在您的场景很简单时才使用 Refit。尽管 Refit 可能看起来是最简单的解决方案，但在需要更复杂的自定义授权时，它会带来自己的复杂性。您将在接下来的活动中进一步简化解决方案。

## 活动 8.03：使用 Refit 列出所有国家的国家 API

您了解到的做同一件事的不同方式越多，您就越容易做出选择并选择最适合工作的最佳工具。不同的团队可能使用不同的工具，Refit 是一种独特的、极简主义的方法，您可能会遇到。其他人可能会说它使工作复杂化，因为客户端接口中隐藏了太多内容（代码少并不意味着您可以轻松理解代码）。无论您是支持 Refit 还是反对它，最好先亲自练习并形成自己的观点。这项活动将帮助您做到这一点。在这里，您将访问 Countries API 以显示所有国家、按其语言和首都城市显示的国家。

这项活动的目的是展示在消费简单 API 时，Refit 在快速原型设计中可以有多实用。其步骤如下：

1.  为序列化创建模型。为此，请使用示例[`restcountries.com/v3/name/peru`](https://restcountries.com/v3/name/peru)获取响应。

1.  现在复制响应。

1.  然后使用类生成器，例如[`json2csharp.com/`](https://json2csharp.com/)，将 JSON（响应）转换为模型。

1.  定义一个带有方法的接口：`Get`，`GetByCapital`和`GetByLanguage`。

1.  创建一个演示，打印国家名称、地区和国家状态。

结果将显示如下：

```cpp
All:
Aruba Americas Oranjestad
Afghanistan Asia Kabul
Lithuanian:
Lithuania Europe Vilnius
Vilnius:
Lithuania Europe Vilnius
```

注意

此活动的解决方案可在[`packt.link/qclbF`](https://packt.link/qclbF)找到。

.NET 还有其他几种本机创建 HTTP 请求的方式，你可以使用`HttpWebRequest`或`WebClient`。这两种方式并未被弃用，可以使用，但与较新的`HttpClient`相比，它们是较老的替代方案。下一节将涵盖所有这些内容。

在接下来的部分，您将了解到解决使用`HttpClient`时代码重复问题的其他库。

# 其他进行 HTTP 请求的方式

Refit 和 RestSharp 只是解决使用`HttpClient`时代码重复问题的许多库中的两个。Flurl 和 TinyRest 是另外两个流行的替代方案。每年都会创建新的库，它们不断发展。没有一种适合所有场景的最佳方式。为了确保您做出正确的选择，您需要先进行一些研究，因为这些替代方案有一些需要考虑的缺陷。

`HttpClient`是为.NET 中最低级别的 HTTP 调用而设计的。这是最安全的选择，因为它有很好的文档记录，经过测试，并且允许最大的自由。虽然有许多库比`HttpClient`更简单易用，但它们通常针对基本场景（无授权，无动态设置标头）。当涉及创建高级 HTTP 调用时，它们往往变得相当复杂。

在选择要使用的客户端时，首先选择 API 本身提供的客户端。如果 API 没有提供客户端，请考虑项目的复杂性和范围。对于简单、小范围的项目，请使用您认为最方便的任何 NuGet `HttpClient`替代方案。但是，如果项目的范围很大，调用很复杂，请使用框架提供的本机`HttpClient`。

在下一个练习中，您将实现一个使用 Refit 会变得复杂的示例。为了解决这个复杂性，您将同时使用`HttpClient`和 RestSharp。

## 练习 8.03：在 PayPal 沙盒中测试付款的强类型 HTTP 客户端

编程中的常见场景是进行付款。然而，在开发阶段，您不希望使用真实的银行账户，因此寻找在测试环境中处理付款的方法——即沙盒。在这个练习中，您将学习如何调用支付沙盒 API。您将使用 PayPal 的沙盒 API([`developer.paypal.com/docs/api/orders/v2/`](https://developer.paypal.com/docs/api/orders/v2/))来创建订单并获取您创建的订单。

本练习将使用`Refit`来创建客户端接口和实现分辨率。它还将使用`HttpClient`来提供获取`auth`头部的方法。最后，您将使用 RestSharp 从`HttpClient`中获取访问令牌。执行以下步骤完成此练习：

1.  转到[`www.paypal.com/tt/webapps/mpp/account-selection`](https://www.paypal.com/tt/webapps/mpp/account-selection)。

1.  创建一个 PayPal 账户（个人或商业）。

1.  选择您的位置并点击“开始”按钮。

1.  提供您的手机号码。

1.  点击“下一步”按钮并输入代码。

1.  通过输入电子邮件地址和密码设置您的个人资料。

1.  提供您的地址详细信息。

1.  现在链接您的信用卡或借记卡。您也可以免费按照[`www.paypal.com/tt/webapps/mpp/account-selection`](https://www.paypal.com/tt/webapps/mpp/account-selection)上的说明进行操作。

注意

在 PayPal 上创建账户是免费的。链接信用卡（或借记卡）的要求只是账户创建的一部分，并不会收费。一旦确认身份验证，付款将被退还。

1.  现在注销账户，然后转到[`developer.paypal.com/developer/accounts/`](https://developer.paypal.com/developer/accounts/)。

1.  点击“登录到仪表板”按钮并继续：

![图 8.21：登录 PayPal 仪表板以管理沙箱和实时环境](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_21.jpg)

图 8.21：登录 PayPal 仪表板以管理沙箱和实时环境

1.  然后输入请求的凭据并继续下一步。

1.  点击`Sandbox`选项下的`Accounts`选项。您将看到为您创建的两个测试账户：

![图 8.22：用于测试的沙箱 PayPal 账户](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_22.jpg)

图 8.22：用于测试的沙箱 PayPal 账户

您将使用这些账户在接下来的步骤中进行测试。

注意

PayPal 沙箱是免费的。

1.  转到[`developer.paypal.com/developer/applications`](https://developer.paypal.com/developer/applications)获取您的客户端 ID 和秘钥。就像 GitHub 示例一样，PayPal 使用 OAuth 应用程序为您提供客户端 ID 和秘钥。

1.  对于一个默认账户，PayPal 还生成了一个默认的 OAuth 应用。因此，点击“沙箱”选项卡，然后选择“默认应用程序”：

![图 8.23：为 PayPal 创建 OAuth 应用](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_23.jpg)

图 8.23：为 PayPal 创建 OAuth 应用

1.  在新窗口中，检查`Client ID`和`Secret`。

1.  注意这两点，并将它们存储在环境变量中：

![图 8.24：显示客户端 ID 和秘钥的默认应用程序详情](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_24.jpg)

图 8.24：显示客户端 ID 和秘钥的默认应用程序详情

1.  在一个新的空类`Exercise03.AuthHeaderHandler.cs`中创建用于访问 PayPal 客户端 ID 和秘钥的属性：

```cpp
public static string PayPalClientId { get; } = EnvironmentVariable.GetOrThrow("PayPalClientId");
public static string PayPalSecret { get; } = EnvironmentVariable.GetOrThrow("PayPalSecret");
```

这里使用`EnvironmentVariable.GetOrThrow`辅助方法来获取用户的环境变量，如果不存在则抛出。您将使用这些属性来连接到沙箱 PayPal API。

注意

您可以在[`packt.link/y2MCy`](https://packt.link/y2MCy)找到用于环境变量的代码。

1.  在`Demo.cs`类中，添加一个用于 PayPal 沙箱的`BaseAddress`的`const`变量：

```cpp
public const string BaseAddress = "https://api.sandbox.paypal.com/";
```

`BaseAddress`将用于使用 PayPal URL 初始化不同的客户端（RestSharp 和 Refit）。

1.  使用`Refit`创建一个带有`CreateOrder`和`GetOrder`方法的客户端：

```cpp
public interface IPayPalClient
{
    [Post("/v2/checkout/orders")]
    public Task<CreatedOrderResponse> CreateOrder(Order order);
    [Get("/v2/checkout/orders/{id}")]
    public Task<Order> GetOrder(string id);
}
```

要获取示例请求，请参考您想要调用的 API 的文档。通常，它们会有一个示例请求。在这种情况下，PayPal 的`CreateOrder`请求可以在[`developer.paypal.com/docs/api/orders/v2/`](https://developer.paypal.com/docs/api/orders/v2/)找到：

```cpp
{
   "intent":"CAPTURE",
   "purchase_units":[
      {
         "amount":{
            "currency_code":"USD",
            "value":"100.00"
         }
      }
   ]
}
```

![图 8.25：PayPal 创建订单示例请求，突出显示主体](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_25.jpg)

图 8.25：PayPal 创建订单示例请求，突出显示主体

在*图 8.25*中，`-d`是一个参数，不属于请求主体。

1.  使用[`json2csharp.com/`](https://json2csharp.com/)并从 JSON 生成 C#类。相应的 C#类将为您生成。

1.  将`RootObject`重命名为`Order`，并将所有类更改为`record`类型，因为它是 DTO 的更合适的类型：

```cpp
IPayPalClient.cs
public record Order
{
    public string intent { get; set; }
    public Purchase_Units[] purchase_units { get; set; }
}
public record Name
{
    public string name { get; set; }
}
public record Purchase_Units
{
    public Amount amount { get; set; }
    public Payee payee { get; set; }
```

```cpp
The complete code can be found here: https://packt.link/GvEZ8.
```

1.  使用相同的 PayPal 文档([`developer.paypal.com/docs/api/orders/v2/`](https://developer.paypal.com/docs/api/orders/v2/))，复制示例响应：

```cpp
{
    "id": "7XS70547FW3652617",
    "intent": "CAPTURE",
    "status": "CREATED",
    "purchase_units": [
        {
            "reference_id": "default",
            "amount": {
                "currency_code": "USD",
                "value": "100.00"
            },
            "payee": {
                "email_address": "sb-emttb7510335@business.example.com",
                "merchant_id": "7LSF4RYZLRB96"
            }
        }
    ],
    "create_time": "2021-09-04T13:01:34Z",
    "links": [
        {
            "href": "https://api.sandbox.paypal.com/v2/checkout/orders/7XS70547FW3652617",
            "rel": "self",
            "method": "GET"
        }
     ]
}
```

1.  使用[`json2csharp.com/`](https://json2csharp.com/)并从 JSON 生成 C#类。在这里，您将获得与请求 JSON 非常相似的类。唯一的区别是响应（为简洁起见进行了简化）：

```cpp
public class CreateOrderResponse
{
    public string id { get; set; }
}
```

1.  使用`AuthHeaderHandler`在发出请求时获取访问令牌，并确保它继承`DelegatingHandler`：

```cpp
public class AuthHeaderHandler : DelegatingHandler
{
```

要调用 PayPal，您需要在每个请求中使用`auth`标头。`auth`标头的值是从另一个端点检索的。Refit 不能随意添加标头。但是，您可以使用自定义`HttpClient`和自定义`HttpMessageHandler`设置 Refit，每当发出请求时都会获取访问令牌。出于这个原因使用`AuthHeaderHandler`。

`DelegatingHandler`是一个允许拦截`HttpRequest`的类，当它被发送时，在发送 HTTP 请求之前或之后执行某些操作。在这种情况下，在发送 HTTP 请求之前，您将获取`auth`标头并将其添加到发送的请求中。

1.  现在，通过向`AuthenticationHeader`添加一个令牌来重写`SendRequest`：

```cpp
protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
{
                var accessToken = await GetAccessToken(CreateBasicAuthToken());
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
}
```

1.  要获取访问令牌，您首先需要使用基本的`auth`（客户端 ID 和密钥）获取 OAuth 令牌：

```cpp
 private static string CreateBasicAuthToken()
      {
                var credentials = Encoding.GetEncoding("ISO-8859-1").GetBytes(PayPalClientId + ":" + PayPalSecret);
                var authHeader = Convert.ToBase64String(credentials);
                return "Basic " + authHeader;
      }
```

1.  获取访问令牌将需要一个`auth`令牌。使用`RestSharp`客户端并向请求添加`Authorization`标头。

1.  接下来，根据 PayPal API 规范将`content-type`设置为`application/x-www-form-urlencoded`。

1.  将`grant_type=client_credentials`作为请求正文内容添加：

```cpp
            private static async Task<string> GetAccessToken(string authToken)
            {
                var request = new RestRequest("v1/oauth2/token");
                request.AddHeader("Authorization", authToken);
                request.AddHeader("content-type", "application/x-www-form-urlencoded");
                request.AddParameter("application/x-www-form-urlencoded", "grant_type=client_credentials", ParameterType.RequestBody);
```

1.  执行上述请求并使用私有嵌套类`Response`返回响应，以简化您的工作：

```cpp
                var response = await RestClient.ExecuteAsync<Response>(request, Method.POST);
                return response.Data.access_token;
            }
        private class Response
        {
            public string access_token { get; set; }
        }
      }
```

为什么需要嵌套类？在这里，访问令牌嵌套在响应中。它不仅仅是一个字符串，而是一个对象。从 JSON 中自行解析会有点复杂。但是，您已经知道如何反序列化对象。因此，即使只是一个属性，反序列化仍然有所帮助。

1.  现在，在`AuthHandler`类中为`GetAccessToken`方法创建`RestClient`：

```cpp
private static readonly RestClient RestClient = new RestClient(baseAddress);
```

1.  在`Demo`类中，创建`Run`方法：

```cpp
public static async Task Run()
        	{
```

1.  使用自定义`AuthHeaderHandler`提供程序解析`Refit`客户端：

```cpp
            var authHandler = new AuthHeaderHandler {InnerHandler = new HttpClientHandler() };
            var payPalClient = RestService.For<IPayPalClient>(new HttpClient(authHandler)
                {
                    BaseAddress = new Uri(baseAddress)
                });
```

1.  假设通过创建`Order`对象进行了付款，运行以下代码：

```cpp
var order = new Order
            {
                intent = "CAPTURE",
                purchase_units = new[]
                {
                    new Purchase_Units
                    {
                        amount = new Amount
                        {
                            currency_code = "EUR", value = "100.00"
                        }
                    }
                }
            };
```

1.  现在，调用 PayPal API 并创建一个刚刚创建的订单的订单端点。

1.  获取创建的订单以查看是否有效，并打印检索到的订单支付信息：

```cpp
var createOrderResponse = await payPalClient.CreateOrder(order);
var payment = await payPalClient.GetOrder(createOrderResponse.id);
var pay = payment.purchase_units.First();
Console.WriteLine($"{pay.payee.email_address} - " +
                              $"{pay.amount.value}" +
                              $"{pay.amount.currency_code}");
```

如果环境变量设置正确，您应该会看到以下输出：

```cpp
sb-emttb7510335@business.example.com - 100.00EUR
```

正如前面提到的，这是一个沙盒 API。然而，切换到带有真实货币的实时环境只是设置在该环境中创建新的 PayPal 账户并调用不同的端点：[`api-m.paypal.com`](https://api-m.paypal.com)。

注意

您将无法访问[`api-m.paypal.com`](https://api-m.paypal.com)，因为它是用于生产 PayPal 使用并且是付费的。然而，当您准备好与 PayPal 进行真正的集成时，这应该是代码中唯一的更改（不同的基本 URI）。

请确保您已设置环境变量并且正在使用您自己的客户端和密钥。否则，可能会显示一些未处理的异常错误。

注意

您可以在[`packt.link/cFRq6`](https://packt.link/cFRq6)找到此练习中使用的代码。

您现在知道如何使用 Web API 执行简单的 CRUD 操作。但是，到目前为止，您只使用了文本。那么，使用图像调用 API 会有所不同吗？在下一个活动中找出答案。

## 活动 8.04：使用 Azure Blob Storage 客户端上传和下载文件

Azure Blob Storage 是 Azure 上用于存储不同文件（日志、图像、音乐和整个驱动器）的云服务。在您可以使用任何 Azure 存储服务之前，您将需要一个存储账户。Blob 只是文件，但不能直接存储在账户中；相反，它们需要一个容器。

Azure 存储容器类似于存储其他文件的目录。但是，与目录不同，容器不能包含其他容器。使用 Azure 存储账户创建两个容器，上传图像和文本文件，然后在本地下载上传的文件。所有这些都将在您自己的客户端中完成，该客户端包装了 Azure Blob 存储客户端。

此活动的目的是让您熟悉通过云存储处理文件，并将迄今为止学到的知识付诸实践。执行以下步骤完成此活动：

1.  转到`Azure 存储账户`。

1.  创建一个新的 Azure 存储账户。

1.  在环境变量中存储 blob 存储访问密钥，名称为`BlobStorageKey`。

1.  安装`Azure Blob Storage`客户端。

1.  为存储字段和默认容器客户端（默认情况下将在其中存储 blob 的容器）创建`FilesClient`类。

1.  创建一个构造函数来初始化两个客户端（以支持访问不同的容器）。

1.  添加一个方法来创建一个容器，如果已经存在则获取一个现有的容器。

1.  创建一个方法，将文件上传到特定的容器。

1.  创建一个方法，从特定的容器下载文件。

1.  创建一个`Demo`类，其中包含下载和上传目录的路径。

1.  添加测试数据，即两个文件，即图像和文本文件（*图 8.26*，*图 8.27*和*图 8.28*）：

![图 8.26：两个 Azure 存储容器，exercise04 和 exercise04b，在您的存储账户中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_26.jpg)

图 8.26：您的存储账户中的两个 Azure 存储容器，exercise04 和 exercise04b

文本文件：

![图 8.27：Test1.txt 文件上传到 exercise04 容器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_27.jpg)

图 8.27：Test1.txt 文件上传到 exercise04 容器

图像文件：

![图 8.28：Morning.jpg 文件上传到 exercise04b 容器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_28.jpg)

图 8.28：Morning.jpg 文件上传到 exercise04b 容器

1.  创建方法`Run`，上传一个文本文件，然后在本地下载它。

1.  运行代码。如果您做得正确，您应该看到以下输出，两个文件都已在本地下载：

![图 8.29：从两个容器中下载的 Morning.jpg 和 Test1.txt 文件演示代码执行后](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-ws/img/B16835_08_29.jpg)

图 8.29：在演示代码执行后从两个容器中下载的 Morning.jpg 和 Test1.txt 文件

注意

此活动的解决方案可以在[`packt.link/qclbF`](https://packt.link/qclbF)找到。

几乎不可能创建一个适合所有人的完美客户端。因此，即使对于给定给您的一些问题已经有了解决方案，您通常仍需要进一步将其抽象化，使其适应解决您确切问题的需求。您遇到的问题是从特定文件夹上传和下载文件。为了解决这个问题，您将客户端的层级抽象化，仅暴露两个功能——一个用于上传文件，另一个用于下载文件。

# 总结

无论您是什么样的程序员，都会有许多情况需要使用 Web 服务。在线有不同类型的服务，但最常见的类型是 RESTful。REST 只是一组指南，因此不应与 HTTP 混淆。REST API 简单、自我记录、结构良好，目前是 Web API 的黄金标准。然而，在大多数情况下，在 RESTful API 的上下文中，请求是通过 HTTP 发送的，您的消息包含 JSON。

使用 C#进行 HTTP 调用的主要工具是`HttpClient`，但是，在尝试自己实现 HTTP 调用之前，您应该寻找要使用的 Web API 的 NuGet 包。Azure Blob 存储、Azure 文本分析、PayPal 和 GitHub 只是一些 Web API 的例子。

在本章中，您了解了很多在网络上为您完成的功能。消费起来并不难；现在您需要知道的是如何与第三方的 RESTful Web API 进行通信。在下一章中，您将学习如何使用 ASP.NET Core Web API 模板创建自己的 RESTful web 服务，同时还将介绍 Azure Functions 以及特殊工具 Swagger 和 NuGet。
