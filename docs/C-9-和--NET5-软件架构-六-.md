# C#9 和 .NET5 软件架构（六）

> 原文：[`zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA`](https://zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Blazor WebAssembly

在本章中，您将学习如何使用 Blazor WebAssembly 实现演示层。Blazor WebAssembly 应用程序是 C#应用程序，可以在支持 WebAssembly 技术的任何浏览器中运行。它们可以通过导航到特定的 URL 进行访问，并以标准静态内容的形式在浏览器中下载，由 HTML 页面和可下载文件组成。

Blazor 应用程序使用了我们在第十五章《介绍 ASP.NET Core MVC》中已经分析过的许多技术，比如依赖注入和 Razor。因此，我们强烈建议在阅读本章之前先学习第十五章《介绍 ASP.NET Core MVC》。

更具体地说，在本章中，您将学习以下主题：

+   Blazor WebAssembly 架构

+   Blazor 页面和组件

+   Blazor 表单和验证

+   Blazor 高级特性，如全球化、身份验证和 JavaScript 互操作性

+   Blazor WebAssembly 的第三方工具

+   用例：在 Blazor WebAssembly 中实现一个简单的应用程序

虽然也有运行在服务器上的 Blazor，就像 ASP.NET Core MVC 一样，但本章仅讨论 Blazor WebAssembly，它完全在用户的浏览器中运行，因为本章的主要目的是提供一个相关的示例，展示如何使用客户端技术实现演示层。此外，作为一种服务器端技术，Blazor 无法提供与其他服务器端技术（如 ASP.NET Core MVC）相媲美的性能，我们已经在第十五章《介绍 ASP.NET Core MVC》中进行了分析。

第一节概述了 Blazor WebAssembly 的总体架构，而其余部分描述了具体特性。在需要时，通过分析和修改 Visual Studio 在选择 Blazor WebAssembly 项目模板时自动生成的示例代码来澄清概念。最后一节展示了如何将学到的所有概念应用到实践中，实现一个基于 WWTravelClub 书籍用例的简单应用程序。

# 技术要求

本章需要免费的 Visual Studio 2019 社区版或更高版本，并安装了所有数据库工具。所有概念都将通过一个简单的示例应用程序进行澄清，该应用程序基于 WWTravelClub 书籍用例。本章的代码可在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)上找到。

# Blazor WebAssembly 架构

Blazor WebAssembly 利用了新的 WebAssembly 浏览器功能，在浏览器中执行.NET 运行时。这样，它使所有开发人员都能够在任何支持 WebAssembly 的浏览器中运行的应用程序的实现中使用整个.NET 代码库和生态系统。WebAssembly 被构想为 JavaScript 的高性能替代品。它是一种能够在浏览器中运行并遵守与 JavaScript 代码相同限制的汇编。这意味着 WebAssembly 代码，就像 JavaScript 代码一样，运行在一个具有非常有限访问所有机器资源的隔离执行环境中。

WebAssembly 与过去的类似选项（如 Flash 和 Silverlight）不同，因为它是 W3C 的官方标准。更具体地说，它于 2019 年 12 月 5 日成为官方标准，因此预计将有很长的寿命。事实上，所有主流浏览器已经支持它。

然而，WebAssembly 不仅带来了性能！它还为现代和先进的面向对象语言（如 C++（直接编译）、Java（字节码）和 C#（.NET））在浏览器中运行整个代码库创造了机会。

微软建议使用 Unity 3D 图形框架和 Blazor 在浏览器中运行.NET 代码。

在 WebAssembly 之前，浏览器中运行的演示层只能用 JavaScript 实现，这带来了语言维护所带来的所有问题。

现在，使用 Blazor，我们可以使用现代和先进的 C#来实现复杂的应用程序，利用 C#编译器和 Visual Studio 为这种语言提供的所有便利。

此外，使用 Blazor，所有.NET 开发人员都可以利用.NET 框架的全部功能来实现在浏览器中运行的表示层，并与在服务器端运行的所有其他层共享库和类。

接下来的小节描述了 Blazor 架构的整体情况。第一小节探讨了单页应用程序的一般概念，并指出了 Blazor 的特点。

## 什么是单页应用程序？

**单页应用程序**（**SPA**）是一个基于 HTML 的应用程序，其中 HTML 由在浏览器中运行的代码更改，而不是向服务器发出新请求并从头开始呈现新的 HTML 页面。SPA 能够通过用新的 HTML 替换完整的页面区域来模拟多页面体验。

SPA 框架是专门设计用于实现单页应用程序的框架。在 WebAssembly 出现之前，所有的 SPA 框架都是基于 JavaScript 的。最著名的基于 JavaScript 的 SPA 框架是 Angular、React.js 和 Vue.js。

所有的 SPA 框架都提供了将数据转换为 HTML 以显示给用户的方法，并依赖一个称为*router*的模块来模拟页面更改。通常，数据填充到 HTML 模板的占位符中，并选择要呈现的模板部分（类似 if 的结构），以及呈现的次数（类似 for 的结构）。

Blazor 的模板语言是 Razor，我们已经在*第十五章*中描述过。

为了增加模块化，代码被组织成组件，这些组件是一种虚拟的 HTML 标记，一旦呈现，就会生成实际的 HTML 标记。像 HTML 标记一样，组件有它们的属性，通常被称为参数，以及它们的自定义事件。开发人员需要确保每个组件使用它的参数来创建适当的 HTML，并确保它生成足够的事件。组件可以以分层的方式嵌套在其他组件中。

应用程序路由器通过选择组件来执行其工作，充当页面，并将它们放置在预定义的区域。每个页面组件都有一个与之相关联的 Web 地址路径。这个路径与 Web 应用程序域连接在一起，成为一个唯一标识页面的 URL。与通常的 Web 应用程序一样，页面 URL 用于与路由器通信，以确定要加载哪个页面，可以使用常规链接或路由方法/函数。

一些 SPA 框架还提供了预定义的依赖注入引擎，以确保组件与在浏览器中运行的通用服务和业务代码之间有更好的分离。在本小节列出的框架中，只有 Blazor 和 Angular 具有开箱即用的依赖注入引擎。

基于 JavaScript 的 SPA 框架通常会将所有 JavaScript 代码编译成几个 JavaScript 文件，然后执行所谓的摇树操作，即删除所有未使用的代码。

目前，Blazor 将主应用程序引用的所有 DLL 分开，并对每个 DLL 执行摇树操作。

下一小节开始描述 Blazor 架构。鼓励您创建一个名为`BlazorReview`的 Blazor WebAssembly 项目，这样您就可以检查整个章节中解释的代码和构造。请选择**个人用户帐户**作为身份验证，以及**ASP.NET Core hosted**。这样，Visual Studio 还将创建一个与 Blazor 客户端应用程序通信的 ASP.NET Core 项目，其中包含所有身份验证和授权逻辑。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_16_01.png)

图 16.1：创建 BlazorReview 应用程序

如果启动应用程序并尝试登录或尝试访问需要登录的页面，则应该出现一个错误，指出数据库迁移尚未应用。只需单击消息旁边的链接即可应用待处理的迁移。否则，如*第八章*的*使用 C#与数据交互-Entity Framework Core*部分中所解释的那样，转到 Visual Studio 包管理器控制台并运行`Update-Database`命令。

## 加载和启动应用程序

Blazor WebAssembly 应用程序的 URL 始终包括一个`index.html`静态 HTML 页面。在我们的`BlazorReview`项目中，`index.html`位于`BlazorReview.Client->wwwroot->index.html`。此页面是 Blazor 应用程序将创建其 HTML 的容器。它包含一个带有`viewport meta`声明、标题和整个应用程序 CSS 的 HTML 头。Visual Studio 默认项目模板添加了一个特定于应用程序的 CSS 文件和 Bootstrap CSS，具有中性样式。您可以使用具有自定义样式的默认 Bootstrap CSS 或完全不同的 CSS 框架来替换默认的 Bootstrap CSS。

正文包含以下代码：

```cs
<body>
<div id="app">Loading...</div>
<div id="blazor-error-ui">
        An unhandled error has occurred.
<a href="" class="reload">Reload</a>
<a class="dismiss">![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_16_001.png)</a>
</div>
<script 
src="img/AuthenticationService.js">
</script>
<script src="img/blazor.webassembly.js"></script>
</body> 
```

初始的`div`是应用程序将放置其生成的代码的地方。放置在此`div`中的任何标记都将在 Blazor 应用程序加载和启动时出现，然后将被应用程序生成的 HTML 替换。第二个`div`通常是不可见的，只有在 Blazor 拦截到未处理的异常时才会出现。

`blazor.webassembly.js`包含 Blazor 框架的 JavaScript 部分。除其他外，它负责下载.NET 运行时以及所有应用程序 DLL。更具体地说，`blazor.webassembly.js`下载列出所有应用程序文件及其哈希值的`blazor.boot.json`文件。然后，`blazor.webassembly.js`下载此文件中列出的所有资源并验证它们的哈希值。`blazor.webassembly.js`下载的所有资源都是在构建或发布应用程序时创建的。

只有在项目启用身份验证时才会添加`AuthenticationService.js`，它负责 Blazor 利用其他身份验证凭据（如 cookie）来获取承载令牌的`OpenID Connect`协议。承载令牌是客户端通过 Web API 与服务器交互的首选身份验证凭据。身份验证将在本章后面的*身份验证和授权*子章节中更详细地讨论，而承载令牌将在*第十四章*的*应用 Service-Oriented Architectures with .NET Core*部分中讨论。

Blazor 应用程序的入口点在`BlazorReview.Client->Program.cs`文件中。它具有以下结构：

```cs
public class Program
{
    public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("#app");
            // Services added to the application 
            // Dependency Injection engine declared with statements like:
            // builder.Services.Add...
            await builder.Build().RunAsync();
        }
    } 
```

`WebAssemblyHostBuilder`是用于创建`WebAssemblyHost`的构建器，它是在*第五章*的*将微服务架构应用于企业应用程序*中讨论的通用主机的 WebAssembly 特定实现（鼓励您查看该子章节）。第一个构建器配置指令声明了 Blazor 根组件（`App`），它将包含整个组件树，并在`Index.html`页面的哪个 HTML 标记中放置它（`#app`）。更具体地说，`RootComponents.Add`添加了一个托管服务，负责处理整个 Blazor 组件树。我们可以通过多次调用`RootComponents.Add`在同一个 HTML 页面中运行多个 Blazor WebAssembly 用户界面，每次使用不同的 HTML 标记引用。

`builder.Services`包含了所有通常的方法和扩展方法，用于向 Blazor 应用程序的依赖引擎添加服务：`AddScoped`、`AddTransient`、`AddSingleton`等等。就像在 ASP.NET Core MVC 应用程序中一样（*第十五章*，*介绍 ASP.NET Core MVC*），服务是实现业务逻辑和存储共享状态的首选位置。在 ASP.NET Core MVC 中，服务通常传递给控制器，而在 Blazor WebAssembly 中，它们被注入到组件中。

下一小节将解释根`App`组件如何模拟页面更改。

## 路由

由主机构建代码引用的根`App`类在`BlazorReview.Client->App.razor`文件中定义。`App`是一个 Blazor 组件，像所有 Blazor 组件一样，它是在具有`.razor`扩展名的文件中定义的，并且使用富有组件标记的 Razor 语法，即用表示其他 Blazor 组件的类似 HTML 的标签。它包含了处理应用程序页面的全部逻辑：

```cs
<CascadingAuthenticationState>
<Router AppAssembly="@typeof(Program).Assembly">
<Found Context="routeData">
<AuthorizeRouteView RouteData="@routeData"
                    DefaultLayout="@typeof(MainLayout)">
<NotAuthorized>
@*Template that specifies what to show 
when user is not authorized *@
</NotAuthorized>
</AuthorizeRouteView>
</Found>
<NotFound>
<LayoutView Layout="@typeof(MainLayout)">
<p>Sorry, there's nothing at this address.</p>
</LayoutView>
</NotFound>
</Router>
</CascadingAuthenticationState> 
```

前面代码中的所有标记都代表组件或特定的组件参数，称为模板。组件将在本章中详细讨论。暂时想象它们是一种我们可以用 C#和 Razor 代码定义的自定义 HTML 标记。模板则是接受 Razor 标记作为值的参数。模板将在本节的*模板和级联参数*小节中讨论。

`CascadingAuthenticationState`组件的唯一功能是将身份验证和授权信息传递给其内部组件树中的所有组件。只有在项目创建过程中选择添加授权时，Visual Studio 才会生成它。

`Router`组件是实际的应用程序路由器。它扫描`AppAssembly`参数中传递的程序集，寻找包含路由信息的组件，即可以作为页面工作的组件。Visual Studio 将包含`Program`类的程序集传递给它，即主应用程序。其他程序集中包含的页面可以通过`AdditionalAssemblies`参数添加，该参数接受一个程序集的`IEnumerable`。

之后，路由器拦截所有通过代码或通过通常的`<a>` HTML 标签执行的页面更改，这些标签指向应用程序基地址内的地址。导航可以通过代码处理，通过从依赖注入中要求`NavigationManager`实例来处理。

`Router`组件有两个模板，一个用于找到请求的 URI 的页面（`Found`），另一个用于找不到请求的页面（`NotFound`）。当应用程序使用授权时，`Found`模板由`AuthorizeRouteView`组件组成，进一步区分用户是否有权访问所选页面。当应用程序不使用授权时，`Found`模板由`RouteView`组件组成：

```cs
<RouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)" /> 
```

`RouteView`接受所选页面，并在由`DefaultLayout`参数指定的布局页面内呈现它。这个规范只是一个默认值，因为每个页面都可以通过指定不同的布局页面来覆盖它。Blazor 布局页面的工作方式类似于*第十五章*，*介绍 ASP.NET Core MVC*中描述的 ASP.NET Core MVC 布局页面，唯一的区别是指定页面标记的位置是用`@Body`指定的：

```cs
<div class="content px-4">
      @Body
</div> 
```

在 Visual Studio 模板中，默认的布局页面位于`BlazorReview.Client->Shared->MainLayout.razor`文件中。

如果应用程序使用授权，`AuthorizeRouteView`的工作方式类似于`RouteView`，但它还允许指定一个用户未经授权的情况下的模板：

```cs
<NotAuthorized>
@if (!context.User.Identity.IsAuthenticated)
{
<RedirectToLogin />
}
else
{
<p>You are not authorized to access this resource.</p>
}
</NotAuthorized> 
```

如果用户未经过身份验证，`RedirectToLogin`组件将使用`NavigationManager`实例来转到登录逻辑页面，否则，它会通知用户他们没有足够的权限来访问所选页面。

Blazor WebAssembly 还允许程序集延迟加载以减少初始应用程序加载时间，但由于篇幅有限，我们将不在此讨论。*进一步阅读*部分包含了官方 Blazor 文档的参考资料。

# Blazor 页面和组件

在本节中，您将学习 Blazor 组件的基础知识，如何定义组件，其结构，如何将事件附加到 HTML 标记，如何定义它们的属性，以及如何在组件内部使用其他组件。我们已将所有内容组织成不同的子节。第一个子节描述了组件结构的基础知识。

## 组件结构

组件是在扩展名为`.razor`的文件中定义的。一旦编译，它们就变成了从`ComponentBase`继承的类。与所有其他 Visual Studio 项目元素一样，Blazor 组件可以通过**添加新项**菜单获得。通常，要用作页面的组件是在`Pages`文件夹中定义的，或者在其子文件夹中定义，而其他组件则组织在不同的文件夹中。默认的 Blazor 项目将所有非页面组件添加到`Shared`文件夹中，但您可以以不同的方式组织它们。

默认情况下，页面被分配一个与它们所在文件夹的路径相对应的命名空间。因此，例如，在我们的示例项目中，所有在`BlazorReview.Client->Pages`路径中的页面都被分配到`BlazorReview.Client.Pages`命名空间。但是，您可以通过在文件顶部的声明区域中放置一个`@namespace`声明来更改此默认命名空间。此区域还可以包含其他重要的声明。以下是一个显示所有声明的示例：

```cs
@page "/counter"
@layout MyCustomLayout
@namespace BlazorApp2.Client.Pages
@using Microsoft.AspNetCore.Authorization
@implements MyInterface
@inherits MyParentComponent
@typeparam T
@attribute [Authorize]
@inject NavigationManager navigation 
```

前两个指令只对必须作为页面工作的组件有意义。更具体地说，`@layout`指令用另一个组件覆盖默认的布局页面，而`@page`指令定义了页面的路径（**路由**）在应用程序的基本 URL 内。因此，例如，如果我们的应用程序在`https://localhost:5001`上运行，那么上述页面的 URL 将是`https://localhost:5001/counter`。页面路由也可以包含参数，就像在这个例子中一样：`/orderitem/{customer}/{order}`。参数名称必须与组件定义的参数的公共属性匹配。匹配不区分大小写，并且参数将在本小节后面进行解释。

实例化每个参数的字符串被转换为参数类型，如果此转换失败，则会抛出异常。可以通过将每个参数与类型关联来防止这种行为，在这种情况下，如果转换为指定类型失败，则与页面 URL 的匹配失败。只支持基本类型：`/orderitem/{customer:int}/{order:int}`。参数是强制性的，也就是说，如果找不到它们，匹配失败，路由器会尝试其他页面。但是，您可以通过指定两个`@page`指令使参数变为可选，一个带参数，另一个不带参数。

`@namespace`覆盖了组件的默认命名空间，而`@using`等同于通常的 C# `using`。在特殊的`{project folder}->_Imports.razor`文件夹中声明的`@using`会自动应用于所有组件。

`@inherits`声明组件是另一个组件的子类，而`@implements`声明它实现了一个接口。

如果组件是一个泛型类，则使用`@typeparam`，并声明泛型参数的名称，而`@attribute`声明应用于组件类的任何属性。属性级别的属性直接应用于代码区域中定义的属性，因此它们不需要特殊的标记。`[Authorize]`属性应用于作为页面使用的组件类，防止未经授权的用户访问页面。它的工作方式与在 ASP.NET Core MVC 中应用于控制器或操作方法时完全相同。

最后，`@inject`指令需要一个类型实例来注入依赖注入引擎，并将其插入到类型名称后声明的字段中；在前面的示例中，在`navigation`参数中。

组件文件的中间部分包含了将由 Razor 标记呈现的 HTML，其中可能包含对子组件的调用。

文件的底部由`@code`构造包围，并包含实现组件的类的字段、属性和方法：

```cs
@code{
 ...
 private string myField="0";
 [Parameter]
 public int Quantity {get; set;}=0;
 private void IncrementQuantity ()
 {
         Quantity++;
 }
 private void DecrementQuantity ()
 {
        Quantity--;
        if (Quantity<0) Quantity=0;
 }
 ... 
} 
```

用`[Parameter]`属性修饰的公共属性作为组件参数工作；也就是说，当组件实例化到另一个组件中时，它们用于将值传递给修饰的属性，就像在 HTML 标记中将值传递给 HTML 元素一样：

```cs
<OrderItem Quantity ="2" Id="123"/> 
```

值也可以通过页面路由参数传递给组件参数，这些参数与属性名称进行不区分大小写的匹配：

```cs
OrderItem/{id}/{quantity} 
```

组件参数也可以接受复杂类型和函数：

```cs
<modal title='() => "Test title" ' ...../> 
```

如果组件是通用的，它们必须为每个使用`typeparam`声明的通用参数传递类型值：

```cs
<myGeneric T= "string"……/> 
```

然而，通常编译器能够从其他参数的类型中推断出通用类型。

最后，`@code`指令包围的代码也可以在与组件相同的名称和命名空间的部分类中声明：

```cs
public partial class Counter
{
  [Parameter] 
public int CurrentCounter {get; set;}=0;
  ...
  ...
} 
```

通常，这些部分类被声明在与组件相同的文件夹中，并且文件名等于组件文件名加上`.cs`后缀。因此，例如，与`counter.razor`组件关联的部分类将是`counter.razor.cs`。

每个组件也可以有一个关联的 CSS 文件，其名称必须是组件文件名加上`.css`后缀。因此，例如，与`counter.razor`组件关联的 CSS 文件将是`counter.razor.css`。此文件中包含的 CSS 仅应用于该组件，对页面的其余部分没有影响。这称为 CSS 隔离，目前是通过向所有组件 HTML 根添加唯一属性来实现的。然后，组件 CSS 文件的所有选择器都被限定为此属性，以便它们不能影响其他 HTML。

每当一个组件用`[Parameter(CaptureUnmatchedValues = true)]`修饰一个`IDictionary<string, object>`参数时，那么所有未匹配的参数插入到标签中，也就是所有没有匹配组件属性的参数，都会作为键值对添加到`IDictionary`中。

此功能提供了一种简单的方法，将参数转发给组件标记中包含的 HTML 元素或其他子组件。例如，如果我们有一个`Detail`组件，它显示传递给其`Value`参数的对象的详细视图，我们可以使用此功能将所有常规 HTML 属性转发到组件的根 HTML 标记，如下例所示：

```cs
<div  @attributes="AdditionalAttributes">
...
</div>
@code{
[Parameter(CaptureUnmatchedValues = true)]
public Dictionary<string, object>
AdditionalAttributes { get; set; }
 [Parameter]
 Public T Value {get; set;}
} 
```

这样，添加到组件标记的常规 HTML 属性，例如 class，将被转发到组件的根`div`，并以某种方式用于样式化组件：

```cs
<Detail Value="myObject" class="my-css-class"/> 
```

下一小节解释了如何将生成标记的函数传递给组件。

## 模板和级联参数

Blazor 通过构建称为**渲染树**的数据结构来工作，该结构在 UI 更改时进行更新。在每次更改时，Blazor 会定位必须呈现的 HTML 部分，并使用**渲染树**中包含的信息来更新它。

`RenderFragment`委托定义了一个能够向**渲染树**的特定位置添加更多标记的函数。还有一个`RenderFragment<T>`，它接受一个进一步的参数，您可以使用它来驱动标记生成。例如，您可以将`Customer`对象传递给`RenderFragment<T>`，以便它可以呈现该特定客户的所有数据。

您可以使用 C#代码定义`RenderFragment`或`RenderFragment<T>`，但最简单的方法是在组件中使用 Razor 标记进行定义。Razor 编译器将负责为您生成适当的 C#代码：

```cs
RenderFragment myRenderFragment = @<p>The time is @DateTime.Now.</p>;
RenderFragment<Customer> customerRenderFragment = 
(item) => @<p>Customer name is @item.Name.</p>; 
```

有关添加标记的位置的信息是通过其接收的`RenderTreeBuilder`参数传递的。您可以通过简单调用它来在组件 Razor 标记中使用`RenderFragment`，如下例所示：

```cs
RenderFragment myRenderFragment = ...
  ...
<div>
  ...
  @myRenderFragment
  ...
</div>
  ... 
```

调用`RenderFragment`的位置定义了它将添加其标记的位置，因为组件编译器能够生成正确的`RenderTreeBuilder`参数传递给它。`RenderFragment<T>`委托的调用如下所示：

```cs
Customer myCustomer = ...
  ...
<div>
  ...
  @myRenderFragment(myCustomer)
  ...
</div>
  ... 
```

作为函数，渲染片段可以像所有其他类型一样传递给组件参数。但是，Blazor 有一种特定的语法，使同时定义和传递渲染片段到组件变得更容易，即**模板**语法。首先，在组件中定义参数：

```cs
[Parameter]
Public RenderFragment<Customer>CustomerTemplate {get; set;}
[Parameter]
Public RenderFragment Title {get; set;} 
```

然后，当您调用客户时，可以执行以下操作：

```cs
<Detail>
<Title>
<h5>This is a title</h5>
</Title>
<CustomerTemplate Context=customer>
<p>Customer name is @customer.Name.</p>
</CustomerTemplate >
</Detail> 
```

每个渲染片段参数都由与参数同名的标记表示。您可以将定义渲染片段的标记放在其中。对于具有参数的`CustomerTemplate`，`Context`关键字在标记内定义了参数名称。在我们的示例中，选择的参数名称是`customer`。

当组件只有一个渲染片段参数时，如果它的名称为`ChildContent`，则模板标记可以直接封闭在组件的开始和结束标记之间：

```cs
[Parameter]
Public RenderFragment<Customer> ChildContent {get; set;}
……………
……………
<IHaveJustOneRenderFragment Context=customer>
<p>Customer name is @customer.Name.</p>
</IHaveJustOneRenderFragment> 
```

为了熟悉组件模板，让我们修改`Pages->FetchData.razor`页面，以便不再使用`foreach`，而是使用`Repeater`组件。

让我们右键单击`Shared`文件夹，选择**添加**，然后**Razor 组件**，并添加一个新的**Repeater.razor**组件。然后，用以下内容替换现有代码：

```cs
@typeparam T
@foreach(var item in Values)
{
@ChildContent(item)
}
@code {
    [Parameter]
public RenderFragment<T> ChildContent { get; set; }
    [Parameter]
public IEnumerable<T> Values { get; set; }
} 
```

该组件使用泛型参数进行定义，以便可以与任何`IEnumerable`一起使用。现在让我们用这个替换**FetchData.razor**组件的`tbody`中的标记：

```cs
<Repeater Values="forecasts" Context="forecast">
<tr>
<td>@forecast.Date.ToShortDateString()</td>
<td>@forecast.TemperatureC</td>
<td>@forecast.TemperatureF</td>
<td>@forecast.Summary</td>
</tr>
</Repeater> 
```

由于`Repeater`组件只有一个模板，并且我们将其命名为`ChildContent`，因此我们可以直接在组件的开始和结束标记中放置我们的模板标记。运行它并验证页面是否正常工作。您已经学会了如何使用模板，以及放置在组件内部的标记定义了一个模板。

一个重要的预定义模板化 Blazor 组件是`CascadingValue`组件。它以不进行任何更改地呈现放置在其中的内容，但将类型实例传递给其所有后代组件：

```cs
<CascadingValue  Value="new MyOptionsInstance{...}">
……
</CascadingValue > 
```

现在，放置在`CascadingValue`标记内以及所有后代组件中的所有组件都可以捕获传递给`CascadingValueValue`参数的`MyOptionsInstance`实例。只需组件声明一个与`MyOptionsInstance`兼容的类型的公共或私有属性，并使用`CascadingParameter`属性进行修饰即可：

```cs
[CascadingParameter]
privateMyOptionsInstance options {get; set;} 
```

匹配是通过类型兼容性执行的。在与其他具有兼容类型的级联参数存在歧义的情况下，我们可以指定`CascadingValue`组件的`Name`可选参数，并将相同的名称传递给`CascadingParameter`属性：`[CascadingParameter("myUnique name")]`。

`CascadingValue`标签还有一个`IsFixed`参数，出于性能原因，应尽可能设置为`true`。实际上，传播级联值非常有用，用于传递选项和设置，但计算成本非常高。

当`IsFixed`设置为`true`时，传播仅在每个涉及内容的第一次呈现时执行，然后在内容的生命周期内不尝试更新级联值。因此，只要级联对象的指针在内容的生命周期内没有更改，就可以使用`IsFixed`。

级联值的一个例子是我们在*路由*小节中遇到的`CascadingAuthenticationState`组件，它将认证和授权信息级联到所有渲染的组件中。

## 事件

HTML 标记和 Blazor 组件都使用属性/参数来获取输入。HTML 标记通过事件向页面的其余部分提供输出，Blazor 允许将 C#函数附加到 HTML 的`on{event name}`属性。语法显示在`Pages->Counter.razor`组件中：

```cs
<p>Current count: @currentCount</p>
<button class="btn btn-primary" @onclick="IncrementCount">Click me</button>
@code {
private int currentCount = 0;
private void IncrementCount()
    {
        currentCount++;
    }
} 
```

该函数也可以作为 lambda 内联传递。此外，它接受通常的`event`参数的 C#等价物。*进一步阅读*部分包含了指向 Blazor 官方文档页面的链接，列出了所有支持的事件及其参数。

Blazor 还允许组件中的事件，因此它们也可以返回输出。组件事件是类型为`EventCallBack`或`EventCallBack<T>`的参数。`EventCallBack`是没有参数的组件事件类型，而`EventCallBack<T>`是带有类型为`T`的参数的组件事件类型。为了触发一个事件，比如`MyEvent`，组件调用：

```cs
awaitMyEvent.InvokeAsync() 
```

或者

```cs
awaitMyIntEvent.InvokeAsync(arg) 
```

这些调用执行与事件绑定的处理程序，如果没有绑定处理程序，则不执行任何操作。

一旦定义，组件事件可以与 HTML 元素事件完全相同的方式使用，唯一的区别在于不需要使用`@`前缀来命名事件，因为在 HTML 事件中，`@`是需要区分 HTML 属性和 Blazor 添加的具有相同名称的参数之间的区别：

```cs
[Parameter]
publicEventCallback MyEvent {get; set;}
[Parameter]
publicEventCallback<int> MyIntEvent {get; set;}
...
...
<ExampleComponent 
MyEvent="() => ..." 
MyIntEvent = "(i) =>..." /> 
```

实际上，HTML 元素事件也是`EventCallBack<T>`，这就是为什么这两种事件类型的行为完全相同。`EventCallBack`和`EventCallBack<T>`都是结构体，而不是委托，因为它们包含一个委托，以及一个指向必须被通知事件已被触发的实体的指针。从形式上讲，这个实体由`Microsoft.AspNetCore.Components.IHandleEvent`接口表示。不用说，所有组件都实现了这个接口。通知`IHandleEvent`发生了状态变化。状态变化在 Blazor 更新页面 HTML 的方式中起着基本作用。我们将在下一小节中详细分析它们。

对于 HTML 元素，Blazor 还提供了通过向指定事件的属性添加`:preventDefault`和`:stopPropagation`指令来阻止事件的默认操作和事件冒泡的可能性，就像这些例子中一样：

```cs
@onkeypress="KeyHandler" @onkeypress:preventDefault="true"
@onkeypress="KeyHandler" @onkeypress:preventDefault="true" @onkeypress:stopPropagation  ="true" 
```

## 绑定

通常，组件参数值必须与外部变量、属性或字段保持同步。这种同步的典型应用是在输入组件或 HTML 标记中编辑的对象属性。每当用户更改输入值时，对象属性必须一致更新，反之亦然。对象属性值必须在组件渲染时立即复制到组件中，以便用户可以编辑它。

类似的情况由参数-事件对处理。具体来说，一方面，属性被复制到输入组件参数中。另一方面，每当输入更改值时，都会触发一个更新属性的组件事件。这样，属性和输入值保持同步。

这种情况非常常见和有用，以至于 Blazor 有一个特定的语法，可以同时定义事件和将属性值复制到参数中。这种简化的语法要求事件与交互中涉及的参数具有相同的名称，但带有`Changed`后缀。

例如，假设一个组件有一个`Value`参数。那么相应的事件必须是`ValueChanged`。此外，每当用户更改组件值时，组件必须通过调用`await ValueChanged.InvokeAsync(arg)`来调用`ValueChanged`事件。有了这个设置，可以使用这里显示的语法将属性`MyObject.MyProperty`与`Value`属性同步：

```cs
<MyComponent @bind-Value="MyObject.MyProperty"/> 
```

上述语法称为**绑定**。Blazor 会自动附加一个更新`MyObject.MyProperty`属性的事件处理程序到`ValueChanged`事件。

HTML 元素的绑定方式类似，但由于开发人员无法决定参数和事件的名称，因此必须使用略有不同的约定。首先，无需在绑定中指定参数名称，因为它始终是 HTML 输入`value`属性。因此，绑定简单地写为`@bind="object.MyProperty"`。默认情况下，对象属性在`change`事件上更新，但您可以通过添加`@bind-event: @bind-event="oninput"`属性来指定不同的事件。

此外，HTML 输入的绑定尝试自动将输入字符串转换为目标类型。如果转换失败，输入将恢复到其初始值。这种行为相当原始，因为在出现错误时，不会向用户提供错误消息，并且文化设置没有得到正确的考虑（HTML5 输入使用不变的文化，但文本输入必须使用当前文化）。我们建议只将输入绑定到字符串目标类型。Blazor 具有专门用于处理日期和数字的组件，应该在目标类型不是字符串时使用。我们将在*Blazor 表单和验证*部分中对它们进行描述。

为了熟悉事件，让我们编写一个组件，当用户单击确认按钮时，同步输入文本类型的内容。右键单击`Shared`文件夹，然后添加一个新的**ConfirmedText.razor**组件。然后用以下代码替换其代码：

```cs
<input type="text" @bind="Value" @attributes="AdditionalAttributes"/>
<button class="btn btn-secondary" @onclick="Confirmed">@ButtonText</button>
@code {
    [Parameter(CaptureUnmatchedValues = true)]
public Dictionary<string, object> AdditionalAttributes { get; set; }
    [Parameter]
public string Value {get; set;}
    [Parameter]
public EventCallback<string> ValueChanged { get; set; }
    [Parameter]
public string ButtonText { get; set; }
async Task Confirmed()
    {
        await ValueChanged.InvokeAsync(Value);
    }
} 
```

`ConfirmedText`组件利用按钮点击事件来触发`ValueChanged`事件。此外，组件本身使用`@bind`将其`Value`参数与 HTML 输入同步。值得指出的是，组件使用`CaptureUnmatchedValues`将应用于其标记的所有 HTML 属性转发到 HTML 输入。这样，`ConfirmedText`组件的用户可以通过简单地向组件标记添加`class`和/或`style`属性来设置输入字段的样式。

现在让我们在`Pages->Index.razor`页面中使用此组件，方法是将以下代码放在`Index.razor`的末尾：

```cs
<ConfirmedText @bind-Value="textValue" ButtonText="Confirm" />
<p>
    Confirmed value is: @textValue
</p>
@code{
private string textValue = null;
} 
```

如果运行项目并与输入及其**确认**按钮进行交互，您会发现每次单击**确认**按钮时，不仅会将输入值复制到`textValue`页面属性中，而且组件后面段落的内容也会得到一致的更新。

我们明确使用`@bind-Value`将`textValue`与组件同步，但是谁负责保持`textValue`与段落内容同步？答案在下一小节中。

## Blazor 如何更新 HTML

当我们在 Razor 标记中写入变量、属性或字段的内容时，例如`@model.property`，Blazor 不仅在组件呈现时呈现变量、属性或字段的实际值，而且还尝试在该值每次更改时更新 HTML，这个过程称为**变更检测**。变更检测是所有主要 SPA 框架的特性，但 Blazor 实现它的方式非常简单和优雅。

基本思想是，一旦所有 HTML 都被呈现，更改只能因为在事件内执行的代码而发生。这就是为什么`EventCallBack`和`EventCallBack<T>`包含对`IHandleEvent`的引用。当组件将处理程序绑定到事件时，Razor 编译器创建一个`EventCallBack`或`EventCallBack<T>`，并在其`struct`构造函数中传递绑定到事件的函数以及定义该函数的组件（`IHandleEvent`）。

处理程序的代码执行后，Blazor 运行时会通知`IHandleEvent`可能已更改。实际上，处理程序代码只能更改组件中定义处理程序的变量、属性或字段的值。反过来，这会触发组件中的变更检测。Blazor 验证了组件 Razor 标记中使用的变量、属性或字段的更改，并更新相关的 HTML。

如果更改的变量、属性或字段是另一个组件的输入参数，则该组件生成的 HTML 可能也需要更新。因此，会递归触发另一个根据该组件触发的变更检测过程。

先前概述的算法仅在满足以下列出的条件时才发现所有相关更改：

1.  在事件处理程序中，没有组件引用其他组件的数据结构。

1.  所有组件的输入都通过其参数而不是通过方法调用或其他公共成员到达。

如果由于前述条件之一的失败而未检测到更改，则开发人员必须手动声明组件可能的更改。这可以通过调用`StateHasChanged()`组件方法来实现。由于此调用可能会导致页面 HTML 的更改，因此其执行不能异步进行，而必须在 HTML 页面 UI 线程中排队。这是通过将要执行的函数传递给`InvokeAsync`组件方法来完成的。

总结一下，要执行的指令是`await InvokeAsync(StateHasChanged)`。

下一小节总结了组件的生命周期及相关的生命周期方法的描述。

## 组件生命周期

每个组件生命周期事件都有一个关联的方法。一些方法既有同步版本又有异步版本，有些只有异步版本，而有些只有同步版本。

组件生命周期始于传递给组件的参数被复制到相关的组件属性中。您可以通过覆盖以下方法来自定义此步骤：

```cs
public override async Task SetParametersAsync(ParameterView parameters)
{
await ...
await base.SetParametersAsync(parameters);
} 
```

通常，定制包括修改其他数据结构，因此调用基本方法也执行将参数复制到相关属性的默认操作。

之后，与这两种方法相关联的组件初始化如下：

```cs
protected override void OnInitialized()
{
    ...
}
protected override async Task OnInitializedAsync()
{
await ...
} 
```

它们在组件生命周期中只被调用一次，即在组件创建并添加到渲染树后立即调用。请将任何初始化代码放在那里，而不是在组件构造函数中，因为这将提高组件的可测试性，因为在那里，您已经设置了所有参数，并且未来的 Blazor 版本可能会池化和重用组件实例。

如果初始化代码订阅了某些事件或执行需要在组件销毁时进行清理的操作，请实现`IDisposable`，并将所有清理代码放在其`Dispose`方法中。实际上，每当组件实现`IDisposable`时，Blazor 在销毁组件之前都会调用其`Dispose`方法。

组件初始化后，每次组件参数更改时，都会调用以下两种方法：

```cs
protected override async Task OnParametersSetAsync()
{
await ...
}
protected override void OnParametersSet()
{
    ...
} 
```

它们是更新依赖于组件参数值的数据结构的正确位置。

之后，组件被渲染或重新渲染。您可以通过覆盖`ShouldRender`方法来防止更新后组件重新渲染：

```cs
protected override bool ShouldRender()
{
...
} 
```

只有在确定其 HTML 代码将更改时，才让组件重新渲染是一种高级优化技术，用于组件库的实现中。

组件渲染阶段还涉及调用其子组件。因此，只有在所有后代组件完成渲染后，组件渲染才被认为是完整的。渲染完成后，将调用以下方法：

```cs
protected override void OnAfterRender(bool firstRender)
{
if (firstRender)
    {
    }
...
}
protected override async Task OnAfterRenderAsync(bool firstRender)
{
if (firstRender)
    {
    await...
        ...
    }
    await ...
} 
```

由于在调用上述方法时，所有组件 HTML 都已更新，并且所有子组件都已执行完其生命周期方法，因此上述方法是执行以下操作的正确位置：

+   调用操纵生成的 HTML 的 JavaScript 函数。JavaScript 调用在*JavaScript 互操作性*子部分中描述。

+   处理附加到参数或级联参数的信息由后代组件。事实上，类似标签的组件和其他组件可能需要在根组件中注册一些子部件，因此根组件通常会级联一个数据结构，其中一些子组件可以注册。在`AfterRender`和`AfterRenderAsync`中编写的代码可以依赖于所有子部件已完成其注册的事实。

下一节描述了 Blazor 用于收集用户输入的工具。

# Blazor 表单和验证

与所有主要的 SPA 框架类似，Blazor 还提供了特定的工具来处理用户输入，同时通过错误消息和即时视觉提示向用户提供有效的反馈。整个工具集被称为**Blazor Forms**，包括一个名为`EditForm`的表单组件，各种输入组件，数据注释验证器，验证错误摘要和验证错误标签。

`EditForm`负责编排所有输入组件的状态，通过表单内级联的`EditContext`类的实例。编排来自输入组件和数据注释验证器与此`EditContext`实例的交互。验证摘要和错误消息标签不参与编排，但会注册一些`EditContext`事件以便了解错误。

`EditForm`必须在其`Model`参数中传递其属性必须呈现的对象。值得指出的是，绑定到嵌套属性的输入组件不会被验证，因此`EditForm`必须传递一个扁平化的 ViewModel。`EditForm`创建一个新的`EditContext`实例，将其接收到的对象传递给其构造函数中的`Model`参数，并级联它以便它可以与表单内容交互。

您还可以直接在`EditForm`的`EditContext`参数中传递一个`EditContext`自定义实例，而不是在其`Model`参数中传递对象，这种情况下，`EditForm`将使用您的自定义副本而不是创建一个新实例。通常，当您需要订阅`EditContextOnValidationStateChanged`和`OnFieldChanged`事件时，可以这样做。

当使用**提交**按钮提交`EditForm`且没有错误时，表单会调用其`OnValidSubmit`回调，在这里您可以放置使用和处理用户输入的代码。如果有验证错误，表单会调用其`OnInvalidSubmit`回调。

每个输入的状态反映在自动添加到其中的一些 CSS 类中，即：`valid`，`invalid`和`modified`。您可以使用这些类为用户提供适当的视觉反馈。默认的 Blazor Visual Studio 模板已经为它们提供了一些 CSS。

以下是一个典型的表单：

```cs
<EditForm Model="FixedInteger"OnValidSubmit="@HandleValidSubmit" >
<DataAnnotationsValidator />
<ValidationSummary />
<div class="form-group">
<label for="integerfixed">Integer value</label>
<InputNumber @bind-Value="FixedInteger.Value"
id="integerfixed" class="form-control" />
<ValidationMessage For="@(() => FixedInteger.Value)" />
</div>
<button type="submit" class="btn btn-primary"> Submit</button>
</EditForm> 
```

标签是标准的 HTML 标签，而`InputNumber`是一个专门用于数字属性的 Blazor 组件。`ValidationMessage`是仅在验证错误发生时出现的错误标签。默认情况下，它以`validation-message` CSS 类呈现。与错误消息相关联的属性通过无参数的 lambda 传递给`for`参数，如示例所示。

`DataAnnotationsValidator`组件基于通常的.NET 验证属性（如`RangeAttribute`，`RequiredAttribute`等）添加了验证。您还可以通过继承`ValidationAttribute`类来编写自定义验证属性。

您可以在验证属性中提供自定义错误消息。如果它们包含`{0}`占位符，如果找到`DisplayAttribute`，则将填充为属性显示名称，否则将填充为属性名称。

除了`InputNumber`组件外，Blazor 还支持用于`string`属性的`InputText`组件，用于在 HTML`textarea`中编辑`string`属性的`InputTextArea`组件，用于`bool`属性的`InputCheckbox`组件，以及用于呈现`DateTime`和`DateTimeOffset`的`InputDate`组件。它们的工作方式与`InputNumber`组件完全相同。没有其他 HTML5 输入类型的组件可用。特别是，没有用于呈现时间或日期和时间，或用于使用`range`小部件呈现数字的组件。

您可以通过继承`InputBase<TValue>`类并重写`BuildRenderTree`、`FormatValueAsString`和`TryParseValueFromString`方法来实现渲染时间或日期和时间。`InputNumber`组件的源代码显示了如何做到这一点：[`github.com/dotnet/aspnetcore/blob/15f341f8ee556fa0c2825cdddfe59a88b35a87e2/src/Components/Web/src/Forms/InputNumber.cs`](https://github.com/dotnet/aspnetcore/blob/15f341f8ee556fa0c2825cdddfe59a88b35a87e2/src/Components/We)。您还可以使用*Blazor WebAssembly 的第三方工具*部分中描述的第三方库。

Blazor 还有一个专门用于呈现`select`的组件，其工作方式如下例所示：

```cs
<InputSelect @bind-Value="order.ProductColor">
<option value="">Select a color ...</option>
<option value="Red">Red</option>
<option value="Blue">Blue</option>
<option value="White">White</option>
</InputSelect> 
```

您还可以使用`InputRadioGroup`和`InputRadio`组件将枚举呈现为单选按钮组，如下例所示：

```cs
<InputRadioGroup Name="color" @bind-Value="order.Color">
<InputRadio Name="color" Value="AllColors.Red" /> Red<br>
<InputRadio Name="color" Value="AllColors.Blue" /> Blue<br>
<InputRadio Name="color" Value="AllColors.White" /> White<br>
</InputRadioGroup> 
```

最后，Blazor 还提供了一个`InputFile`组件以及处理和上传文件的所有工具。我们不会在这里介绍，但*进一步阅读*部分包含指向官方文档的链接。

本小节结束了对 Blazor 基础知识的描述；下一节将分析一些高级功能。

# Blazor 高级功能

本节收集了各种 Blazor 高级功能的简短描述，分为子节。由于篇幅有限，我们无法提供每个功能的所有细节，但缺少的细节在*进一步阅读*部分的链接中有所涵盖。我们从如何引用 Razor 标记中定义的组件和 HTML 元素开始。

## 组件和 HTML 元素的引用

有时我们可能需要引用组件以便调用其一些方法。例如，对于实现模态窗口的组件就是这种情况：

```cs
<Modal @ref="myModal">
...
</Modal>
...
<button type="button" class="btn btn-primary" 
@onclick="() => myModal.Show()">
Open modal
</button>
...
@code{
private Modal  myModal {get; set;}
 ...
} 
```

正如前面的例子所示，引用是使用`@ref`指令捕获的。相同的`@ref`指令也可以用于捕获对 HTML 元素的引用。HTML 引用具有`ElementReference`类型，并且通常用于在 HTML 元素上调用 JavaScript 函数，如下一小节所述。

## JavaScript 互操作性

由于 Blazor 不会将所有 JavaScript 功能暴露给 C#代码，并且由于方便利用可用的大量 JavaScript 代码库，有时需要调用 JavaScript 函数。Blazor 通过`IJSRuntime`接口允许这样做，该接口可以通过依赖注入注入到组件中。

一旦有了`IJSRuntime`实例，就可以调用返回值的 JavaScript 函数，如下所示：

```cs
T result = await jsRuntime.InvokeAsync<T>(
"<name of JavaScript function or method>", arg1, arg2....); 
```

不返回任何参数的函数可以像这样被调用：

```cs
awaitjsRuntime.InvokeAsync(
"<name of JavaScript function or method>", arg1, arg2....); 
```

参数可以是基本类型或可以在 JSON 中序列化的对象，而 JavaScript 函数的名称是一个字符串，可以包含表示属性、子属性和方法名称的点，例如`"myJavaScriptObject.myProperty.myMethod"`字符串。

参数也可以是使用`@ref`指令捕获的`ElementReference`实例，在这种情况下，它们在 JavaScript 端作为 HTML 元素接收。

调用的 JavaScript 函数必须在`Index.html`文件中定义，或者在`Index.html`中引用的 JavaScript 文件中定义。

如果您正在编写一个带有 Razor 库项目的组件库，JavaScript 文件可以作为 DLL 库中的资源与 CSS 文件一起嵌入。只需在项目根目录中添加一个`wwwroot`文件夹，并将所需的 CSS 和 JavaScript 文件放在该文件夹或其子文件夹中。之后，这些文件可以被引用为：

```cs
_content/<dll name>/<file path in wwwroot> 
```

因此，如果文件名为`myJsFile.js`，dll 名称为`MyCompany.MyLibrary`，并且文件放在`wwwroot`内的`js`文件夹中，则其引用将是：

```cs
_content/MyCompany.MyLibrary/js/myJsFile.js 
```

如果您的 JavaScript 文件组织为 ES6 模块，您可以避免在`Index.html`中引用它们，并可以直接加载模块，如下所示：

```cs
// _content/MyCompany.MyLibrary/js/myJsFile.js  JavaScript file 
export function myFunction ()
{
...
}
...
//C# code
var module = await jsRuntime.InvokeAsync<JSObjectReference>(
    "import", "./_content/MyCompany.MyLibrary/js/myJsFile.js");
...
T res= await module.InvokeAsync<T>("myFunction") 
```

此外，可以从 JavaScript 代码中调用 C#对象的实例方法，采取以下步骤：

1.  假设 C#方法名为`MyMethod`。请使用`[JSInvokable]`属性装饰`MyMethod`方法。

1.  将 C#对象封装在`DotNetObjectReference`实例中，并通过 JavaScript 调用将其传递给 JavaScript：

```cs
var objRef = DotNetObjectReference.Create(myObjectInstance);
//pass objRef to JavaScript
....
//dispose the DotNetObjectReference
objRef.Dispose() 
```

1.  在 JavaScript 方面，假设 C#对象在名为`dotnetObject`的变量中。然后只需调用：

```cs
dotnetObject.invokeMethodAsync("<dll name>", "MyMethod", arg1, ...).
then(result => {...}) 
```

下一节将解释如何处理内容和数字/日期本地化。

## 全球化和本地化

一旦 Blazor 应用程序启动，应用程序文化和应用程序 UI 文化都将设置为浏览器文化。但是，开发人员可以通过将所选文化分配给`CultureInfo.DefaultThreadCurrentCulture`和`CultureInfo.DefaultThreadCurrentUICulture`来更改它们。通常，应用程序允许用户选择其支持的文化之一，或者仅在支持的情况下接受浏览器文化，否则将回退到支持的文化。实际上，只能支持合理数量的文化，因为所有应用程序字符串必须在所有支持的文化中进行翻译。

一旦设置了`CurrentCulture`，日期和数字将根据所选文化的惯例自动格式化。对于 UI 文化，开发人员必须手动提供包含所有支持的文化中所有应用程序字符串翻译的资源文件。

有两种使用资源文件的方法。使用第一种选项，您创建一个资源文件，比如`myResource.resx`，然后添加所有特定语言的文件：`myResource.it.resx`，`myResource.pt.resx`等。在这种情况下，Visual Studio 会创建一个名为`myResource`的静态类，其静态属性是每个资源文件的键。这些属性将自动包含与当前 UI 文化对应的本地化字符串。您可以在任何地方使用这些静态属性，并且您可以使用由资源类型和资源名称组成的对来设置验证属性的`ErrorMessageResourceType`和`ErrorMessageResourceName`属性，或其他属性的类似属性。这样，属性将使用自动本地化的字符串。

使用第二种选项，您只添加特定语言的资源文件（`myResource.it.resx`，`myResource.pt.resx`等）。在这种情况下，Visual Studio 不会创建与资源文件关联的任何类，您可以将资源文件与在组件中注入的`IStringLocalizer`和`IStringLocalizer<T>`一起使用，就像在 ASP.NET Core MVC 视图中使用它们一样（请参阅*第十五章*的*ASP.NET Core 全球化*部分，*展示 ASP.NET Core MVC*）。

## 认证和授权

在*Routing*子部分中，我们概述了`CascadingAuthenticationState`和`AuthorizeRouteView`组件如何阻止未经授权的用户访问受`[Authorize]`属性保护的页面。让我们深入了解页面授权的工作原理。

在.NET 应用程序中，身份验证和授权信息通常包含在`ClaimsPrincipal`实例中。在服务器应用程序中，当用户登录时，将构建此实例，并从数据库中获取所需的信息。在 Blazor WebAssembly 中，此类信息必须由负责 SPA 身份验证的远程服务器提供。由于有几种方法可以为 Blazor WebAssembly 应用程序提供身份验证和授权，因此 Blazor 定义了`AuthenticationStateProvider`抽象。

身份验证和授权提供程序继承自`AuthenticationStateProvider`抽象类，并覆盖其`GetAuthenticationStateAsync`方法，该方法返回一个`Task<AuthenticationState>`，其中`AuthenticationState`包含身份验证和授权信息。实际上，`AuthenticationState`只包含一个具有`ClaimsPrincipal`的`User`属性。

一旦我们定义了`AuthenticationStateProvider`的具体实现，我们必须在应用程序的`program.cs`文件中将其注册到依赖引擎容器中。

```cs
services.AddScoped<AuthenticationStateProvider, MyAuthStateProvider>(); 
```

在描述了 Blazor 如何使用由注册的`AuthenticationStateProvider`提供的身份验证和授权信息后，我们将回到 Blazor 提供的`AuthenticationStateProvider`的预定义实现。

`CascadingAuthenticationState`组件调用注册的`AuthenticationStateProvider`的`GetAuthenticationStateAsync`方法，并级联返回的`Task<AuthenticationState>`。您可以使用以下方式在组件中定义`[CascadingParameter]`来拦截此级联值：

```cs
[CascadingParameter]
private Task<AuthenticationState>myAuthenticationStateTask { get; set; }
……
ClaimsPrincipal user = (await myAuthenticationStateTask).User; 
```

然而，Blazor 应用程序通常使用`AuthorizeRouteView`和`AuthorizeView`组件来控制用户对内容的访问。

`AuthorizeRouteView`如果用户不满足页面`[Authorize]`属性的要求，则阻止访问页面，否则将呈现`NotAuthorized`模板中的内容。`AuthorizeRouteView`还有一个`Authorizing`模板，当正在检索用户信息时会显示该模板。

`AuthorizeView`可以在组件内部使用，仅向经过授权的用户显示其包含的标记。它包含与`[Authorize]`属性相同的`Roles`和`Policy`参数，您可以使用这些参数来指定用户必须满足的约束以访问内容。

```cs
<AuthorizeView Roles="Admin,SuperUser">
//authorized content
</AuthorizeView> 
```

`AuthorizeView`还可以指定`NotAuthorized`和`Authorizing`模板：

```cs
<AuthorizeView>
<Authorized>
...
</Authorized>
<Authorizing>
        ...
</Authorizing>
<NotAuthorized>
        ...
</NotAuthorized>
</AuthorizeView> 
```

如果在创建 Blazor WebAssembly 项目时添加了授权，将向应用程序的依赖引擎添加以下方法调用：

```cs
builder.Services.AddApiAuthorization(); 
```

此方法添加了一个`AuthenticationStateProvider`，该提取用户信息的方式是从通常的 ASP.NET Core 身份验证 cookie 中提取。由于身份验证 cookie 是加密的，因此必须通过联系服务器公开的端点来执行此操作。此操作是通过本章的*加载和启动应用程序*子章节中看到的`AuthenticationService.js` JavaScript 文件来执行的。服务器端点以 bearer token 的形式返回用户信息，该 token 也可用于验证与服务器的 WEB API 的通信。有关 bearer token 的详细信息，请参见*第十四章*，*使用.NET Core 应用服务导向架构*中的*REST 服务授权和身份验证*和*ASP.NET Core 服务授权*部分。Blazor WebAssembly 通信将在下一子章节中描述。

如果找不到有效的身份验证 cookie，提供程序将创建一个未经身份验证的`ClaimsPrincipal`。这样，当用户尝试访问由`[Authorize]`属性保护的页面时，`AuthorizeRouteView`组件会调用`RedirectToLogin`组件，后者又会导航到`Authentication.razor`页面，并在其`action`路由参数中传递一个登录请求。

```cs
@page "/authentication/{action}"
@using Microsoft.AspNetCore.Components.WebAssembly.Authentication
<RemoteAuthenticatorView Action="@Action"  />
@code{
    [Parameter] public string Action { get; set; }
} 
```

`RemoteAuthenticatorView`充当与通常的 ASP.NET Core 用户登录/注册系统的接口，每当它接收要执行的“操作”时，都会将用户从 Blazor 应用程序重定向到适当的 ASP.NET Core 服务器页面（登录、注册、注销、用户资料）。

与服务器通信所需的所有信息都基于名称约定，但可以使用`AddApiAuthorization`方法的`options`参数进行自定义。例如，在那里，您可以更改用户可以注册的 URL，以及 Blazor 用于收集有关服务器设置的端点的地址。此端点位于`BlazorReview.Server->Controller->OidcConfigurationController.cs`文件中。

用户登录后，将被重定向到引起登录请求的 Blazor 应用程序页面。重定向 URL 由`BlazorReview.Client->Shared->RedirectToLogin.razor`组件计算，该组件从`NavigationManager`中提取 URL 并将其传递给`RemoteAuthenticatorView`组件。这次，`AuthenticationStateProvider`能够从登录操作创建的身份验证 cookie 中获取用户信息。

有关身份验证过程的更多详细信息，请参阅*Further reading*部分中的官方文档参考。

下一小节描述了`HttpClient`类和相关类型的 Blazor WebAssembly 特定实现。

## 与服务器的通信

Blazor WebAssembly 支持与*第十四章*，*应用.NET Core 的面向服务的架构*中描述的相同的.NET `HttpClient`和`HttpClientFactory`类。但是，由于浏览器的通信限制，它们的实现是不同的，并依赖于浏览器的**fetch API**。

在*第十四章*，*应用.NET Core 的面向服务的架构*中，我们分析了如何利用`HttpClientFactory`来定义类型化的客户端。您也可以使用完全相同的语法在 Blazor 中定义类型化的客户端。

然而，由于 Blazor 需要在每个请求中发送在身份验证过程中创建的令牌到应用程序服务器，因此通常会定义一个命名客户端，如下所示：

```cs
builder.Services.AddHttpClient("BlazorReview.ServerAPI", client =>
    client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress)
.AddHttpMessageHandler<BaseAddressAuthorizationMessageHandler>(); 
```

`AddHttpMessageHandler`添加了一个`DelegatingHandler`，即`DelegatingHandler`抽象类的子类。`DelegatingHandler`的实现重写了其`SendAsync`方法，以处理每个请求和每个相关响应：

```cs
protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
{
//modify request 
   ...
HttpResponseMessage= response = await base.SendAsync(
request, cancellationToken);
//modify response
   ...
return response;
} 
```

`BaseAddressAuthorizationMessageHandler`是通过我们在前一节中看到的`AddApiAuthorization`调用添加到依赖注入引擎中的。它将由授权过程生成的令牌添加到每个发送到应用程序服务器域的请求中。如果此令牌已过期或根本找不到，则它会尝试从用户身份验证 cookie 中获取新的令牌。如果此尝试也失败，则会抛出`AccessTokenNotAvailableException`。通常，类似的异常会被捕获并触发重定向到登录页面（默认情况下为`/authentication/{action}`）：

```cs
try
    {
        //server call here
    }
catch (AccessTokenNotAvailableException exception)
    {
        exception.Redirect();
    } 
```

由于大多数请求都是针对应用程序服务器的，并且只有少数调用可能会与 CORS 联系其他服务器，因此`BlazorReview.ServerAPI`命名为`client`也被定义为默认的`HttpClient`实例：

```cs
builder.Services.AddScoped(sp =>
                sp.GetRequiredService<IHttpClientFactory>()
                    .CreateClient("BlazorReview.ServerAPI")); 
```

可以通过向依赖注入引擎请求`HttpClient`实例来获取默认客户端。可以通过定义使用其他令牌的其他命名客户端来处理对其他服务器的 CORS 请求。可以通过首先从依赖注入中获取`IHttpClientFactory`实例，然后调用其`CreateClient("<named client name>")`方法来获取命名客户端。Blazor 提供了用于获取令牌和连接到知名服务的包。它们在*Further reading*部分中的授权文档中有描述。

接下来的部分简要讨论了一些最相关的第三方工具和库，这些工具和库完善了 Blazor 的官方功能，并帮助提高 Blazor 项目的生产力。

# Blazor WebAssembly 的第三方工具

尽管 Blazor 是一个年轻的产品，但其第三方工具和产品生态系统已经相当丰富。在开源、免费产品中，值得一提的是**Blazorise**项目（[`github.com/stsrki/Blazorise`](https://github.com/stsrki/Blazorise)），其中包含各种免费的基本 Blazor 组件（输入、选项卡、模态框等），可以使用各种 CSS 框架（如 Bootstrap 和 Material）进行样式设置。它还包含一个简单的可编辑网格和一个简单的树视图。

另外值得一提的是**BlazorStrap**（[`github.com/chanan/BlazorStrap`](https://github.com/chanan/BlazorStrap)），其中包含了所有 Bootstrap 4 组件和小部件的纯 Blazor 实现。

在所有商业产品中，值得一提的是**Blazor Controls Toolkit**（[`blazor.mvc-controls.com/`](http://blazor.mvc-controls.com/)），这是一个用于实现商业应用程序的完整工具集。它包含了所有输入类型及其在浏览器不支持时的回退；所有 Bootstrap 组件；其他基本组件；以及一个完整的、高级的拖放框架；高级可定制和可编辑的组件，如详细视图、详细列表、网格、树重复器（树视图的泛化）。所有组件都基于一个复杂的元数据表示系统，使用户能够使用数据注释和内联 Razor 声明以声明方式设计标记。

此外，它还包含了额外复杂的验证属性，撤消用户输入的工具，计算发送到服务器的更改的工具，基于 OData 协议的复杂客户端和服务器端查询工具，以及用于维护和保存整个应用程序状态的工具。

还值得一提的是**bUnit**开源项目（[`github.com/egil/bUnit`](https://github.com/egil/bUnit)），它提供了测试 Blazor 组件的所有工具。

接下来的部分将展示如何将所学知识付诸实践，实现一个简单的应用程序。

# 用例 - 在 Blazor WebAssembly 中实现一个简单的应用程序

在本节中，我们将为*WWTravelClub*书籍使用案例实现一个包搜索应用程序。第一小节解释了如何利用我们在*第十五章* *介绍 ASP.NET Core MVC*中已经实现的域层和数据层来设置解决方案。

## 准备解决方案

首先，创建一个**PackagesManagement**解决方案文件夹的副本，我们在*第十五章* *介绍 ASP.NET Core MVC*中创建，并将其重命名为**PackagesManagementBlazor**。

打开解决方案，右键单击 Web 项目（名为**PackagesManagement**）并删除它。然后，转到解决方案文件夹并删除整个 Web 项目文件夹（名为**PackagesManagement**）。

现在右键单击解决方案，然后选择**添加新项目**。添加一个名为**PackagesManagementBlazor**的新的 Blazor WebAssembly 项目。选择**无身份验证**和**ASP.NET Core 托管**。我们不需要身份验证，因为我们将要实现的按位置搜索功能也必须对未注册用户可用。

确保**PackagesManagementBlazor.Server**项目是启动项目（其名称应为粗体）。如果不是，请右键单击它，然后单击**设置为启动项目**。

服务器项目需要引用数据（**PackagesManagementDB**）和域（**PackagesManagementDomain**）项目，请将它们添加为引用。

让我们也将旧 Web 项目的相同连接字符串复制到`PackagesManagementBlazor.Serverappsettings.json`文件中：

```cs
"ConnectionStrings": {
        "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=package-management;Trusted_Connection=True;MultipleActiveResultSets=true"
 }, 
```

这样，我们可以重用我们已经创建的数据库。我们还需要添加与旧 Web 项目添加的相同的 DDD 工具。在项目根目录中添加一个名为`Tools`的文件夹，并将与该书籍关联的 GitHub 存储库的`ch12->ApplicationLayer`文件夹的内容复制到其中。

为了完成解决方案设置，我们只需要通过在`Startup.cs`文件的`ConfigureServices`方法的末尾添加以下代码来将**PackagesManagementBlazor.Server**与域层连接起来：

```cs
services.AddDbLayer(Configuration
                .GetConnectionString("DefaultConnection"),
                "PackagesManagementDB"); 
```

这是我们在旧的 Web 项目中添加的相同方法。最后，我们还可以添加`AddAllQueries`扩展方法，它会发现 Web 项目中的所有查询：

```cs
services.AddAllQueries(this.GetType().Assembly); 
```

由于这是一个仅查询的应用程序，我们不需要其他自动发现工具。

下一小节将解释如何设计服务器端的 REST API。

## 实现所需的 ASP.NET Core REST API

作为第一步，让我们定义在服务器和客户端应用程序之间通信中使用的 ViewModels。它们必须在被两个应用程序引用的**PackagesManagementBlazor.Shared**项目中定义。

让我们从`PackageInfosViewModel` ViewModel 开始：

```cs
using System;
namespace PackagesManagementBlazor.Shared
{
    public class PackageInfosViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public int DurationInDays { get; set; }
        public DateTime? StartValidityDate { get; set; }
        public DateTime? EndValidityDate { get; set; }
        public string DestinationName { get; set; }
        public int DestinationId { get; set; }
        public override string ToString()
        {
            return string.Format("{0}. {1} days in {2}, price: {3}",
                Name, DurationInDays, DestinationName, Price);
        }
    }
} 
```

然后，还要添加一个 ViewModel，它包含要返回给 Blazor 应用程序的所有软件包：

```cs
using System.Collections.Generic;
namespace PackagesManagementBlazor.Shared
{
    public class PackagesListViewModel
    {
        public IEnumerable<PackageInfosViewModel>
            Items { get; set; }
    }
} 
```

现在我们还可以添加我们的查询，通过位置搜索软件包。让我们在**PackagesManagementBlazor.Server**项目的根目录中添加一个`Queries`文件夹，然后添加定义我们查询的接口`IPackagesListByLocationQuery`：

```cs
using DDD.ApplicationLayer;
using PackagesManagementBlazor.Shared;
using System.Collections.Generic;
using System.Threading.Tasks;
namespace PackagesManagementBlazor.Server.Queries
{
    public interface IPackagesListByLocationQuery: IQuery
    {
        Task<IEnumerable<PackageInfosViewModel>>
            GetPackagesOf(string location); 
    }
} 
```

最后，让我们也添加查询实现：

```cs
public class PackagesListByLocationQuery:IPackagesListByLocationQuery
    {
        private readonly MainDbContext ctx;
        public PackagesListByLocationQuery(MainDbContext ctx)
        {
            this.ctx = ctx;
        }
        public async Task<IEnumerable<PackageInfosViewModel>> GetPackagesOf(string location)
        {
            return await ctx.Packages
                .Where(m => m.MyDestination.Name.StartsWith(location))
                .Select(m => new PackageInfosViewModel
            {
                StartValidityDate = m.StartValidityDate,
                EndValidityDate = m.EndValidityDate,
                Name = m.Name,
                DurationInDays = m.DurationInDays,
                Id = m.Id,
                Price = m.Price,
                DestinationName = m.MyDestination.Name,
                DestinationId = m.DestinationId
            })
                .OrderByDescending(m=> m.EndValidityDate)
                .ToListAsync();
        }
    } 
```

我们终于准备好定义我们的`PackagesController`：

```cs
using Microsoft.AspNetCore.Mvc;
using PackagesManagementBlazor.Server.Queries;
using PackagesManagementBlazor.Shared;
using System.Threading.Tasks;
namespace PackagesManagementBlazor.Server.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class PackagesController : ControllerBase
    {
        // GET api/<PackagesController>/Flor
        [HttpGet("{location}")]
        public async Task<PackagesListViewModel> Get(string location, 
            [FromServices] IPackagesListByLocationQuery query )
        {
            return new PackagesListViewModel
            {
                Items = await query.GetPackagesOf(location)
            };
        }  
    }
} 
```

服务器端代码已经完成！让我们继续定义与服务器通信的 Blazor 服务。

## 在服务中实现业务逻辑

让我们在**PackagesManagementBlazor.Client**项目中添加一个`ViewModels`和一个`Services`文件夹。我们需要的大多数 ViewModel 已经在**PackagesManagementBlazor.Shared**项目中定义。我们只需要一个用于搜索表单的 ViewModel。让我们将其添加到`ViewModels`文件夹中：

```cs
using System.ComponentModel.DataAnnotations;
namespace PackagesManagementBlazor.Client.ViewModels
{
    public class SearchViewModel
    {
        [Required]
        public string Location { get; set; }
    }
} 
```

让我们称我们的服务为`PackagesClient`，并将其添加到`Services`文件夹中：

```cs
namespace PackagesManagementBlazor.Client.Services
{
    public class PackagesClient
    {
        private HttpClient client;
        public PackagesClient(HttpClient client)
        {
            this.client = client;
        }
        public async Task<IEnumerable<PackageInfosViewModel>>
            GetByLocation(string location)
        {
            var result =
                await client.GetFromJsonAsync<PackagesListViewModel>
                    ("Packages/" + Uri.EscapeDataString(location));
            return result.Items;
        }
    }
} 
```

代码很简单！`Uri.EscapeDataString`方法对参数进行 url 编码，以便可以安全地附加到 URL 上。

最后，让我们在依赖注入中注册服务：

```cs
builder.Services.AddScoped<PackagesClient>(); 
```

值得指出的是，在商业应用程序中，我们应该通过`IPackagesClient`接口注册服务，以便能够在测试中模拟它（`.AddScoped<IPackagesClient, PackagesClient>()`）。

一切就绪；我们只需要构建 UI。

## 实现用户界面

作为第一步，让我们删除我们不需要的应用页面，即`Pages->Counter.razor`和`Pages->FetchData.razor`。让我们还从`Shared->NavMenu.razor`中的侧边菜单中删除它们的链接。

我们将把我们的代码放在`Pages->Index.razor`页面中。让我们用以下代码替换此页面的代码：

```cs
@using PackagesManagementBlazor.Client.ViewModels
@using PackagesManagementBlazor.Shared
@using PackagesManagementBlazor.Client.Services
@inject PackagesClient client
@page "/"
<h1>Search packages by location</h1>
<EditForm Model="search"
          OnValidSubmit="Search">
<DataAnnotationsValidator />
<div class="form-group">
<label for="integerfixed">Insert location starting chars</label>
<InputText @bind-Value="search.Location" />
<ValidationMessage For="@(() => search.Location)" />
</div>
<button type="submit" class="btn btn-primary">
        Search
</button>
</EditForm>
@code{
    SearchViewModel search { get; set; } 
= new SearchViewModel();
    async Task Search()
    {
        ...
    }
} 
```

前面的代码添加了所需的`@using`，在页面中注入了我们的`PackagesClient`服务，并定义了搜索表单。当表单成功提交时，它会调用`Search`回调，我们将在其中放置检索所有结果的代码。

现在是时候添加显示所有结果的逻辑并完成`@code`块了。以下代码必须立即放在搜索表单之后：

```cs
@if (packages != null)
{
...
}
else if (loading)
{
    <p><em>Loading...</em></p>
}
@code{
    SearchViewModel search { get; set; } = new SearchViewModel();
    private IEnumerable<PackageInfosViewModel> packages;
    bool loading;
    async Task Search()
    {
        packages = null;
        loading = true;
        await InvokeAsync(StateHasChanged);
        packages = await client.GetByLocation(search.Location);
        loading = false;
    }
} 
```

`if`块中省略的代码负责渲染带有所有结果的表格。在注释了前面的代码之后，我们将显示它。

在使用`PackagesClient`服务检索结果之前，我们删除所有先前的结果并设置`loading`字段，因此 Razor 代码选择`else if`路径，用加载消息替换先前的表。一旦我们设置了这些变量，就必须调用`StateHasChanged`来触发变化检测并刷新页面。在检索到所有结果并且回调返回后，不需要再次调用`StateHasChanged`，因为回调本身的终止会触发变化检测并导致所需的页面刷新。

以下是呈现包含所有结果的表的代码：

```cs
<div class="table-responsive">
  <table class="table">
    <thead>
      <tr>
        <th scope="col">Destination</th>
        <th scope="col">Name</th>
        <th scope="col">Duration/days</th>
        <th scope="col">Price</th>
        <th scope="col">Available from</th>
        <th scope="col">Available to</th>
      </tr>
    </thead>
    <tbody>
      @foreach (var package in packages)
      {
        <tr>
          <td>
            @package.DestinationName
          </td>
          <td>
            @package.Name
          </td>
          <td>
            @package.DurationInDays
          </td>
          <td>
            @package.Price
          </td>
          <td>
            @(package.StartValidityDate.HasValue ?
              package.StartValidityDate.Value.ToString("d")
              :
              String.Empty)
          </td>
          <td>
            @(package.EndValidityDate.HasValue ?
              package.EndValidityDate.Value.ToString("d")
              :
              String.Empty)
          </td>
        </tr>
      }
    </tbody>
  </table>
</div> 
```

运行项目并编写 Florence 的初始字符。由于在之前的章节中，我们在数据库中插入了 Florence 作为一个位置，所以应该会出现一些结果！

# 总结

在本章中，您了解了 SPA 是什么，并学习了如何基于 Blazor WebAssembly 框架构建 SPA。本章的第一部分描述了 Blazor WebAssembly 架构，然后解释了如何与 Blazor 组件交换输入/输出以及绑定的概念。

在解释了 Blazor 的一般原则之后，本章重点介绍了如何在提供用户输入的同时，在出现错误时为用户提供足够的反馈和视觉线索。然后，本章简要介绍了高级功能，如 JavaScript 互操作性，全球化，授权认证和客户端-服务器通信。

最后，从书中用户案例中提取的实际示例展示了如何在实践中使用 Blazor 来实现一个简单的旅游套餐搜索应用程序。

# 问题

1.  WebAssembly 是什么？

1.  SPA 是什么？

1.  Blazor `router`组件的目的是什么？

1.  Blazor 页面是什么？

1.  `@namespace`指令的目的是什么？

1.  `EditContext`是什么？

1.  初始化组件的正确位置是什么？

1.  处理用户输入的正确位置是什么？

1.  `IJSRuntime`接口是什么？

1.  `@ref`的目的是什么？

# 进一步阅读

+   Blazor 官方文档可在此处找到：[`docs.microsoft.com/en-US/aspnet/core/blazor/webassembly-lazy-load-assemblies`](https://docs.microsoft.com/en-US/aspnet/core/blazor/webassembly-lazy-load-assemblies)。

+   有关程序集的延迟加载的描述在此处：[`docs.microsoft.com/en-US/aspnet/core/blazor/webassembly-lazy-load-assemblies`](https://docs.microsoft.com/en-US/aspnet/core/blazor/webassembly-lazy-load-assemblies)。

+   Blazor 支持的所有 HTML 事件及其事件参数均列在：[`docs.microsoft.com/en-US/aspnet/core/blazor/components/event-handling?#event-argument-types`](https://docs.microsoft.com/en-US/aspnet/core/blazor/components/event-handling?#event-argument-types)。

+   Blazor 支持与 ASP.NET MVC 相同的验证属性，但不包括`RemoteAttribute`：[`docs.microsoft.com/en-us/aspnet/core/mvc/models/validation#built-in-attributes`](https://docs.microsoft.com/en-us/aspnet/core/mvc/models/validation#built-in-attributes)。

+   `InputFile`组件的描述以及如何使用它可以在这里找到：[`docs.microsoft.com/en-US/aspnet/core/blazor/file-uploads`](https://docs.microsoft.com/en-US/aspnet/core/blazor/file-uploads)。

+   有关 Blazor 本地化和全球化的更多详细信息可在此处找到：[`docs.microsoft.com/en-US/aspnet/core/blazor/globalization-localization`](https://docs.microsoft.com/en-US/aspnet/core/blazor/globalization-localization)。

+   有关 Blazor 身份验证的更多详细信息可在此处找到，以及所有相关 URL：[`docs.microsoft.com/en-US/aspnet/core/blazor/security/webassembly/`](https://docs.microsoft.com/en-US/aspnet/core/blazor/security/webassembly/)。


# 第十七章：C# 9 的最佳编码实践

当你在项目中担任软件架构师时，你有责任定义和/或维护一个编码标准，指导团队按照公司的期望进行编程。本章涵盖了一些编码的最佳实践，将帮助像你这样的开发人员编写安全、简单和可维护的软件。它还包括了在 C#中编码的技巧和窍门。

本章将涵盖以下主题：

+   你的代码复杂性如何影响性能

+   使用版本控制系统的重要性

+   在 C#中编写安全代码

+   编码的.NET 核心技巧和窍门

+   书中用例-编写代码的 Dos 和 Don'ts

C# 9 与.NET 5 一起推出。然而，这里介绍的实践可以在许多版本的.NET 中使用，但它们涉及 C#编程的基础。

# 技术要求

本章需要使用 Visual Studio 2019 免费的社区版或更高版本，并安装所有数据库工具。你可以在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)找到本章的示例代码。

# 你的代码越复杂，你就是一个越糟糕的程序员

对于许多人来说，一个优秀的程序员是那种编写复杂代码的人。然而，软件开发成熟度的演变意味着有一种不同的思考方式。复杂性并不意味着工作做得好；它意味着代码质量差。一些令人难以置信的科学家和研究人员已经证实了这一理论，并强调专业代码需要专注于时间、高质量和预算内完成。

即使你手头上有一个复杂的情景，如果你减少模糊不清的地方并澄清你编写的过程，特别是使用良好的方法和变量名称，并遵守 SOLID 原则，你将把复杂性转化为简单的代码。

因此，如果你想编写优秀的代码，你需要专注于如何做到这一点，考虑到你不是唯一一个以后会阅读它的人。这是一个改变你编写代码方式的好建议。这就是我们将讨论本章的每个要点的方式。

如果你对编写优秀代码的重要性的理解与在编写代码时的简单和清晰的想法一致，你应该看一下 Visual Studio 工具**代码度量**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_01.png)

图 17.1：在 Visual Studio 中计算代码度量

**代码度量**工具将提供度量标准，让你了解你正在交付的软件的质量。该工具提供的度量标准可以在此链接找到：[`docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-values?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-values?view=vs-2019)。以下小节重点描述了它们在一些实际场景中的用途。

## 可维护性指数

这个指数表示维护代码的难易程度-代码越容易，指数越高（限制为 100）。易于维护是保持软件健康的关键点之一。显然，任何软件都将需要未来的更改，因为变化是不可避免的。因此，如果你的可维护性水平低，考虑重构你的代码。编写专门负责单一职责的类和方法，避免重复代码，限制每个方法的代码行数是你可以提高可维护性指数的例子。

## 圈复杂度

《圈复杂度指标》的作者是 Thomas J. McCabe。他根据软件函数可用的代码路径数量（图节点）来定义函数的复杂性。路径越多，函数就越复杂。McCabe 认为每个函数的复杂度得分必须小于 10。这意味着，如果代码有更复杂的方法，您必须对其进行重构，将这些代码的部分转换为单独的方法。有一些真实的场景可以很容易地检测到这种行为：

+   循环内的循环

+   大量连续的`if-else`

+   在同一个方法中处理每个`case`的`switch`

例如，看一下处理信用卡交易的不同响应的此方法的第一个版本。正如您所看到的，圈复杂度大于 McCabe 所考虑的基数。这种情况发生的原因是主`switch`的每个`case`内部的`if-else`的数量：

```cs
/// <summary>
/// This code is being used just for explaining the concept of cyclomatic complexity. 
/// It makes no sense at all. Please Calculate Code Metrics for understanding 
/// </summary>
private static void CyclomaticComplexitySample()
{
  var billingMode = GetBillingMode();
  var messageResponse = ProcessCreditCardMethod();
  switch (messageResponse)
    {
      case "A":
        if (billingMode == "M1")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "B":
        if (billingMode == "M2")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "C":
        if (billingMode == "M3")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "D":
        if (billingMode == "M4")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "E":
        if (billingMode == "M5")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "F":
        if (billingMode == "M6")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "G":
        if (billingMode == "M7")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      case "H":
        if (billingMode == "M8")
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        else
          Console.WriteLine($"Billing Mode {billingMode} for " +
            $"Message Response {messageResponse}");
        break;
      default:
        Console.WriteLine("The result of processing is unknown");
        break;
    }
} 
```

如果您计算此代码的代码指标，您将发现在圈复杂度方面的结果很糟糕，正如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_02.png)

图 17.2：高圈复杂度

代码本身没有意义，但这里的重点是向您展示可以通过编写更好的代码来进行多少改进：

+   `switch-case`中的选项可以使用`Enum`来编写

+   每个`case`处理可以在一个特定的方法中完成

+   `switch-case`可以用`Dictionary<Enum, Method>`来替换

通过使用前述技术重构此代码，结果是一段更容易理解的代码，如下面的主方法的代码片段所示：

```cs
static void Main()
{
    var billingMode = GetBillingMode();
    var messageResponse = ProcessCreditCardMethod();
Dictionary<CreditCardProcessingResult, CheckResultMethod>
methodsForCheckingResult =GetMethodsForCheckingResult();
    if (methodsForCheckingResult.ContainsKey(messageResponse))
        methodsForCheckingResultmessageResponse;
    else
        Console.WriteLine("The result of processing is unknown");
} 
```

完整的代码可以在本章的 GitHub 存储库中找到，并演示了如何实现更低复杂度的代码。以下屏幕截图显示了这些结果，根据代码指标：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_03.png)

图 17.3：重构后的圈复杂度减少

正如您在前面的屏幕截图中所看到的，重构后复杂性大大减少。在第十三章《在 C# 9 中实现代码重用性》中，我们讨论了重构对于代码重用的重要性。我们在这里做这个的原因是一样的-我们想要消除重复。

关键点在于，通过应用这些技术，代码的理解增加了，复杂性减少了，证明了圈复杂度的重要性。

## 继承深度

这个指标代表了与正在分析的类连接的类的数量。您继承的类越多，指标就会越糟。这就像类耦合一样，表明了更改代码有多困难。例如，以下屏幕截图中有四个继承类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_04.png)

图 17.4：继承深度示例

您可以在以下屏幕截图中看到，更深的类具有更糟糕的指标，因为有三个其他类可以更改其行为：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_05.png)

图 17.5：继承深度指标

继承是基本的面向对象分析原则之一。然而，它有时可能对您的代码不利，因为它可能导致依赖性。因此，如果有意义的话，考虑使用组合而不是继承。

## 类耦合

当您在一个类中连接太多类时，显然会产生耦合，这可能会导致代码维护不良。例如，参考以下屏幕截图。它显示了一个已经执行了大量聚合的设计。代码本身没有意义：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_06.png)

图 17.6：类耦合示例

一旦您计算了前述设计的代码指标，您将看到`ProcessData()`方法的类耦合实例数，该方法调用`ExecuteTypeA()`、`ExecuteTypeB()`和`ExecuteTypeC()`，等于三（`3`）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_07.png)

图 17.7：类耦合度指标

一些论文指出，类耦合实例的最大数量应为九（`9`）。聚合比继承更好的实践，使用接口将解决类耦合问题。例如，相同的代码在以下设计中将给出更好的结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_08.png)

图 17.8：减少类耦合

注意，在设计中使用接口将允许您增加执行类型的数量，而不增加解决方案的类耦合度：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_09.png)

图 17.9：应用聚合后的类耦合结果

作为软件架构师，您必须考虑设计您的解决方案具有更多的内聚性而不是耦合性。文献表明，良好的软件具有低耦合和高内聚。在软件开发中，高内聚表示一个场景，其中每个类必须具有其方法和数据，并且它们之间有良好的关系。另一方面，低耦合表示软件中的类不是紧密和直接连接的。这是一个基本原则，可以指导您获得更好的架构模型。

## 代码行数

这个指标在让您了解您正在处理的代码规模方面是有用的。代码行数和复杂性之间没有联系，因为行数并不表示复杂性。另一方面，代码行数显示了软件的规模和软件设计。例如，如果一个类中有太多的代码行数（超过 1000 行代码-1KLOC），这表明它是一个糟糕的设计。

# 使用版本控制系统

你可能会觉得这本书中的这个主题有点显而易见，但许多人和公司仍然不将拥有版本控制系统视为软件开发的基本工具！写这个主题的想法是强迫你去理解它。如果你不使用版本控制系统，没有任何架构模型或最佳实践可以拯救软件开发。

在过去的几年里，我们一直在享受在线版本控制系统的优势，比如 GitHub、BitBucket 和 Azure DevOps。事实上，您必须在软件开发生命周期中拥有这样的工具，而且现在没有理由不拥有它，因为大多数提供商为小团队提供免费版本。即使您是独自开发，这些工具也可以用于跟踪您的更改，管理您的软件版本，并保证代码的一致性和完整性。

## 团队中处理版本控制系统

当你独自一人时使用版本控制系统工具是显而易见的。你想保护你的代码。但这种系统是为了解决编写代码时的团队问题而开发的。因此，一些功能，比如分支和合并，被引入以保持代码的完整性，即使在开发人员数量相当大的情况下也是如此。

作为软件架构师，您将不得不决定在团队中进行哪种分支策略。Azure DevOps 和 GitHub 提出了不同的交付方式，并且在某些场景中都是有用的。

关于 Azure DevOps 团队如何处理这个问题，可以在这里找到：[`devblogs.microsoft.com/devops/release-flow-how-we-do-branching-on-the-vsts-team/`](https://devblogs.microsoft.com/devops/release-flow-how-we-do-branching-on-the-vsts-team/)。GitHub 在[`guides.github.com/introduction/flow/`](https://guides.github.com/introduction/flow/)中描述了它的流程。我们不知道哪一个最适合您的需求，但我们希望您明白您需要有控制代码的策略。

在*第二十章*，*理解 DevOps 原则*中，我们将更详细地讨论这个问题。

# 在 C#中编写安全的代码

C#可以被认为是一种安全的编程语言。除非强制使用，否则不需要指针，并且在大多数情况下，内存释放由垃圾收集器管理。即便如此，您应该小心，以便从代码中获得更好和更安全的结果。让我们看一些确保 C#代码安全的常见做法。

## try-catch

编码中的异常是如此频繁，以至于每当它们发生时，您都应该有一种管理它们的方式。`try-catch`语句是用于管理异常的，并且对于保持代码安全非常重要。有很多情况下，应用程序崩溃的原因是缺乏使用`try-catch`。以下代码显示了缺乏使用`try-catch`语句的示例。值得一提的是，这只是一个例子，用于理解没有正确处理的异常概念。考虑使用`int.TryParse(textToConvert, out int result)`来处理解析不成功的情况：

```cs
private static int CodeWithNoTryCatch(string textToConvert)
{
    return Convert.ToInt32(textToConvert);
} 
```

另一方面，不正确使用`try-catch`也可能对您的代码造成损害，特别是因为您将看不到该代码的正确行为，并且可能会误解提供的结果。

以下代码显示了一个空的`try-catch`语句：

```cs
private static int CodeWithEmptyTryCatch(string textToConvert)
{
    try
    {
        return Convert.ToInt32(textToConvert);
    }
    catch
    {
        return 0;
    }
} 
```

`try-catch`语句必须始终与日志记录解决方案连接，以便您可以从系统获得响应，指示正确的行为，并且不会导致应用程序崩溃。以下代码显示了具有日志管理的理想`try-catch`语句。值得一提的是，尽可能捕获特定异常，因为捕获一般异常会隐藏意外异常：

```cs
private static int CodeWithCorrectTryCatch(string textToConvert)
{
    try
    {
        return Convert.ToInt32(textToConvert);
    }
    catch (FormatException err)
    {
        Logger.GenerateLog(err);
        return 0;
    }
} 
```

作为软件架构师，您应该进行代码检查，以修复代码中发现的这种行为。系统的不稳定性通常与代码中缺乏`try-catch`语句有关。

## try-finally 和 using

内存泄漏可以被认为是软件的最糟糕行为之一。它们会导致不稳定性，计算机资源的不良使用和不希望的应用程序崩溃。C#试图通过垃圾收集器解决这个问题，一旦它意识到对象可以被释放，就会自动释放内存中的对象。

与 I/O 交互的对象通常不受垃圾收集器管理：文件系统，套接字等。以下代码是`FileStream`对象的不正确使用示例，因为它认为垃圾收集器会释放所使用的内存，但实际上不会：

```cs
private static void CodeWithIncorrectFileStreamManagement()
{
    FileStream file = new FileStream("C:\\file.txt",
        FileMode.CreateNew);
    byte[] data = GetFileData();
    file.Write(data, 0, data.Length);
} 
```

此外，垃圾收集器与需要释放的对象交互需要一段时间，有时您可能希望自己执行。对于这两种情况，使用`try-finally`或`using`语句是最佳实践：

```cs
private static void CorrectFileStreamManagementFirstOption()
{
    FileStream file = new FileStream("C:\\file.txt",
        FileMode.CreateNew);
    try
    {
        byte[] data = GetFileData();
        file.Write(data, 0, data.Length);
    }
    finally
    {
        file.Dispose();
    }
}
private static void CorrectFileStreamManagementSecondOption()
{
    using (FileStream file = new FileStream("C:\\file.txt", 
        FileMode.CreateNew))
    {
        byte[] data = GetFileData();
        file.Write(data, 0, data.Length);
    }
}
private static void CorrectFileStreamManagementThirdOption()
{
    using FileStream file = new FileStream("C:\\file.txt", 
        FileMode.CreateNew);
    byte[] data = GetFileData();
    file.Write(data, 0, data.Length);
} 
```

前面的代码准确显示了如何处理垃圾收集器未管理的对象。您同时实现了`try-finally`和`using`。作为软件架构师，您确实需要注意这种代码。缺乏`try-finally`或`using`语句可能会在运行时对软件行为造成巨大损害。值得一提的是，使用代码分析工具（现在与.NET 5 一起分发）将自动提醒您这类问题。

## IDisposable 接口

与在方法中创建的对象不使用`try-finally`/`using`语句进行管理会导致问题类似，未正确实现`IDisposable`接口的类中创建的对象可能会导致应用程序中的内存泄漏。因此，当您有一个处理和创建对象的类时，应该实现可释放模式以确保释放其创建的所有资源：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_17_10.png)

图 17.10：IDisposable 接口实现

```cs
indicating it in your code and right-clicking on the Quick Actions and Refactoring option, as you can see in the preceding screenshot. 
```

插入代码后，您需要按照 TODO 说明执行，以实现正确的模式。

# .NET 5 编码技巧和窍门

.NET 5 实现了一些有助于我们编写更好代码的好功能。其中最有用的之一是**依赖注入**（**DI**），这已经在*第十一章*，*设计模式和.NET 5 实现*中讨论过。有一些很好的理由可以考虑这一点。首先，您不需要担心处理注入的对象，因为您不会是它们的创建者。

此外，DI 使您能够注入`ILogger`，这是一个用于调试异常的有用工具，需要在代码中通过`try-catch`语句进行管理。此外，在 C#中使用.NET 5 进行编程必须遵循任何编程语言的通用最佳实践。以下列表显示了其中一些：

+   **类、方法和变量应具有可理解的名称**：名称应该解释读者需要了解的一切。除非这些声明是公共的，否则不应该需要解释性注释。

+   **方法不能具有高复杂性级别**：应检查圈复杂度，以便方法不具有太多行的代码。

+   **成员必须具有正确的可见性**：作为面向对象的编程语言，C#允许使用不同的可见性关键字进行封装。C# 9.0 正在提供*Init-only setters*，因此您可以创建`init`属性/索引访问器而不是`set`，在对象构造后将这些成员定义为只读。

+   **应避免重复的代码**：在 C#等高级编程语言中没有理由存在重复的代码。

+   **在使用之前应检查对象**：由于可能存在空对象，代码必须进行空类型检查。值得一提的是，自 C# 8 以来，我们有可空引用类型，以避免与可空对象相关的错误。

+   **应使用常量和枚举器**：避免在代码中使用魔术数字和文本的一个好方法是将这些信息转换为常量和枚举器，这通常更容易理解。

+   **应避免使用不安全的代码**：不安全的代码使您能够在 C#中处理指针。除非没有其他实现解决方案的方法，否则应避免使用不安全的代码。

+   **try-catch 语句不能是空的**：`try-catch`语句在`catch`区域没有处理是没有理由的。此外，捕获的异常应尽可能具体，而不仅仅是一个“异常”，以避免吞噬意外的异常。

+   **处理您创建的对象，如果它们是可处置的**：即使对于垃圾收集器将处理已处置对象的对象，也要考虑处理您自己负责创建的对象。

+   **至少应该对公共方法进行注释**：考虑到公共方法是在您的库之外使用的方法，必须对其进行解释以进行正确的外部使用。

+   **switch-case 语句必须有默认处理**：由于`switch-case`语句可能在某些情况下接收到未知的入口变量，因此默认处理将确保在这种情况下代码不会中断。

您可以参考[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-reference-types`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-reference-t)获取有关可空引用类型的更多信息。

作为软件架构师，您可以考虑为开发人员提供代码模式的良好实践，以保持代码风格的一致性。您还可以将此代码模式用作编码检查的检查表，从而提高软件代码质量。

# WWTravelClub - 编写代码的 DOs 和 DON'Ts

作为软件架构师，您必须定义符合您所工作公司需求的代码标准。

在本书的示例项目中（在*第一章*，*了解软件架构的重要性*中了解更多关于 WWTravelClub 项目的信息），情况并无不同。我们决定为其制定标准的方式是描述我们在编写生成的示例时遵循的 DO 和 DON'T 的列表。值得一提的是，这个列表是开始制定标准的好方法，作为软件架构师，您应该与团队中的开发人员讨论这个列表，以便以实际和良好的方式发展它。

此外，这些语句旨在澄清团队成员之间的沟通，并改善您正在开发的软件的性能和可维护性：

+   用英文编写代码

+   遵循 C#编码规范，使用驼峰命名法

+   用易懂的名称编写类、方法和变量

+   注释公共类、方法和属性

+   尽可能使用`using`语句

+   尽可能使用`async`实现

+   不要编写空的`try-catch`语句

+   不要编写循环复杂度得分超过 10 的方法

+   不要在`for/while/do-while/foreach`语句中使用`break`和`continue`

这些 DO 和 DON'T 非常简单，而且比这更好的是，将为您的团队编写的代码产生很好的结果。在*第十九章*，*使用工具编写更好的代码*中，我们将讨论帮助您实施这些规则的工具。

# 总结

在本章中，我们讨论了编写安全代码的一些重要提示。本章介绍了一个用于分析代码指标的工具，以便您可以管理正在开发的软件的复杂性和可维护性。最后，我们提出了一些好的建议，以确保您的软件不会因内存泄漏和异常而崩溃。在现实生活中，软件架构师总是会被要求解决这类问题。

在下一章中，我们将学习一些单元测试技术，单元测试的原则，以及一个专注于 C#测试项目的软件过程模型。

# 问题

1.  我们为什么需要关注可维护性？

1.  循环复杂度是什么？

1.  列出使用版本控制系统的优势。

1.  垃圾收集器是什么？

1.  实现`IDisposable`接口的重要性是什么？

1.  在编码方面，.NET 5 给我们带来了哪些优势？

# 进一步阅读

这些是一些书籍和网站，您可以在本章的主题中找到更多信息：

+   *代码整洁之道：敏捷软件工艺的手册*，作者 Martin, Robert C. Pearson Education, 2012。

+   *嵌入式系统设计艺术*，作者 Jack G. Ganssle。Elsevier, 1999。

+   *重构*，作者 Martin Fowler。Addison-Wesley, 2018。

+   *复杂度测量*，作者 Thomas J. McCabe。IEEE Trans. Software Eng. 2(4): 308-320, 1976 ([`dblp.uni-trier.de/db/journals/tse/tse2.html`](https://dblp.uni-trier.de/db/journals/tse/tse2.html))。

+   [`blogs.msdn.microsoft.com/zainnab/2011/05/25/code-metrics-class-coupling/`](https://blogs.msdn.microsoft.com/zainnab/2011/05/25/code-metrics-class-coupling/)

+   [`docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-values?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-values?view=vs-2019)

+   [`github.com/`](https://github.com/)

+   [`bitbucket.org/`](https://bitbucket.org/)

+   [`azure.microsoft.com/en-us/services/devops/`](https://azure.microsoft.com/en-us/services/devops/)

+   [`guides.github.com/introduction/flow/`](https://guides.github.com/introduction/flow/)

+   [`blogs.msdn.microsoft.com/devops/2018/04/19/release-flow-how-we-do-branching-on-the-vsts-team/`](https://blogs.msdn.microsoft.com/devops/2018/04/19/release-flow-how-we-do-branching-on-the-vsts-team)

+   [`docs.microsoft.com/aspnet/core/fundamentals/logging/`](https://docs.microsoft.com/aspnet/core/fundamentals/logging/)

+   [`docs.microsoft.com/en-us/dotnet/csharp/whats-new/csharp-9`](https://docs.microsoft.com/en-us/dotnet/csharp/whats-new/csharp-9)


# 第十八章：使用单元测试用例和 TDD 测试您的代码

在开发软件时，确保应用程序没有错误并且满足所有要求是至关重要的。这可以通过在开发过程中测试所有模块，或者在整个应用程序已经完全或部分实现时进行测试来完成。

手动执行所有测试并不可行，因为大多数测试必须在应用程序修改时每次执行，并且正如本书中所解释的那样，现代软件正在不断修改以适应快速变化的市场需求。本章讨论了交付可靠软件所需的所有类型的测试，以及如何组织和自动化它们。

更具体地说，本章涵盖以下主题：

+   了解单元测试和集成测试及其用法

+   了解**测试驱动开发**（**TDD**）的基础知识

+   在 Visual Studio 中定义 C#测试项目

+   用例 - 在 DevOps Azure 中自动化单元测试

在本章中，我们将看到哪些类型的测试值得实施，以及什么是单元测试。我们将看到可用的不同类型的项目以及如何在其中编写单元测试。在本章结束时，本书的用例将帮助我们在 Azure DevOps 中执行我们的测试，自动执行我们应用程序的**持续集成/持续交付**（**CI/CD**）周期中的测试。

# 技术要求

本章需要安装 Visual Studio 2019 免费社区版或更高版本，并安装所有数据库工具。还需要一个免费的 Azure 帐户。如果您还没有创建，请参阅*第一章*中的*创建 Azure 帐户*部分。

本章中的所有概念都以基于 WWTravelClub 书用例的实际示例进行了澄清。本章的代码可在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Hands-On-Software-Architecture-with-C-9-and-.NET-5)上找到。

# 了解单元测试和集成测试

延迟应用程序测试直到大部分功能已完全实现必须避免以下原因：

+   如果一个类或模块设计或实现不正确，它可能已经影响了其他模块的实现方式。因此，在这一点上，修复问题可能会有很高的成本。

+   测试所有可能执行路径所需的输入组合随着一起测试的模块或类的数量呈指数增长。因此，例如，如果类方法`A`的执行可以有三条不同的路径，而另一个方法`B`的执行可以有四条路径，那么测试`A`和`B`将需要 3 x 4 个不同的输入。一般来说，如果我们一起测试几个模块，要测试的路径总数是每个模块中要测试的路径数的乘积。相反，如果模块分开测试，所需的输入数量只是测试每个模块所需的路径的总和。

+   如果由*N*个模块组成的聚合的测试失败，那么在*N*个模块中定位错误的来源通常是一项非常耗时的活动。

+   当一起测试*N*个模块时，我们必须重新定义涉及*N*个模块的所有测试，即使*N*个模块中的一个发生了变化。

这些考虑表明，更方便的是分别测试每个模块方法。不幸的是，验证所有方法而不考虑它们的上下文的一系列测试是不完整的，因为一些错误可能是由模块之间的不正确交互引起的。

因此，测试分为两个阶段：

+   **单元测试**：这些测试验证每个模块的所有执行路径是否正常。它们非常完整，通常覆盖所有可能的路径。这是因为与整个应用程序的可能执行路径相比，每个方法或模块的可能执行路径并不多。

+   **集成测试**：这些测试在软件通过所有单元测试后执行。集成测试验证所有模块是否正确交互以获得预期结果。集成测试不需要完整，因为单元测试已经验证了每个模块的所有执行路径是否正常工作。它们需要验证所有交互模式，也就是各种模块可能合作的所有可能方式。

通常，每种交互模式都有多个与之关联的测试：一种是典型的模式激活，另一种是一些极端情况下的激活。例如，如果整个交互模式接收一个数组作为输入，我们将编写一个测试来测试数组的典型大小，一个测试用`null`数组，一个测试用空数组，以及一个测试用非常大的数组。这样，我们可以验证单个模块的设计是否与整个交互模式的需求相匹配。

有了前面的策略，如果我们修改一个单个模块而不改变其公共接口，我们需要修改该模块的单元测试。

如果改变涉及到一些模块的交互方式，那么我们还需要添加新的集成测试或修改现有的集成测试。然而，通常情况下，这并不是一个大问题，因为大多数测试都是单元测试，因此重写所有集成测试的大部分并不需要太大的努力。此外，如果应用程序是根据**单一职责**、**开闭原则**、**里氏替换原则**、**接口隔离原则**或**依赖倒置原则**（**SOLID**）原则设计的，那么在单个代码修改后必须更改的集成测试数量应该很小，因为修改应该只影响直接与修改的方法或类交互的几个类。

## 自动化单元和集成测试

在这一点上，应该清楚地知道单元测试和集成测试都必须在软件的整个生命周期中得到重复使用。这就是为什么值得自动化它们。自动化单元和集成测试可以避免手动测试执行可能出现的错误，并节省时间。几千个自动化测试可以在每次对现代软件的 CI/CD 周期中所需的频繁更改中，在几分钟内验证软件的完整性，从而使得频繁更改成为可能。

随着发现新的错误，会添加新的测试来发现它们，以便它们不会在软件的未来版本中重新出现。这样，自动化测试总是变得更加可靠，并更好地保护软件免受由于新更改而引入的错误。因此，添加新错误的概率（不会立即被发现的错误）大大降低了。

下一节将为我们提供组织和设计自动化单元和集成测试的基础，以及如何在*C#测试项目定义*部分中编写测试的实际细节。

## 编写自动化（单元和集成）测试

测试不是从头开始编写的；所有软件开发平台都有工具，可以帮助我们编写测试并运行它们（或其中一些）。一旦选择的测试被执行，所有工具都会显示报告，并提供调试所有失败测试代码的可能性。

更具体地说，所有单元和集成测试框架都由三个重要部分组成：

+   **定义所有测试的设施**：它们验证实际结果是否与预期结果相符。通常，测试被组织成测试类，每个测试调用要么测试单个应用程序类，要么测试单个类方法。每个测试分为三个阶段：

1.  测试准备：准备测试所需的一般环境。这个阶段只是为测试准备全局环境，比如要注入到类构造函数中的对象或数据库表的模拟；它不准备我们要测试的每个方法的单独输入。通常，相同的准备过程用于多个测试，因此测试准备被分解成专门的模块。

1.  测试执行：使用适当的输入调用要测试的方法，并将其执行的所有结果与预期结果进行比较，使用诸如`Assert.Equal(x, y)`和`Assert.NotNull(x)`之类的结构。

1.  拆卸：清理整个环境，以避免一个测试的执行影响其他测试。这一步是*步骤 1*的相反。

+   模拟设施：集成测试使用涉及对象协作模式的所有（或几乎所有）类，而单元测试则禁止使用其他应用程序类。因此，如果被测试的类 A 使用另一个应用程序类 B 的方法，该方法在其构造函数或方法 M 中被注入，那么为了测试 M，我们必须注入 B 的一个虚假实现。值得指出的是，只有在单元测试期间，才不允许执行一些处理的类使用另一个类，而纯数据类可以。模拟框架包含定义接口和接口方法实现的设施，这些实现返回可以在测试中定义的数据。通常，模拟实现还能够报告所有模拟方法调用的信息。这样的模拟实现不需要定义实际的类文件，而是通过调用诸如`new Mock<IMyInterface>()`之类的方法在线上测试代码中完成。

+   执行和报告工具：这是一个基于可视化配置的工具，开发人员可以用来决定何时启动哪些测试以及何时启动它们。此外，它还显示了测试的最终结果，包括所有成功的测试、所有失败的测试、每个测试的执行时间以及依赖于特定工具和配置方式的其他信息的报告。通常，在开发 IDE（如 Visual Studio）中执行的执行和报告工具还可以让您在每个失败的测试上启动调试会话。

由于只有接口允许完全模拟定义其所有方法，我们应该在类的构造函数和方法中注入接口或纯数据类（不需要模拟）；否则，类将无法进行单元测试。因此，对于我们想要注入到另一个类中的每个协作类，我们必须定义一个相应的接口。

此外，类应该使用在它们的构造函数或方法中注入的实例，而不是其他类的公共静态字段中可用的类实例；否则，在编写测试时可能会忘记隐藏的交互，这可能会使测试的准备步骤变得复杂。

以下部分描述了软件开发中使用的其他类型的测试。

## 编写验收和性能测试

验收测试定义了项目利益相关者和开发团队之间的合同。它们用于验证开发的软件实际上是否与他们达成的协议一致。验收测试不仅验证功能规范，还验证了软件可用性和用户界面的约束。由于它们还有展示软件在实际计算机监视器和显示器上的外观和行为的目的，它们永远不是完全自动的，而主要由操作员遵循的食谱和验证列表组成。

有时，自动测试是为了验证功能规范而开发的，但这些测试通常绕过用户界面，并直接将测试输入注入到用户界面后面的逻辑中。例如，在 ASP.NET Core MVC 应用程序的情况下，整个网站在包含填充了测试数据的所有必要存储的完整环境中运行。输入不是提供给 HTML 页面，而是直接注入到 ASP.NET Core 控制器中。绕过用户界面的测试称为皮下测试。ASP.NET Core 提供了各种工具来执行皮下测试，以及自动化与 HTML 页面交互的工具。

在自动化测试的情况下，通常首选皮下测试，而全面测试是手动执行的原因如下：

+   没有自动测试可以验证用户界面的外观和可用性。

+   自动化实际与用户界面的交互是一项非常耗时的任务。

+   用户界面经常更改以改善其可用性并添加新功能，对单个应用程序屏幕的小改动可能会迫使对该屏幕上的所有测试进行完全重写。

简而言之，用户界面测试非常昂贵，可重用性低，因此很少值得自动化。但是，ASP.NET Core 提供了`Microsoft.AspNetCore.Mvc.Testing` NuGet 包，以在测试环境中运行整个网站。与`AngleSharp` NuGet 包一起使用，可以编写具有可接受的编程工作的自动化全面测试。自动化的 ASP.NET Core 验收测试将在*第二十二章* *功能测试自动化*中详细描述。

性能测试对应用程序施加虚拟负载，以查看其是否能够处理典型的生产负载，发现其负载限制，并定位瓶颈。该应用程序部署在一个与硬件资源相同的实际生产环境的分期环境中。

然后，虚拟请求被创建并应用于系统，并收集响应时间和其他指标。虚拟请求批次应该与实际生产批次具有相同的组成。如果可用，它们可以从实际生产请求日志中生成。

如果响应时间不令人满意，将收集其他指标以发现可能的瓶颈（低内存、慢存储或慢软件模块）。一旦找到，就可以在调试器中分析负责问题的软件组件，以测量典型请求中涉及的各种方法调用的执行时间。

性能测试中的失败可能导致重新定义应用程序所需的硬件，或者优化一些软件模块、类或方法。

Azure 和 Visual Studio 都提供了创建虚拟负载和报告执行指标的工具。但是，它们已被宣布过时，并将被停用，因此我们不会对其进行描述。作为替代方案，有开源和第三方工具可供使用。其中一些列在*进一步阅读*部分。

下一节描述了一种给测试赋予中心作用的软件开发方法论。

# 理解测试驱动开发（TDD）

**测试驱动开发**（**TDD**）是一种软件开发方法论，它赋予单元测试中心作用。根据这种方法论，单元测试是对每个类的规范的正式化，因此必须在编写类的代码之前编写。实际上，覆盖所有代码路径的完整测试唯一地定义了代码行为，因此可以被视为代码的规范。它不是通过某种正式语言定义代码行为的正式规范，而是基于行为示例的规范。

测试软件的理想方式是编写整个软件行为的正式规范，并使用一些完全自动化的工具验证实际生成的软件是否符合这些规范。过去，一些研究工作花费在定义描述代码规范的正式语言上，但用类似语言表达开发人员心中的行为是一项非常困难且容易出错的任务。因此，这些尝试很快被放弃，转而采用基于示例的方法。当时，主要目的是自动生成代码。

如今，自动生成代码已经大幅被放弃，并在小型应用领域中得以存留，例如创建设备驱动程序。在这些领域，将行为形式化为正式语言的工作量值得花费时间，因为这样做可以节省测试难以重现的并行线程行为的时间。

单元测试最初被构想为一种完全独立的编码示例规范的方式，作为一种名为**极限编程**的特定敏捷开发方法的一部分。然而，如今，TDD 独立于极限编程使用，并作为其他敏捷方法的强制规定。

尽管毫无疑问，经过发现数百个错误后细化的单元测试可以作为可靠的代码规范，但开发人员很难设计可以立即用作代码可靠规范的单元测试。事实上，通常情况下，如果随机选择示例，你需要无限或至少大量的示例来明确定义代码的行为。

只有在理解了所有可能的执行路径之后，才能用可接受的数量的示例来定义行为。事实上，在这一点上，只需为每个执行路径选择一个典型示例即可。因此，在完全编写了方法之后为该方法编写单元测试很容易：只需为已存在的代码的每个执行路径选择一个典型实例。然而，以这种方式编写单元测试并不能防止执行路径设计中的错误。可以说，事先编写测试并不能防止某人忘记测试一个值或值的组合-没有人是完美的！然而，它确实迫使您在实施之前明确考虑它们，这就是为什么您不太可能意外地忽略测试用例。

我们可以得出结论，编写单元测试时，开发人员必须以某种方式预测所有执行路径，寻找极端情况，并可能添加比严格需要的更多的示例。然而，开发人员在编写应用程序代码时可能会犯错误，而在设计单元测试时也可能会犯错误，无法预测所有可能的执行路径。

我们已经确定了 TDD 的主要缺点：单元测试本身可能是错误的。也就是说，不仅应用程序代码，而且其相关的 TDD 单元测试可能与开发人员心中的行为不一致。因此，在开始阶段，单元测试不能被视为软件规范，而是软件行为可能错误和不完整的描述。因此，我们对心中的行为有两种描述：应用程序代码本身以及在应用程序代码之前编写的 TDD 单元测试。

TDD 起作用的原因在于在编写测试和编写代码时犯同样错误的概率非常低。因此，每当测试失败时，测试或应用程序代码中都存在错误，反之亦然，如果应用程序代码或测试中存在错误，测试将失败的概率非常高。也就是说，使用 TDD 可以确保大多数错误立即被发现！

使用 TDD 编写类方法或一段代码是由三个阶段组成的循环：

+   红色阶段：在这个阶段，开发人员编写空方法，要么抛出`NotImplementedException`，要么有空的方法体，并为它们设计新的单元测试，这些测试必须失败，因为此时还没有实现它们描述的行为的代码。

+   绿色阶段：在这个阶段，开发人员编写最少的代码或对现有代码进行最少的修改，以通过所有单元测试。

+   **重构阶段**：一旦测试通过，代码将被重构以确保良好的代码质量和最佳实践和模式的应用。特别是在这个阶段，一些代码可以被提取到其他方法或其他类中。在这个阶段，我们可能还会发现需要其他单元测试，因为发现或创建了新的执行路径或新的极端情况。

一旦所有测试通过而没有编写新代码或修改现有代码，循环就会停止。

有时，设计初始单元测试非常困难，因为很难想象代码可能如何工作以及可能采取的执行路径。在这种情况下，您可以通过编写应用程序代码的初始草图来更好地理解要使用的特定算法。在这个初始阶段，我们只需要专注于主要的执行路径，完全忽略极端情况和输入验证。一旦我们清楚了应该工作的算法背后的主要思想，我们就可以进入标准的三阶段 TDD 循环。

在下一节中，我们将列出 Visual Studio 中提供的所有测试项目，并详细描述 xUnit。

# 定义 C#测试项目

Visual Studio 包含三种类型的单元测试框架的项目模板，即 MSTest、xUnit 和 NUnit。一旦启动新项目向导，为了可视化它们中的适用于.NET Core C#应用程序的版本，将**项目类型**设置为**测试**，**语言**设置为**C#**，**平台**设置为**Linux**，因为.NET Core 项目是唯一可以部署在 Linux 上的项目。

以下屏幕截图显示了应该出现的选择：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_01.png)

图 18.1：添加测试项目

所有前述项目都自动包含用于在 Visual Studio 测试用户界面（Visual Studio 测试运行器）中运行所有测试的 NuGet 包。但它们不包含任何用于模拟接口的设施，因此您需要添加`Moq`NuGet 包，其中包含一个流行的模拟框架。

所有测试项目必须包含对要测试的项目的引用。

在接下来的部分中，我们将描述 xUnit，因为它可能是这三个框架中最受欢迎的。然而，这三个框架都非常相似，主要区别在于用于装饰各种测试类和方法的属性的名称以及断言方法的名称。

## 使用 xUnit 测试框架

在 xUnit 中，测试是用`[Fact]`或`[Theory]`属性装饰的方法。测试会被测试运行器自动发现，并在用户界面中列出所有测试，因此用户可以运行所有测试或只运行其中的一部分。

在运行每个测试之前，会创建测试类的一个新实例，因此在类构造函数中包含的*测试准备*代码会在类的每个测试之前执行。如果您还需要*拆卸*代码，测试类必须实现`IDisposable`接口，以便将拆卸代码包含在`IDisposable.Dispose`方法中。

测试代码调用要测试的方法，然后使用`Assert`静态类的方法测试结果，例如`Assert.NotNull(x)`、`Assert.Equal(x, y)`和`Assert.NotEmpty(IEnumerable x)`。还有一些方法可以验证调用是否引发了特定类型的异常，例如：

```cs
 Assert.Throws<MyException>(() => {/* test code */ ...}). 
```

当断言失败时，会抛出异常。如果测试代码或断言抛出未拦截的异常，则测试失败。

以下是定义单个测试的方法示例：

```cs
[Fact]
public void Test1()
{
    var myInstanceToTest = new ClassToTest();
    Assert.Equal(5, myInstanceToTest.MethodToTest(1));
} 
```

当一个方法只定义一个测试时，使用 `[Fact]` 属性，而当同一个方法定义多个测试时，每个测试都在不同的数据元组上使用时，使用 `[Theory]` 属性。数据元组可以以多种方式指定，并作为方法参数注入到测试中。

可以修改上述代码以在多个输入上测试 `MethodToTest`，如下所示：

```cs
[Theory]
[InlineData(1, 5)]
[InlineData(3, 10)]
[InlineData(5, 20)]
public void Test1(int testInput, int testOutput)
{
    var myInstanceToTest = new ClassToTest();
    Assert.Equal(testOutput, 
        myInstanceToTest.MethodToTest(testInput));
} 
```

每个 `InlineData` 属性指定要注入到方法参数中的元组。由于属性参数只能包含简单的常量数据，xUnit 还允许您从实现 `IEnumerable` 的类中获取所有数据元组，如下例所示：

```cs
public class Test1Data: IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[] { 1, 5};
        yield return new object[] { 3, 10 };
        yield return new object[] { 5, 20 };
    }
    IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();

}
...
...
[Theory]
[ClassData(typeof(Test1Data))]
public void Test1(int testInput, int testOutput)
{
    var myInstanceToTest = new ClassToTest();
    Assert.Equal(testOutput, 
        myInstanceToTest.MethodToTest(testInput));
} 
```

提供测试数据的类的类型由 `ClassData` 属性指定。

还可以使用 `MemberData` 属性从返回 `IEnumerable` 的类的静态方法中获取数据，如下例所示：

```cs
[Theory]
[MemberData(nameof(MyStaticClass.Data), 
    MemberType= typeof(MyStaticClass))]
public void Test1(int testInput, int testOutput)
{
    ... 
```

`MemberData` 属性将方法名作为第一个参数传递，并在 `MemberType` 命名参数中指定类类型。如果静态方法是同一个测试类的一部分，则可以省略 `MemberType` 参数。

下一节将展示如何处理一些高级的准备和清理场景。

## 高级测试准备和清理场景

有时，准备代码包含非常耗时的操作，例如打开与数据库的连接，这些操作不需要在每个测试之前重复执行，但可以在同一个类中的所有测试之前执行一次。在 xUnit 中，这种类型的测试准备代码不能包含在测试类构造函数中；因为在每个单独的测试之前都会创建测试类的不同实例，所以必须将其分解到一个称为 fixture 类的单独类中。

如果我们还需要相应的清理代码，fixture 类必须实现 `IDisposable`。在其他测试框架（如 NUnit）中，测试类实例只会创建一次，因此不需要将 fixture 代码分解到其他类中。然而，不会在每个测试之前创建新实例的测试框架（如 NUnit）可能会因为测试方法之间的不必要交互而出现 bug。

以下是一个打开和关闭数据库连接的 xUnit fixture 类示例：

```cs
public class DatabaseFixture : IDisposable
{
    public DatabaseFixture()
    {
        Db = new SqlConnection("MyConnectionString");
    }
    public void Dispose()
    {
        Db.Close()
    }
    public SqlConnection Db { get; private set; }
} 
```

由于 fixture 类的实例在执行与 fixture 相关的所有测试之前只创建一次，并且在测试后立即被销毁，因此当 fixture 类被创建时数据库连接也只会创建一次，并且在 fixture 对象被销毁后立即被销毁。

通过让测试类实现空的 `IClassFixture<T>` 接口，fixture 类与每个测试类相关联，如下所示：

```cs
public class MyTestsClass : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture fixture;
    public MyDatabaseTests(DatabaseFixture fixture)
    {
        this.fixture = fixture;
    }
    ...
    ...
} 
```

为了使 fixture 测试准备中计算的所有数据对测试可用，fixture 类的实例会自动注入到测试类的构造函数中。例如，在我们之前的例子中，我们可以获取数据库连接实例，以便类的所有测试方法都可以使用它。

如果我们想要在测试类的集合中执行一些测试准备代码，而不是单个测试类，我们必须将 fixture 类与表示测试类集合的空类关联起来，如下所示：

```cs
[CollectionDefinition("My Database collection")]
public class DatabaseCollection : ICollectionFixture<DatabaseFixture>
{
    // this class is empty, since it is just a placeholder
} 
```

`CollectionDefinition` 属性声明了集合的名称，`IClassFixture<T>` 接口已被 `ICollectionFixture<T>` 取代。

然后，我们通过将 `Collection` 属性应用到测试类，声明测试类属于先前定义的集合，如下所示：

```cs
[Collection("My Database collection")]
public class MyTestsClass 
{
    DatabaseFixture fixture;
    public MyDatabaseTests(DatabaseFixture fixture)
    {
        this.fixture = fixture;
    }
    ...
    ...
} 
```

`Collection` 属性声明要使用的集合，而测试类构造函数中的 `DataBaseFixture` 参数提供了一个实际的 fixture 类实例，因此它可以在所有类测试中使用。

接下来的部分将展示如何使用`Moq`框架模拟接口。

## 使用 Moq 模拟接口

模拟能力不包括在我们在本节中列出的任何测试框架中，因为它们不包括在 xUnit 中。因此，它们必须通过安装特定的 NuGet 包来提供。`Moq`框架可在`Moq` NuGet 包中获得，是.NET 中最流行的模拟框架。它非常容易使用，并将在本节中简要描述。

一旦我们安装了 NuGet 包，我们需要在测试文件中添加`using Moq`语句。模拟实现很容易定义，如下所示：

```cs
 var myMockDependency = new Mock<IMyInterface>(); 
```

可以使用`Setup/Return`方法对特定输入的特定方法的模拟依赖行为进行定义，如下所示：

```cs
myMockDependency.Setup(x=>x.MyMethod(5)).Returns(10); 
```

我们可以为同一个方法添加多个`Setup/Return`指令。这样，我们可以指定无限数量的输入/输出行为。

我们可以使用通配符来匹配特定类型，而不是特定的输入值，如下所示：

```cs
myMockDependency.Setup(x => x.MyMethod(It.IsAny<int>()))
                  .Returns(10); 
```

配置了模拟依赖之后，我们可以从其`Object`属性中提取模拟的实例，并将其用作实际实现，如下所示：

```cs
var myMockedInstance=myMockDependency.Object;
...
myMockedInstance.MyMethod(10); 
```

然而，模拟的方法通常由测试中的代码调用，所以我们只需要提取模拟的实例并在测试中使用它作为输入。

我们也可以模拟属性和异步方法，如下所示：

```cs
myMockDependency.Setup(x => x.MyProperty)
                  .Returns(42);
...
myMockDependency.Setup(x => x.MyMethodAsync(1))
                    .ReturnsAsync("aasas");
var res=await myMockDependency.Object
    .MyMethodAsync(1); 
```

对于异步方法，`Returns`必须替换为`ReturnsAsync`。

每个模拟的实例都记录其方法和属性的所有调用，因此我们可以在测试中使用这些信息。以下代码显示了一个例子：

```cs
myMockDependency.Verify(x => x.MyMethod(1), Times.AtLeast(2)); 
```

上述语句断言`MyMethod`至少被给定参数调用了两次。还有`Times.Never`和`Times.Once`（断言方法只被调用了一次），以及更多。

到目前为止，Moq 文档总结应该涵盖了你在测试中可能遇到的 99%的需求，但 Moq 还提供了更复杂的选项。*进一步阅读*部分包含了完整文档的链接。

接下来的部分将展示如何实践定义单元测试以及如何在 Visual Studio 和 Azure DevOps 中运行它们，以书中用例的帮助。

# 用例 - 在 DevOps Azure 中自动化单元测试

在本节中，我们将向我们在*第十五章* *介绍 ASP.NET Core MVC*中构建的示例应用程序添加一些单元测试项目。如果你没有它，你可以从与本书相关的 GitHub 存储库的*第十五章* *介绍 ASP.NET Core MVC*部分下载它。

首先，让我们复制解决方案文件夹并将其命名为`PackagesManagementWithTests`。然后，打开解决方案并将其添加到一个名为`PackagesManagementTest`的 xUnit .NET Core C#测试项目中。最后，添加对 ASP.NET Core 项目（`PackagesManagement`）的引用，因为我们将对其进行测试，并添加对`Moq` NuGet 包的最新版本的引用，因为我们需要模拟能力。在这一点上，我们已经准备好编写我们的测试了。

例如，我们将为`ManagePackagesController`控制器的带有`[HttpPost]`装饰的`Edit`方法编写单元测试，如下所示：

```cs
[HttpPost]
public async Task<IActionResult> Edit(
    PackageFullEditViewModel vm,
    [FromServices] ICommandHandler<UpdatePackageCommand> command)
{
    if (ModelState.IsValid)
    {
        await command.HandleAsync(new UpdatePackageCommand(vm));
        return RedirectToAction(
            nameof(ManagePackagesController.Index));
    }
    else
        return View(vm);
} 
```

在编写我们的测试方法之前，让我们将自动包含在测试项目中的测试类重命名为`ManagePackagesControllerTests`。

第一个测试验证了如果`ModelState`中存在错误，那么操作方法将使用相同的模型呈现一个视图，以便用户可以纠正所有错误。让我们删除现有的测试方法，并编写一个空的`DeletePostValidationFailedTest`方法，如下所示：

```cs
[Fact]
public async Task DeletePostValidationFailedTest()
{
} 
```

由于我们要测试的`Edit`方法是`async`的，方法必须是`async`，返回类型必须是`Task`。在这个测试中，我们不需要模拟对象，因为不会使用任何注入的对象。因此，作为测试的准备，我们只需要创建一个控制器实例，并且必须向`ModelState`添加一个错误，如下所示：

```cs
var controller = new ManagePackagesController();
controller.ModelState
    .AddModelError("Name", "fake error"); 
```

然后我们调用该方法，注入`ViewModel`和一个`null`命令处理程序作为它的参数，因为命令处理程序将不会被使用：

```cs
var vm = new PackageFullEditViewModel();
var result = await controller.Edit(vm, null); 
```

在验证阶段，我们验证结果是`ViewResult`，并且它包含在控制器中注入的相同模型：

```cs
var viewResult = Assert.IsType<ViewResult>(result);
Assert.Equal(vm, viewResult.Model); 
```

现在，我们还需要一个测试来验证，如果没有错误，命令处理程序被调用，然后浏览器被重定向到`Index`控制器的操作方法。我们调用`DeletePostSuccessTest`方法：

```cs
[Fact]
public async Task DeletePostSuccessTest()
{
} 
```

这次准备代码必须包括命令处理程序模拟的准备工作，如下所示：

```cs
var controller = new ManagePackagesController();
var commandDependency =
    new Mock<ICommandHandler<UpdatePackageCommand>>();
commandDependency
    .Setup(m => m.HandleAsync(It.IsAny<UpdatePackageCommand>()))
    .Returns(Task.CompletedTask);
var vm = new PackageFullEditViewModel(); 
```

由于处理程序`HandleAsync`方法没有返回`async`值，我们不能使用`ReturnsAsync`，而是必须使用`Returns`方法返回一个完成的`Task`(`Task.Complete`)。要测试的方法被调用时，传入了`ViewModel`和模拟的处理程序：

```cs
var result = await controller.Edit(vm, 
    commandDependency.Object); 
```

在这种情况下，验证代码如下：

```cs
commandDependency.Verify(m => m.HandleAsync(
    It.IsAny<UpdatePackageCommand>()), 
    Times.Once);
var redirectResult=Assert.IsType<RedirectToActionResult>(result);
Assert.Equal(nameof(ManagePackagesController.Index), 
    redirectResult.ActionName);
Assert.Null(redirectResult.ControllerName); 
```

作为第一步，我们验证命令处理程序是否实际被调用了一次。更好的验证还应包括检查它是否被调用，并且传递给操作方法的命令包括`ViewModel`。我们将把它作为一个练习来进行。

然后我们验证操作方法返回`RedirectToActionResult`，并且具有正确的操作方法名称，没有指定控制器名称。

一旦所有测试准备就绪，如果测试窗口没有出现在 Visual Studio 的左侧栏中，我们可以简单地从 Visual Studio 的**测试**菜单中选择**运行所有测试**项目。一旦测试窗口出现，进一步的调用可以从这个窗口内启动。

如果测试失败，我们可以在其代码中添加断点，这样我们就可以通过在测试窗口中右键单击它，然后选择**调试选定的测试**来启动调试会话。

## 连接到 Azure DevOps 存储库

测试在应用程序的 CI/CD 周期中发挥着基础作用，特别是在持续集成中。它们必须至少在每次应用程序存储库的主分支被修改时执行，以验证更改不会引入错误。

以下步骤显示了如何将我们的解决方案连接到 Azure DevOps 存储库，并且我们将定义一个 Azure DevOps 流水线来构建项目并启动其测试。这样，每天在所有开发人员推送他们的更改之后，我们可以启动流水线来验证存储库代码是否编译并通过了所有测试：

1.  作为第一步，我们需要一个免费的 DevOps 订阅。如果你还没有，请点击此页面上的**开始免费**按钮创建一个：[`azure.microsoft.com/en-us/services/devops/`](https://azure.microsoft.com/en-us/services/devops/)。在这里，让我们定义一个组织，但在创建项目之前停下来，因为我们将从 Visual Studio 内部创建项目。

1.  确保你已经用 Azure 账户登录到 Visual Studio（与创建 DevOps 账户时使用的相同）。在这一点上，你可以通过右键单击解决方案并选择**配置到 Azure 的持续交付...**来为你的解决方案创建一个 DevOps 存储库。在出现的窗口中，一个错误消息会告诉你你的代码没有配置存储库：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_02.png)

图 18.2：没有存储库错误消息

1.  点击**立即添加到源代码控制**链接。之后，DevOps 屏幕将出现在 Visual Studio 的**Team Explorer**选项卡中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_03.png)

图 18.3：发布存储库到 DevOps 面板

如*第三章*所示，*使用 Azure DevOps 记录需求*，Team Explorer 正在被 Git Changes 取代，但如果这个自动向导带你到 Team Explorer，就用它来创建你的存储库。然后你可以使用 Git Changes 窗口。

1.  单击“发布 Git 存储库”按钮后，将提示您选择 DevOps 组织和存储库的名称。成功将代码发布到 DevOps 存储库后，DevOps 屏幕应该会发生以下变化：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_04.png)

图 18.4：发布后的 DevOps 按钮

DevOps 屏幕显示了您在线 DevOps 项目的链接。将来，当您打开解决方案时，如果链接没有出现，请单击 DevOps 屏幕的“连接”按钮或“管理连接”链接（以后出现的那个）来选择并连接您的项目。

1.  单击此链接转到在线项目。一旦进入那里，如果单击左侧菜单上的“存储库”项目，您将看到刚刚发布的存储库。

1.  现在，单击“管道”菜单项来创建一个用于构建和测试项目的 DevOps 管道。在出现的窗口中，单击按钮创建新的管道：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_05.png)

图 18.5：管道页面

1.  您将被提示选择存储库的位置：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_06.png)

图 18.6：存储库选择

1.  选择“Azure Repos Git”，然后选择您的存储库。然后会提示您关于项目性质的信息：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_07.png)

图 18.7：管道配置

1.  选择“ASP.NET Core”。将为您自动创建一个用于构建和测试项目的管道。通过将新创建的`.yaml`文件提交到存储库来保存它：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_08.png)

图 18.8：管道属性

1.  可以通过选择“排队”按钮来运行管道，但由于 DevOps 标准管道在存储库的主分支上有一个触发器，每次提交更改或修改管道时都会自动启动。可以通过单击“编辑”按钮来修改管道：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_09.png)

图 18.9：管道代码

1.  一旦进入编辑模式，所有管道步骤都可以通过单击每个步骤上方出现的“设置”链接进行编辑。可以按以下方式添加新的管道步骤：

1.  在新步骤必须添加的地方写“- 任务：”，然后在输入任务名称时接受出现的建议之一。

1.  一旦编写了有效的任务名称，新步骤上方将出现“设置”链接。单击它。

1.  在出现的窗口中插入所需的任务参数，然后保存。

1.  为了使我们的测试工作，我们需要指定定位包含测试的所有程序集的条件。在我们的情况下，由于我们有一个包含测试的唯一的`.dll`文件，只需指定其名称即可。单击`VSTest@2`测试任务的“设置”链接，并用以下内容替换自动建议的“测试文件”字段的内容：

```cs
**\PackagesManagementTest.dll
!**\*TestAdapter.dll
!**\obj\** 
```

1.  然后单击“添加”以修改实际的管道内容。一旦在“保存并运行”对话框中确认了更改，管道就会启动，如果没有错误，测试结果就会被计算出来。可以通过在管道“历史”选项卡中选择特定构建，并单击出现的页面上的“测试”选项卡来分析特定构建期间启动的测试结果。在我们的情况下，应该看到类似以下截图的内容：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_10.png)

图 18.10：测试结果

1.  如果单击管道页面的“分析”选项卡，您将看到与所有构建相关的分析，包括有关测试结果的分析：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_18_11.png)

图 18.11：构建分析

1.  单击“分析”页面的测试区域会得到有关所有管道测试结果的详细报告。

总结一下，我们创建了一个新的 Azure DevOps 存储库，将解决方案发布到新存储库，然后创建了一个构建管道，在每次构建后执行我们的测试。构建管道一旦保存就会执行，并且每当有人提交到主分支时都会执行。

# 摘要

在本章中，我们解释了为什么值得自动化软件测试，然后我们专注于单元测试的重要性。我们还列出了所有类型的测试及其主要特点，主要关注单元测试。我们分析了 TDD 的优势，以及如何在实践中使用它。有了这些知识，您应该能够编写既可靠又易于修改的软件。

最后，我们分析了.NET Core 项目可用的所有测试工具，重点介绍了 xUnit 和 Moq 的描述，并展示了如何在实践中使用它们，无论是在 Visual Studio 还是在 Azure DevOps 中，都是通过本书的用例。

下一章将讨论如何测试和衡量代码的质量。

# 问题

1.  为什么值得自动化单元测试？

1.  TDD 能够立即发现大多数错误的主要原因是什么？

1.  `[Theory]`和`[Fact]`属性在 xUnit 中有什么区别？

1.  在测试断言中使用了哪个 xUnit 静态类？

1.  哪些方法允许定义 Moq 模拟的依赖项？

1.  是否可以使用 Moq 模拟异步方法？如果可以，如何？

# 进一步阅读

尽管本章中包含的 xUnit 文档非常完整，但它并未包括 xUnit 提供的少量配置选项。完整的 xUnit 文档可在[`xunit.net/`](https://xunit.net/)找到。MSTest 和 NUnit 的文档分别可在[`github.com/microsoft/testfx`](https://github.com/microsoft/testfx)和[`github.com/nunit/docs/wiki/NUnit-Documentation`](https://github.com/nunit/docs/wiki/NUnit-Documentation)找到。

Moq 的完整文档可在[`github.com/moq/moq4/wiki/Quickstart`](https://github.com/moq/moq4/wiki/Quickstart)找到。

以下是一些用于 Web 应用程序的性能测试框架的链接：

+   [`jmeter.apache.org/`](https://jmeter.apache.org/)（免费且开源）

+   [`www.neotys.com/neoload/overview`](https://www.neotys.com/neoload/overview)

+   [`www.microfocus.com/en-us/products/loadrunner-load-testing/overview`](https://www.microfocus.com/en-us/products/loadrunner-load-testing/overview)

+   [`www.microfocus.com/en-us/products/silk-performer/overview`](https://www.microfocus.com/en-us/products/silk-performer/overview)
