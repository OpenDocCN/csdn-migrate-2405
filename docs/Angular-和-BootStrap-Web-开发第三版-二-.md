# Angular 和 BootStrap Web 开发第三版（二）

> 原文：[`zh.annas-archive.org/md5/C3E0BC11B26050B30F3DD95AAA2C59BD`](https://zh.annas-archive.org/md5/C3E0BC11B26050B30F3DD95AAA2C59BD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：路由

上一章是一个庞然大物，但它是必要的，因为它需要给你提供两种你可能会使用的技术的速成课程，或者应该考虑在你的网页开发项目中使用的技术（无论你的项目是否利用 Angular）。另外，第三章《Bootstrap - 网格布局和组件》也有助于为本书的其余部分铺平道路。

与之相比，本章要小得多，但它标志着我们进入 Angular 的真正开端。从这一点开始，每一章，甚至第十二章《集成后端数据服务》，其中主要关注在 Node 和 MongoDB 中构建后端服务，都包含 Angular 的内容（具体来说，如何使用 Angular 的 HTTP 客户端以及如何将代码封装在 Angular 服务中）。

关于本章的另一个注意事项是，大多数关于 Angular 的书籍在介绍 Angular 模板和组件之前并不介绍路由，这是可以接受的；但我们不会遵循这种方法。尽管路由和组件模板是密不可分的，这也是大多数书籍在介绍组件之后再讨论路由的原因，但理解组件并不是理解路由的先决条件。

更一般地说，大多数编程书籍都试图提前呈现所有的材料和概念，然后在以后的某个时候回过头来尝试以某种方式实现它们。这种方法的问题之一是，它违反了我们大脑在吸收和内化新信息时的工作方式。通常最好立即以小的增量步骤使用新信息。

本书的重点是尽可能实用，尽快实现，并以最大程度地保留和理解新材料的方式。因此，为了实现这一点，我们将在整本书中一起构建我们的示例应用程序，学习我们需要的主题，而不是在之前。这意味着我们经常会实现尚未完全解释的内容。它们将在实现它们时向您解释，或者在之后立即解释——当您的大脑处于最佳状态，并寻找模式以促进理解时。

所以，不要担心头等跳进去——通常这是最好的方式。我是你的向导，我会一直陪伴你到书的最后。

在本章中，我们将一起学习以下内容：

+   为 Angular 应用程序定义路由是什么

+   使用 CLI 创建应用程序的外壳以及它的前几个组件

+   为我们的应用程序配置路由

+   研究路由重定向、参数化路由和路由守卫

+   完成我们应用程序的路由配置。

+   研究路由策略

有很多内容要涵盖（即使是像这样的小章节），所以让我们开始吧！

# 什么是 Angular 中的路由？

在 Angular 中，路由简单地将请求的 URL 映射到一个组件。这往往会让从另一个具有路由的技术（特别是不是单页面应用程序框架的技术）转向 Angular 的人感到困惑。让我稍微解释一下。

Angular 应用程序只有一个页面（因此，术语单页面应用程序），我们将在创建 Angular 应用程序时看到。Angular 组件有模板，这些模板是用于设计结构和布局的标准 HTML 元素。正如我们将在第六章中看到的 *构建 Angular 组件*，它们也有样式。

正如书的第一章中提到的，Angular 应用程序可以被看作是组件树。这意味着组件可以包含其他组件，并且这种组件的嵌套可以根据应用程序的需要继续进行。

因此，尽管组件有模板（注意：一些 web 框架将 web 页面称为模板），Angular 的路由将 URL 路径映射到组件，而不是 web 页面或模板。当请求的 URL 渲染为组件的模板时（我们马上就会看到这是如何发生的），不仅会渲染该组件的模板，还会渲染所有嵌套组件的模板。由 Angular 路由映射到的顶级组件可能包含其他子组件，这些子组件又可以包含其他子组件，依此类推。这就是组件树的含义。

在大多数情况下，Angular 应用程序中的数据是从父组件流向其直接子组件的。它不会从父组件流向其孙子组件。此外，数据也不会向上流动。这是一个单向流动-从父级到子级。我说“在大多数情况下”，因为有一些技术和库可以改变部分行为-例如，组件可以通过中介相互通信，我们将在本书后面讨论。但是，按设计，没有外部干预，数据是从父级到子级流动的。

随着我们在本书中的进展，您将熟悉所有这些。您现在唯一需要理解的是，要理解路由，URL 被映射到组件而不是页面，因为 Angular 应用程序只有一个页面。Angular 应用程序中唯一的页面是`index.html`页面，位于 app 目录中。在[第六章]中，我们将看到我们的默认组件如何加载到`index.html`页面中。现在，让我们回到路由。

# 使用 CLI 创建应用程序的外壳

这就是一切的开始。我们现在已经到达了使用 CLI 创建应用程序的起点以及我们需要连接到路由配置的第一批组件的点。我们已经学习了如何安装 CLI，甚至一起创建了我们的第一个 Angular 应用程序-尽管我们的待办事项应用程序很小，只是为了让我们入门-在[第一章]中。

如果您还没有安装 CLI，那么现在肯定要安装了。一旦您完成了这个步骤（希望您已经完成了），启动 CLI，让我们开始吧！

首要任务是在您的计算机上创建一个目录，您将在其中放置所有的 Angular 项目。不要为我们的示例应用程序创建一个目录，因为 CLI 会为您完成这项工作。只需在文件系统上创建一个文件夹，并从命令行（如果您的操作系统是 Windows）或终端（如果您的操作系统是 Mac 或 Linux）中导航到该文件夹。为了简洁起见，从现在开始，我将称其为您的终端，文件夹为目录。

接下来，我们将使用 CLI 来创建我们应用程序的骨架（即根目录），以及 CLI 为我们创建的所有必需的 Angular 应用程序所需的文件和子目录。输入以下命令：

```ts
ng new realtycarousel 
```

**注意**：这将需要大约一分钟的时间来完成。

如果你看到最后一行输出为 Project realtycarousel successfully created.，那么现在你应该有一个名为`realtycarousel`的目录，其中包含我们应用程序的所有文件。

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/b2659de5-4388-4f65-80f5-2b0906a67ef4.png)

现在让我们测试一下是否可以运行它。使用`cd`命令导航到你的`realtycarousel`目录：

```ts
cd realtycarousel
```

接下来，使用 CLI 的服务器命令启动我们的 Angular 应用程序：

```ts
ng serve  
```

你应该在终端看到一堆行输出。如果其中一行类似于`*** NG Live Development* Server is listening on localhost:4200, open your browser on http://localhost:4200/ **`，并且最后一行是`webpack: Compiled successfully`，那么你应该打开浏览器并将其指向`http://localhost:4200`。

如果你看到一个带有 Angular 标志的页面，这意味着一切都设置正确了。你现在有一个空的 Angular 应用程序。

你可以按下*Ctrl* + *C*来停止 CLI 的开发服务器。

接下来，让我们添加几个组件，我们将在路由配置中引用它们。同样，现在不要担心组件。我们将在第六章 *构建 Angular 组件* 和 第七章 *模板、指令和管道* 中深入研究它们。

依次运行以下 CLI 命令列表：

```ts
ng g c home
ng g c signup ng g c login
ng g c logout
ng g c account
ng g c listings
ng g c createListing
ng g c editListing
ng g c previewListing
ng g c photos
ng g c uploadPhoto
ng g c editPhoto
ng g c previewPhoto
ng g c pageNotFound
```

第一个命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/07479861-06b6-476d-a513-58f1833149a6.png)

当我们创建所有其他组件时，我们应该看到类似的输出。

我们现在有了我们需要的第一组组件。虽然它们的模板现在是空的，但这已经足够让我们为我们的应用程序配置路由了。

由于我们将在应用程序中使用 Bootstrap 进行一些操作，例如其导航栏和响应式网格，我们需要安装 Bootstrap 以及其依赖项。在第三章中，*Bootstrap - 网格布局和组件*，我们只是在`index.html`页面的头部引用了一些 CDN URL，以便能够使用 Bootstrap。但是，我们现在将以不同的方式安装 Bootstrap - 我们将使用`npm`。

您需要在系统上安装 Node.js 才能使用**node package manager**（**npm**）。

要安装 Bootstrap、jQuery 和 Popper，请在终端中运行以下命令：

```ts
npm install bootstrap@4 jquery popper --save
```

我们已经安装了库，现在是时候在我们的配置文件中包含它们，以便它们在整个应用程序中可用。

打开`angular.json`文件，并在相应的部分中包含样式表和 JavaScript 文件，如下面的代码片段所示：

```ts
"styles": [
    "styles.css",
    "./node_modules/bootstrap/dist/css/bootstrap.min.css"
],
"scripts": [
    "../node_modules/jquery/dist/jquery.min.js",
    "./node_modules/bootstrap/dist/js/bootstrap.min.js"
] 
```

屏幕截图显示了编辑后的`angular.json`文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/5521ee4d-875c-45da-b366-fc395f4e7e01.png)

一切准备就绪！

现在我们已经拥有了我们需要为应用程序设置路由的核心文件。我们还确保安装了 Bootstrap，因为我们将在本章中为我们的应用程序创建导航栏。此外，我们的导航链接将包含 Angular 用于路由的特殊标签，这也是我们此时需要安装 Bootstrap 的另一个原因。

让我们再次使用我们的 IDE（最好使用 Visual Studio Code，但您可以使用您喜欢的任何 IDE）打开我们的项目，这样我们就可以查看项目结构。此外，在下一节“完成我们的路由配置”中，我们将对一些文件进行更改以进行设置，因此您需要一种方便打开和编辑这些文件的方式。

现在在您的 IDE 中打开项目后，导航到`app`目录，该目录位于`src`目录内。作为 Angular 开发人员，我们将在`app`目录中度过绝大部分时间。在`app`目录中，您会找到许多以*app*开头的文件。这些文件组成了我们应用程序中的根组件（即应用程序组件），当我们来到第六章 *构建 Angular 组件*时，我们将会检查这些文件的每个文件的作用，您将会非常熟悉 Angular 组件。您将在`app`目录中看到许多子目录，每个子目录都是我们刚刚创建的组件，比如 about、account、home 等。

请记住，Angular 应用程序的编写语言是 TypeScript，这就是`.ts`文件扩展名的含义。让我们开始为我们的应用程序配置路由。

# 首先要了解的是基本概念

在这一部分，我们将在开始为我们的 Angular 应用程序添加路由之前，快速了解一些基本概念的概述。在基本概念中，我们将学习`Base Href`、`RouterLink`和`RouterLinkActive`，这些是我们在使用 Angular 路由时需要在模板中实现的内容。

# Base Href

为了在应用程序内部组合链接，每个 Angular 应用程序都应该在父级别定义`base href`。

打开由 Angular CLI 生成的应用程序，并查看`index.html`文件。我们将看到基本`href`定义为`/`，这将解析为根或顶级层次结构。

以下截图显示了由 Angular CLI 生成的默认基本`href`配置：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/86a36aa5-3a0b-4b7a-9775-a45df003382d.png)

# RouterLink 和 RouterLinkActive

在第七章中，*模板、指令和管道*，我们将详细了解组件、指令和模板。现在，只需了解，就像 HTML5 中的锚元素和`href`属性一样，Angular 提供了一种绑定链接和 URL 资源的方式：

```ts
<nav>
 <a routerLink="/home" routerLinkActive="active">Home</a>
 <a routerLink="/listings" routerLinkActive="active">Listings</a>
</nav>
```

在上述代码中，我们添加了两个链接。请注意，我们已经在链接中添加了`routerLink`属性，这将帮助我们分别绑定`/home`和`/listings`的值。

还要注意，我们已经添加了`routerLinkActive`属性，并将值分配为`active`。每当用户点击链接时，Angular 路由将知道并使其处于活动状态。有些人称之为魔术！

# 为我们的应用程序配置路由

是时候为我们的应用程序添加 Angular 路由了。

我们有两种实现路由的选项：

+   我们可以使用 Angular CLI 在项目创建期间添加路由

+   或者我们可以手动添加 Angular 路由到我们的应用程序中

首先，让我们探索简单的方法，使用 Angular CLI 添加路由。

Angular CLI 为我们提供了一种简单的方法来为我们的 Angular 应用程序添加路由功能。在生成新项目时，Angular CLI 将提示我们选择是否要为我们的应用程序添加路由。

以下截图显示了在 CLI 中显示添加 Angular 路由选项：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/e1b33a23-33ed-45e9-a4e6-5f78ba72bd9d.png)

当我们选择在我们的应用程序中添加路由选项时，我们使用 Angular CLI 创建文件，导入所需的模块，并创建路由规则集。

现在，让我们手动为我们的项目添加路由。让我们看看如何在我们的应用程序中配置路由。

为了配置我们的路由，我们需要按照以下步骤进行：

1.  打开`app.module.ts`文件

1.  在文件顶部的`import`部分添加以下`import`语句：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
```

`RouterModule`包含路由服务和路由指令。

`Routes`模块定义了路由类型（记住，TypeScript 为 JavaScript 添加了变量类型）。

1.  在`app-routing.module.ts`文件中编写一些路由和规则集：

```ts
const appRoutes: Routes = [
  { path: ‘home’, component: HomeComponent },
  ...
  { path: ‘’, redirectTo: ‘/home’, pathMatch: ‘full’ },
  { path: ‘**’, component: PageNotFoundComponent  }
];
```

这段代码只显示了三个映射：

+   `HomeComponent`的映射

+   重定向的映射

+   通配符或*catch-all*的 URL 请求的映射

第一个映射对象是最简单的情况。URL 路径（即域名后面的部分）映射到一个组件，没有任何参数（注意路由可以被参数化，我们很快会在*参数化路由*部分看到）。这个路由的作用是指示 Angular 在请求的 URL 路径以 home 结尾时呈现`HomeComponent`模板。

第二个映射对象是如何将一个路径重定向到另一个 URL 和路由的示例。这通常被称为路由重定向。在我们的情况下，路径是一个空字符串，这意味着当仅在浏览器位置栏中输入域名时，Angular 的路由机制将重定向请求（即更改 URL 中的路径）到`/home`。由于有一个处理`/home`的映射对象，它将被触发，从而呈现`HomeComponent`模板。这是网站的常见做法——输入域名通常会将用户带到主页或索引网页。在我们的情况下，由于我们正在构建 SPA（这就是 Angular web 应用程序），没有主页，而是一个主页组件，这意味着主页组件的模板被呈现以模拟主页。

第三个映射对象是通配符匹配的一个示例，并且放置在最后一个映射对象。当 Angular 的路由机制解析请求的 URL 时，它会从上到下将其与映射对象进行比较。如果 URL 不匹配任何映射规则集，将触发最后一个映射对象。对于我们的应用程序来说，这意味着如果没有匹配项，将呈现`PageNotFoundComponent`模板。

1.  现在是时候导入我们的`appRoutes`了；这是我们告诉 Angular 我们的路由的方式。`appRoutes`是一个包含我们路由映射的常量，让我们接着创建它：

```ts
imports: [
 BrowserModule,
 RouterModule.forRoot(appRoutes)
]
```

1.  最后，我们需要将`app-routing.module.ts`文件导入到`app.module.ts`中。

`app-routing.module.ts`文件的完整代码清单在本章后面的*完成我们的路由配置*部分中。

我们已经将路由直接添加到`app.module.ts`文件中。将路由配置文件分离出来是一个很好的做法。更好的做法是，在创建项目时始终使用 Angular CLI 直接添加路由。

就是这样；我们已经在我们的项目中实现了路由。在下一节中，我们将详细了解如何添加更多路由，向我们的路由添加参数，并创建子路由。

# 参数化路由

参数化路由是具有变量值作为 URL 路径一部分的路由。例如，一个常见的例子是当我们通过 ID 引用某些内容时，如下所示：

+   `/listing/23`（在我们的房地产网站上显示属性＃23）

+   `/listing/55`（在我们的房地产网站上显示属性＃55）

+   `/listing/721`（在我们的房地产网站上显示属性＃721）

显然，必须配置数百个路由不仅会很繁琐、低效和容易出错，而且这些路由的维护（即删除路由和添加新路由，因为属性列表的库存发生了变化）将会很麻烦。

幸运的是，Angular 允许参数化路由，可以解决这些问题。

看一下以下代码片段中更新的路由：

```ts
const routes: Routes = [
{ path: 'home'},
{ path: 'listings/:id', component: ListingDetailsComponent },
{ path: ‘’, redirectTo: ‘/home’, pathMatch: ‘full’ },
{ path: ‘**’, component: PageNotFoundComponent  } ];
```

仔细看，在前面的路由中，我们添加了一个捕获列表`id`的路由，并且我们还将其映射到`ListingDetailsComponent`组件。

换句话说，我们还可以说我们已经为列表创建了一个通用模板，并且根据运行时传递的动态值，组件将显示相应的数据。

那很容易。如果我们有一个涉及创建子路由的更复杂的场景呢？继续阅读。

# 子路由

到目前为止，我们创建的路由都是非常简单和直接的用例。在复杂的应用程序中，我们将需要使用深度链接，这指的是在许多级别下追踪链接。

让我们看一些例子：

+   `/home/listings`（显示家中的列表）

+   `/listing/55/details`（显示列表＃55 的详细信息）

+   `/listing/721/facilities`（显示列表＃721 的设施）

这就是子路由对我们非常有用的地方。

在以下示例中，我们在 home 路由路径内创建了一个子路由：

```ts
const routes: Routes = [
{ path: 'home',
 component: HomeComponent,
 children: [
 { path: 'listings',
    component: ListingsComponent}
 ]
},
{path: 'listings/:id', component: ListingDetailsComponent },
{path: '', redirectTo: '/home', pathMatch: 'full'}
];
```

在前面的代码中，我们为*home*路径定义了`children`，再次指定了`path`和`component`，这将对应于子路由路径。

好的，很好。这是好东西。

如果我们想在用户访问特定路由之前添加一些验证呢？就像俱乐部外面的保镖一样？那个保镖就叫做路由守卫。

# 路由守卫

与大多数 Web 应用程序一样，有一些资源（即页面/组件模板）是每个人都可以访问的（例如**欢迎页面**、**定价页面**、**关于我们**页面和其他信息页面），还有一些资源只能被授权用户访问（例如仪表板页面和帐户页面）。这就是路由守卫的作用，它是 Angular 防止未经授权用户访问应用程序受保护部分的方式。当有人尝试访问保留给授权用户的 URL 时，他通常会被重定向到应用程序的公共主页。

在传统的 Web 应用程序中，检查和验证是在服务器端代码中实现的，实际上没有选项可以在客户端验证用户是否可以访问页面。但是使用 Angular 路由守卫，我们可以在客户端实现检查，甚至不需要访问后端服务。

以下是我们可以在应用程序中使用的各种类型的守卫，以增强授权安全性的各种类型的守卫：

+   `CanActivate`：帮助检查路由是否可以被激活

+   `CanActivateChild`：帮助检查路由是否可以访问子路由

+   `CanDeactivate`：帮助检查路由是否可以被停用

+   `Resolve`：帮助在激活任何路由之前检索路由数据

+   `CanLoad`：验证用户是否可以激活正在进行懒加载的模块

在我们开始实际操作之前，我想给你快速概述一下 Angular 路由守卫，比如在哪里使用它们，如何使用它们，返回类型是什么，等等。路由守卫总是作为服务注入的（即，我们有`@injectable`并且需要注入它）。守卫总是返回一个布尔值，`true`或`false`。我们可以让我们的路由守卫返回可观察对象或承诺，内部将其解析为布尔值。

我们将继续在上一节中创建的示例上继续工作和扩展。我们将添加一个新组件并将其命名为**CRUD**。作为用户，当您尝试访问`crud`路由时，我们将检查路由返回`true`时。我们将允许用户导航并查看模板；否则，应用程序将抛出错误提示。

让我们直接进入代码，实现路由守卫。就像我们学习如何生成组件或服务一样，我们可以使用`ng`命令生成路由守卫。在终端中运行以下命令：

```ts
ng generate g activateAdmin
```

我们刚刚生成了一个名为`activateAdmin`的新路由守卫。上述命令的输出显示在这里：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/12833ce7-fa3e-456a-824e-e926a9b69796.png)

让我们看看 Angular CLI 生成的文件。在编辑器中打开`activate-admin.guard.ts`文件。看一下文件中生成的默认代码：

```ts
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ActivateAdminGuard implements CanActivate {
  canActivate(
    next: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> 
     | boolean {
    return true;
  }
}
```

前几行只是从 Angular 路由器中导入所需的`CanActivate`、`ActivatedRouteSnapShot`和`RouterStateSnapshot`模块。接下来，我们知道由于路由守卫是可注入的，通过使用`@injectable`

装饰器，我们正在告知 Angular 将其注入到根内。我们正在创建一个名为`ActivatedAdminGuard`的类，其中已经创建了一个名为`canActivate`的方法。请注意，该方法必须返回一个布尔值，要么是`true`要么是`false`。我们已经创建了我们的路由守卫，现在让我们在`app-routing.module.ts`文件中创建一个路由。

看一下`app-routing.module.ts`文件的更新代码：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { CrudComponent } from './crud/crud.component';
import { LoginComponent } from './login/login.component';
import { RegisterComponent } from './register/register.component';
import {ActivateAdminGuard } from './activate-admin.guard';

const routes: Routes = [
    { path: 'login', component: LoginComponent },
    { path: 'register', component: RegisterComponent },
    { path: 'crud', component: CrudComponent, canActivate:[ActivateAdminGuard] }

    ];

@NgModule({
    imports: [RouterModule.forRoot(routes)],
    exports: [RouterModule]
})
export class AppRoutingModule { }
```

请注意，在路由中，我们已经添加了`canActivate`接口，并且对于我们的`crud`路径，当我们尝试启动`crud`路由时，由于`canActivate`方法返回`true`，用户将能够看到组件模板。

现在，继续将值设置为`false`，看看会发生什么。

如果你看到应用程序的路由返回到`base href`，不要感到惊讶。

# 完成我们的路由配置

如前几节所承诺的，我将分享整个`AppModule`的源代码，包括路由配置。以下代码可能看起来很长或令人害怕，但相信我，它实际上非常简单和直接。

在学习本章的过程中，我们生成了许多组件并创建了它们的路由路径。我们只是导入这些组件并用它们的路径更新`appRoutes`。就是这样。我保证。

这是`app.module.ts`文件的完整清单：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AppComponent } from './app.component';
import { HomeComponent } from './home/home.component';
import { SignupComponent } from './signup/signup.component';
import { LoginComponent } from './login/login.component';
import { ListingsComponent } from './listings/listings.component';
import {ListingDetailsComponent } from './listing-deatails/listing-details.component';
import { EditListingComponent } from './edit-listing/edit-listing.component';
import { PreviewListingComponent } from './preview-listing/preview-listing.component';
import { PhotosComponent } from './photos/photos.component';
import { UploadPhotoComponent } from './upload-photo/upload-photo.component';
import { EditPhotoComponent } from './edit-photo/edit-photo.component';
import { PreviewPhotoComponent } from './preview-photo/preview-photo.component';
import { PageNotFoundComponent } from './page-not-found/page-not-found.component';
import { FeaturesComponent } from './features/features.component';
import { PricingComponent } from './pricing/pricing.component';
import { AboutComponent } from './about/about.component';
import { SupportComponent } from './support/support.component';
import { AccountComponent } from './account/account.component';
import { LogoutComponent } from './logout/logout.component';

const appRoutes: Routes = [
 { path: 'home', component: HomeComponent },
 { path: '', redirectTo: '/home', pathMatch: 'full' },
 { path: 'signup', component: SignupComponent },
 { path: 'login', component: LoginComponent },
 { path: 'logout', component: LogoutComponent },
 { path: 'account', component: AccountComponent },
 { path: 'features', component: FeaturesComponent },
 { path: 'pricing', component: PricingComponent },
 { path: 'about', component: AboutComponent },
 { path: 'support', component: SupportComponent },
 { path: 'listings', component: ListingsComponent },
 { path: 'listing/:id', component: ListingDetailsComponent },
 { path: 'listing/edit', component: EditListingComponent },
 { path: 'listing/preview', component: PreviewListingComponent },
 { path: 'photos', component: PhotosComponent },
 { path: 'photo/upload', component: UploadPhotoComponent },
 { path: 'photo/edit', component: EditPhotoComponent },
 { path: 'photo/preview', component: PreviewPhotoComponent },
 { path: '**', component: PageNotFoundComponent }
];
@NgModule({
 declarations: [
 AppComponent,
 HomeComponent,
 SignupComponent,
 LoginComponent,
 ListingsComponent,
 CreateListingComponent,
 EditListingComponent,
 PreviewListingComponent,
 PhotosComponent,
 UploadPhotoComponent,
 EditPhotoComponent,
 PreviewPhotoComponent,
 PageNotFoundComponent,
 FeaturesComponent,
 PricingComponent,
 AboutComponent,
 SupportComponent,
 AccountComponent,
 LogoutComponent
 ],
imports: [
 BrowserModule,
 RouterModule.forRoot(appRoutes)
],
providers: [],
bootstrap: [AppComponent]
})
export class AppModule { }
```

我们刚刚创建了我们的路由，但我们需要通过创建一些链接来更新我们的模板文件，这些链接将具有前面定义的路由的路径。

任何应用程序中最重要的一点就是一个设计良好的菜单，它有助于引导用户并增加良好的用户体验。

使用 Bootstrap `nav`组件，我们将在下一节为我们的应用程序设计一个菜单。

# Bootstrap 导航栏和路由链接指令

在我们结束本章之前，让我们回顾一下并为我们的应用程序创建 Bootstrap 导航栏。如果你还记得上一章，第三章，*Bootstrap - 网格布局和组件*，我曾提到我们将在本章中涵盖 Bootstrap 导航组件。之所以这样做是因为我们将使用路由指令将我们的导航栏与我们的路由绑定在一起，所以最好的地方就是在本章中进行覆盖，因为它属于路由的范畴。

在上一节中，我让你手动在浏览器栏中输入路由路径 URL 以查看路由是否正常工作，本节中，我们将把所有路由 URL 添加到 Bootstrap `navbar`组件中，这样用户就可以直接点击导航，而不是手动输入。

在本章的开头，我们简要提到了`routerLink`和`routerLinkActive`。现在是时候看到它们的实际效果了。

让我们看一下`app.component.html`文件，这是我们应用程序组件的模板。如果你熟悉 ASP.NET 中的主页面的概念，或者 Rails 中的布局页面，那么你可以将应用程序组件模板视为 Angular 应用程序的等价物。这是因为应用程序组件是将形成我们的应用程序的组件树中的顶级组件。我提出主布局的概念的原因是，无论 HTML 被插入到其中，服务器都会通过在布局页面中呈现调用页面来保留它。虽然这在 Angular 中并不是发生的事情，因为它不是服务器端技术，但在概念上是正确的。

我的意思是，无论我们将什么 HTML 插入到应用程序组件的模板中，当其他组件在其中呈现时，它通常仍然可见。这使得应用程序组件模板成为保存我们的导航栏的理想位置，因为无论选择哪个组件模板来由我们的路由规则集呈现给用户请求的给定 URL，它都将始终可见。

这是我们的`app.component.html`文件的代码清单：

```ts
<div>
 <nav class="navbar navbar-expand-lg navbar-light bg-light">
 <a class="navbar-brand" href="/">LISTCARO</a>
 <button class="navbar-toggler" type="button" data-toggle="collapse" 
   data-target="#navbarSupportedContent" 
   aria-controls="navbarSupportedContent" aria-expanded="false" 
   aria-label="Toggle navigation">
 <span class="navbar-toggler-icon"></span>
 </button>
 <div class="collapse navbar-collapse" id="navbarSupportedContent">
 <ul class="navbar-nav mr-auto">
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="/" class="nav-link">Home</a>
 </li>
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="photos" class="nav-link">Photos</a>
 </li> 
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="listings" class="nav-link">Listings</a>
 </li> 
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="features" class="nav-link">Features</a>
 </li>
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="pricing" class="nav-link">Pricing</a>
 </li>
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="about" class="nav-link">About</a>
 </li>
 <li routerLinkActive="active" class="nav-item"> 
 <a routerLink="support" class="nav-link">Support</a>
 </li>
 <li class="nav-item dropdown">
 <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" 
   role="button" data-toggle="dropdown" aria-haspopup="true" 
   aria-expanded="false">
 User name
 </a>
 <div class="dropdown-menu" aria-labelledby="navbarDropdown">
 <a routerLink="account" class="dropdown-item">Account</a>
 <div class="dropdown-divider"></div>
 <a routerLink="logout" class="dropdown-item">Log out</a>
 </div>
 </li>
 </ul>
 <form class="form-inline my-2 my-lg-0">
 <button class="btn btn-outline-success my-2 my-sm-0" type="submit">
   Log In</button>
 <button class="btn btn-outline-success my-2 my-sm-0" type="submit">
   Try Now</button>
 </form>
 </div>
 </nav>
 <br />
 <router-outlet></router-outlet>
</div>
```

深呼吸，让我们分析前面的代码行。我们正在使用 Angular 指令和属性以及 Bootstrap 内置类。所以让我们开始：

+   我们正在创建一个菜单`navbar`元素`<nav>`，在 Bootstrap 中提供，并分配内置的`navbar`类，`navbar-expand-lg navbar-light bg-light`。

+   我们还使用`navbar-brand`类创建了应用程序的标志的元素和占位符。

+   使用`navbar-nav`类，我们正在定义一组链接。

+   我们正在使用锚标签`<a>`添加一些链接，并分配`nav-link`类，这将形成菜单部分的链接。

+   我们还使用`dropdown-menu`类创建了一个下拉菜单，并使用`dropdown-item`向菜单添加项目。

+   对于 Angular 指令和属性，我们正在使用`routerLink`和`routerLinkActive`，如*首先要做的事情-基本概念*部分所述，`routerLink`属性用于绑定链接的 URL 资源。

+   为了突出显示活动链接，我们正在使用`routerLinkActive`属性。您会注意到，对于所有链接，我们已经将属性值分配为`active`。Angular 在运行时将检测到链接被点击并将其突出显示。

太棒了，到目前为止做得很好。我们已经为我们的应用程序实现了一个`nav`菜单。我们离看到我们的应用程序运行只有一步之遥。

# 指定渲染组件模板的位置

我们需要告诉 Angular 我们希望在哪里显示映射组件的组件模板，以符合我们的路由规则集。对于我们的应用程序，我们希望路由器调用的组件在我们的导航栏下呈现。

Angular 有一个指令可以做到这一点，`<router-outlet>`，它在`RouterModule`中定义。

在我们添加用于创建 Bootstrap 导航栏的 HTML 下面，添加以下一行 HTML：

```ts
<router-outlet></router-outlet>
```

这就是告诉 Angular 路由服务调用的组件应该呈现在哪里所需的一切。

# 运行我们的应用程序

既然我们已经完成了为我们的应用程序配置路由，让我们快速试一下。

您还记得如何构建和启动我们的 Angular 应用程序吗？对了！使用 CLI 并像这样发出`serve`命令：

```ts
ng serve
```

确保在执行此操作时，您位于应用程序的根文件夹中。

一次性启动应用程序并在浏览器中打开 localhost 的快捷方式是使用`ng server`命令与`open`选项，就像这样：

```ts
ng serve --open
```

您应该看到的是浏览器地址栏中的 URL 指向`http://localhost:4200/home`，这是 Angular 路由在起作用。`ng serve`命令与`open`选项一起发出了`http://localhost:4200`的 URL，但这触发了路由重定向到`/home`。很酷，对吧？

当我们运行应用程序时，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/98d58a94-73e5-4779-bbe6-a1c4b9200b42.png)

在下一节中，我们将学习一些我们可以在应用程序中实现的路由策略。

# 路由策略

Angular 中有两种客户端路由策略：

+   `HashLocationStrategy`（通常用于客户端目的，如锚标签）

+   `PathLocationStrategy`（这是默认值）

要启用`HashLocationStrategy`，在`app.module.ts`文件中，我们有`RouterModule.forRoot(appRoutes)`，在`forRoot`方法的第二个参数中添加`{ useHash: true }`。应该是这样的：

```ts
RouterModule.forRoot(appRoutes, { useHash: true })
```

使用`HashLocationStrategy`的 URL 在其路径中有一个井号（#）。以下是一个例子：

[`madeuplistofpeople.com/superheros#cloudman`](http://madeuplistofpeople.com/superheros#cloudman)

前面的 URL 表示对服务器的[`madeuplistofpeople.com/superheros`](http://madeuplistofpeople.com/superheros)的 get 请求。

从井号（#）开始的所有内容都不是请求的一部分，因为浏览器只会发送井号左边的所有内容到服务器。

URL 的`#cloudman`部分仅由客户端使用，通常情况下，浏览器会自动滚动到页面上的锚标签（在本例中，滚动到具有`name`属性为`cloudman`的锚标签）。

`HashLocationStrategy`策略的一个用途是使用井号来存储应用程序状态，这对于实现 SPA 的客户端路由非常方便。

例如，考虑以下 URL：

+   [`madeuplistofpeople.com/#/about`](http://madeuplistofpeople.com/#/about)

+   [`madeuplistofpeople.com/#/search`](http://madeuplistofpeople.com/#/search)

+   [`madeuplistofpeople.com/#/contactus`](http://madeuplistofpeople.com/#/contactus)

这种 URL 模式非常适合 SPA，因为发送到服务器的唯一请求是[`madeuplistofpeople.com`](http://madeuplistofpeople.com)，基本上就是一个页面。客户端将以其编程的任何方式处理不同的哈希片段（即从井号到右侧井号的末尾）。

总结一下，`PathLocationStrategy`的一个重要概念是 Angular 利用了一个名为 pushstate 的 HTML5 历史 API。我们可以使用 pushstate API 更改 URL，同时抑制浏览器发送新请求（即更改后的 URL）到服务器的传统默认操作。这使得可以实现客户端路由，而无需使用井号（#）。这就是为什么它是 Angular 中默认的客户端路由策略的原因。

然而，也有一个缺点。如果浏览器刷新，将向服务器发出请求，服务器将用返回的内容重置您的应用程序。换句话说，除非您实施了本地存储策略，否则您的应用程序将丢失其状态。

# 摘要

这是一个相当简短的章节，但我们仍然涵盖了很多内容。在本章中，我们为我们的应用程序创建了骨架，包括创建我们的路由映射到的组件。然后，我们逐步配置了我们应用程序的路由。这包括导入两个必需的模块（即 RoutingModule 和 Routes），编写路由规则集的映射对象形式，并指定路由组件的呈现位置。

我们还将 Bootstrap 安装并集成到我们的应用程序中，并在根组件的模板中创建了我们的 Bootstrap 导航栏。然后，我们看了一下如何让 Angular 意识到已安装的节点包，特别是 Bootstrap 和 jQuery，因为这是我们安装 Bootstrap 及其依赖项（即 jQuery 和 Popper）的方式。

尽管在本章中我们没有使用参数化路由和路由守卫，但我们在这里提到它们，因为我们将在本书的后面部分使用它们——在第十二章 *集成后端数据服务* 和 *第十四章 *高级 Angular 主题*，并且根据本书的精神，在我们需要它们的时候讨论它们，而不是提前，我们将推迟它们的演示直到适当的时间。

最后，我们看了一下 Angular 让我们可以选择的两种客户端路由策略。

在本章中，我们一再提到了“组件”这个词，因为路由将 URL 路径映射到组件。我们甚至使用 CLI 创建了几个组件，但我们没有花时间去理解组件。这完全没关系，因为正如我们所提到的，你不需要理解组件就能理解路由。现在我们已经掌握了路由，我们将在接下来的章节中看看组件。但在我们开始之前，还有另一个简短的章节[第五章]，*Flex-layout – Angular 的响应式布局引擎*，我们将快速介绍一下。这是一个有点奇怪的章节，因为 Flex-layout 是 Bootstrap 响应式网格的替代方案，因此完全不需要构建 Angular 应用程序。然而，我认为这可能会引起你的兴趣。说到这里，让我们把注意力转向 Flex-layout。


# 第五章：Flex-Layout - Angular 的响应式布局引擎

Flex-Layout 是一个基于 TypeScript 的 Angular 布局引擎。它是在 Angular 项目中布置组件的替代方法，而不是使用 Bootstrap 的网格。Flex-Layout 起源于 AngularJS Material，这是一个由谷歌团队创建的 UI 组件框架，由 Thomas Burleson 领导，他是 Angular 大会上的知名演讲者。我还没有机会参加 Angular 大会，比如 ng-conf 或 AngularMix，但我会的。也许我会在那里见到你！全球范围内有许多关于 Angular 的会议，所以你知道你在明智地学习一项需求量很高且将会持续存在的技术。我想我还没有对你说过这个，所以我现在会说。恭喜！恭喜你选择了这样一个伟大的技术来在你的项目中使用，甚至可能作为构建你职业生涯的基石技术。

当我发现可以改变我为客户和自己创建软件的方式的技术时，我忍不住感到兴奋，现在我可以和你分享我的兴奋！所以，请原谅我稍微偏离了手头的材料。

好的，现在让我们来看看这一章我们将要涵盖的内容。

+   为什么这一章被包括在书中

+   我们组件布局的四种可用技术

+   为什么 FlexBox CSS 可能是最佳选择

+   Flex-Layout 是什么，为什么你应该考虑使用它？

+   整合 Flex-Layout

+   Flex-Layout API

+   在使用 Flex-Layout 时的设计策略

+   将我们的线框和组件与本书的章节和主题相关联

+   实现我们选择的线框

# 为什么这一章被包括在书中

这是一个非常简短的章节。事实上，这可能是本书中最短的章节。然而，我想包括它是为了给你提供选择，特别是在拥有替代技术来替代 Bootstrap 方面。在合理范围内，你拥有的选择越多，你就越好。此外，一些开发者喜欢使用 Bootstrap，而另一些则不喜欢。我怀疑这是因为 Bootstrap 的布局系统是一个网格。我不知道有多少开发者喜欢被限制在这样的东西里。不要误会，我并不是在抨击 Bootstrap（Bootstrap 是一项很棒的技术，甚至在本书的标题中都有它的名字！），但 Flex-Layout 确实感觉更加灵活。一些开发者更愿意使用类似 Flex-Layout 这样的东西的另一个原因是它更加友好。例如，你使用专门的元素，而不是使用带有特殊属性的 DIV 元素。有时这被称为采用声明性方法，有时对开发者来说更自然。这可能现在对你来说有些难以理解，但在本章结束时你会明白的。

# 我们组件布局的四种可用技术

作为网页开发者，除非你有幸在团队中有一个网页设计师，否则我们必须花时间来布局页面上的组件。

顺便说一句，让我们为我们未来的讨论确定一些术语。在前几章中，我已经交替使用了*组件*和*页面*这两个术语，但现在是时候更加精确了。你知道，Angular 应用默认是单页应用，因此只有一个页面。我在书中已经多次提到，Angular 应用就像一个组件树，一切都始于根组件。组件是可组合的，也就是说一个组件可以由其他组件组成。这会导致什么结果呢？嗯，我们需要一个网页来渲染我们的根组件，从那一刻起，我们的根组件引入其他组件，这些组件又引入其他组件。最终的结果是，我们的组件递归地渲染自己，以产生我们有多个页面的错觉。当然，我们并没有多个页面。我们只有一个网页，我们的应用程序的架构方式是每个*页面*都有一个主要的包含组件。这意味着当你看到我提到*页面*时，实际上是指该*页面*上的主要组件，而不是*组件*。

回顾一下我们在第四章 *路由*中编写的代码，现在应该开始对你有意义了。具体来说，给定的 URL 映射到一个组件。对于不是单页应用的传统 Web 应用程序，URL 映射到视图或“页面”。好的，让我们把注意力转回到布局策略的考虑和可用选项。

在我们的应用程序中布置组件包括以下四个必要条件：

+   在容器中布置我们的组件（即父组件和子组件）

+   调整我们的组件大小

+   将我们的组件相对放置在一起

+   组件的样式

我并不自诩是样式或 CSS 方面的专家。我几乎无法搭配我穿的衣服。虽然我们在第三章中看到了一些 CSS，*Bootstrap - 网格布局和组件*，在我们的 SASS 速成课程中（在接下来的章节中我们肯定会看到更多的 CSS），但这不是一本关于设计和样式的书。Packt Publishing 出版了一些关于 CSS 的优秀书籍。在本章中，我们只关注在容器中布局我们的组件。为此，我们有四种可以选择的技术：表格、浮动和清除、FlexBox CSS 和 CSS Grid。

是的，当然，Flex-Layout 也是我们的选择，因为我们选择了 Angular（微笑）。然而，我列出的四种布局技术适用于网页开发一般情况——无论是前端框架、库，还是普通的 HTML 和 CSS。正如我们在第三章中所看到的，*Bootstrap - 网格布局和组件*，Bootstrap 是一个建立在 FlexBox CSS 之上的 CSS 框架，因此也适用于网页开发一般情况。

回到我们对布局技术的讨论，让我们对比一下通常可用于网页开发的四种技术，看看是否有一个明显的赢家。从那里，我们将继续本章的细节，看看 Flex-Layout 是什么，以及为什么我们应该使用它。

# 表格

每个网页开发者（2000 年之前出生）都听说过并可能使用过`TABLE`标签。这是从哪里来的？嗯，很久以前，在一个遥远的星球上，一群外星程序员发明了 HTML 表格标签。这些外星人很快厌倦了使用这种布局技术，所以他们禁止了它的使用，并放逐了所有教授表格标签的网页开发书籍。与此同时，在地球上的某个地方，大约在 1994 年，一位对布局问题感到沮丧的网页开发者被一本看起来像技术书籍的东西砸到了头上。它的标记似乎是某种形式的象形文字，对年轻的技术人员来说都是无法理解的，除了那个熟悉的标记语言。第一章的标题只是`<TABLE>`。

开玩笑的是，虽然表格在网页开发的早期阶段非常有帮助，但现在它们是一种古老的布局技术，经常受到指责。以下是一些表格不再是布局页面元素的默认方法的原因：

+   它们往往会在我们的网页和组件中混乱标记

+   它们是维护的噩梦，因为使用表格移动东西非常乏味

+   它们是刚性的——比网格更加刚性，以至于我们有时不得不诉诸于嵌套表格，这当然加剧了前两个要点

然而，尽管存在这些负面因素，使用表格仍然是一个有效的选择，这就是为什么我在这里将其列为主要的四个选项之一。

# 使用浮动和清除进行定位

CSS 有一些非常酷的功能。我最喜欢的是其中一些处理定位的声明。具体来说，我指的是两个 CSS 声明，即浮动和清除。这些声明可以应用于块级元素，如`<div>`，以及内联元素，如`<img>`。块级元素是占据父元素空间的元素，而内联元素乐意分享它们所在父元素的水平空间。

*浮动*元素（如`<div>`）的概念是，它放弃了占据整个水平线的需求。简而言之，它将其空间折叠为仅消耗所需的空间，而不是贪婪地利用水平空间，其他元素现在可以驻留在其旁边，而不是被推到下面。当被浮动的元素不占据整个空间时，旁边浮动的元素在水平空间不足时会换行到下一行。话虽如此，您可以开始看到如何通过使用 CSS 浮动声明来浮动元素来实现一定程度的响应式设计。

*清除*的目的是控制浮动的效果。当您在元素上使用 CSS 声明清除时，基本上是在指示该元素不要浮动到更高的水平空间上，即使有空间可以浮动。请记住，浮动元素意味着元素将占据它可以占据的最高垂直空间，前提是有空间，并且它的相邻元素也已经被浮动（特别是对于希望独占整个水平空间的块级元素）。当没有足够的空间时，它会换行到下一个可用的位置，如果有足够的空间，它会浮动到其他元素的旁边。唯一的例外是，如果您在其样式或类中应用了清除声明，它将始终表现为换行，即使上方有空间。我们对此了解吗？很好。

通过*浮动*和*清除*定位元素确实有效，您可以使用它们创建一些相当复杂的布局。但随着视口尺寸变小，它们的效果可能并不总是您想要看到的。在响应式布局的世界中，尽可能多地控制布局至关重要，而仅限于浮动和清除通常会使布局重新排列成为一项挑战，尤其是在各种视口尺寸下，至少与下面两个选项给予您的精度一样多。另一件需要习惯的事情是，浮动元素需要根据您是将元素向左还是向右浮动来重新排列页面上的元素列表。

我在*浮动*和*清除*上花了更多时间的原因是，有太多开发人员没有花时间让它深入人心。这里的要点是，您可以仅使用这种布局技术走得很远，根据项目的性质和要求，这可能是医生开的处方。当然，关于*浮动*和*清除*的设计策略还有更多要说，但那是另一本书。像往常一样，我建议尝试使用这种布局技术/策略。

# FlexBox CSS

FlexBox CSS 是一个随着 CSS3 而出现的布局技术。这是一个非常强大的东西，这也是为什么其他框架，比如 Bootstrap 和 Flex-Layout，都是建立在它之上的。但 FlexBox CSS 最好的地方在于，它几乎被所有通用的浏览器所理解。使用 FlexBox，我们既可以获得巨大的浏览器覆盖范围，又可以为应用程序提供令人钦佩的布局灵活性。

我不会再多说 FlexBox CSS，因为很可能你不会直接使用它。我可以假设这样做的原因有三个：

+   Bootstrap 是建立在 FlexBox CSS 之上的，你可能更有可能使用 Bootstrap 网格而不是直接使用 FlexBox CSS

+   对于 Flex-Layout 也是一样的，因为它基本上是在 FlexBox CSS 的基础上包装了一个很好的 API，使其更容易使用

# CSS Grid

CSS Grid FlexBox CSS 是一个随着 CSS4 而出现的布局技术。它也是一个非常强大的东西，它使一些事情比使用 FlexBox CSS 更容易，但与此同时，有些事情比使用 FlexBox CSS 更难实现。作为 CSS 世界相对较新的补充，它并没有被广泛整合到通常使用的浏览器中。

# 为什么 FlexBox CSS 可能是最佳选择

在阅读了前面几段的内容后，谁是赢家对你来说应该不会有什么意外。显然是 FlexBox CSS。让我们用一个因素列表来总结选择布局选项时应该考虑的因素：

+   浏览器覆盖范围：作为开发者，我们非常关心我们的 Web 应用的覆盖范围。

+   易用性：我知道这有点牵强，因为 Bootstrap 的网格和 Flex-Layout 都是建立在它之上的，使其更容易使用。但一旦你掌握了 FlexBox CSS，大多数布局要求都可以比较容易地处理。

+   易于维护：这个因素是从前一个要点中得出的。但大多数开发者感到惊讶的是，在典型应用的生命周期中，开发者参与其中的时间有 20%是在构建它，而 80%的时间是在维护它，所以最后一个要点不能过分强调。

同样，我们不认为 Bootstrap 和 Flex-Layout 是布局技术，因为它们是在基础布局技术之上的工具/框架。

# 什么是 Flex-Layout，为什么应该使用它？

我们已经讨论了为什么对于我们来说，布局组件的最佳选项是 FlexBox CSS，但这是关于 Flex-Layout 的一章，所以我现在需要向你介绍它。所以让我们现在做到这一点，然后我将列出一些原因，为什么你应该考虑使用它，而不是直接使用 FlexBox CSS（再次强调，因为 Flex-Layout 是建立在 FlexBox CSS 之上的）。

Flex-Layout 的主页可以在这里找到：[`www.github.com/angular/flex-layout`](https://www.github.com/angular/flex-layout)。

以下是一些关于 Flex-Layout 的要点：

+   它是一个独立的库。

+   它是 Angular 原生的（并且是 TypeScript 实现）。

+   它与 CLI 集成。

+   它有静态 API，用于容器，以及其他静态 API，用于容器子元素。这些 API 具有以下特点：

+   它们是声明性的

+   它们支持数据绑定和变化检测

+   它们是在 HTML 中使用的指令

+   对于我们来说，没有 CSS 需要编写，因为它会动态地为我们注入

与 FlexBox CSS 相比，使用它的一些优势，以及从前面的要点中可以得出以下结论：

+   你不必是 CSS 专家（事实上，正如你很快会看到的，我们甚至不会使用 CSS 样式表）

+   它完美适配 Angular（事实上，它是 Angular 原生的）

+   有 API 可以帮助开发人员更快地开发应用程序

另一个需要知道的好处是，由于 Flex-Layout 是一个独立的（即自包含的）库，它可以与或无需 Angular Material 一起使用。我们将在第九章中查看 Angular Material，那里我们将使用它的一些组件。同样，这些组件可以用作 ng-Bootstrap 的替代品，或与 ng-Bootstrap 一起使用。我们将在第八章中查看 ng-Bootstrap，*使用 NG Bootstrap*。

我在前面的要点列表中提到了 Flex-Layout 具有静态 API。我没有提到的是它还有响应式 API。我们将在接下来的章节中介绍 Flex-Layout 的静态 API，但我把它的响应式 API 留给你阅读（我在该章节的末尾包含了 Flex-Layout 文档的链接）。

然而，我想简要谈一下响应式 API。响应式 API 是为了让您创建自适应的 UX（即，为不同的视口大小创建略有不同的布局）。为了做到这一点，您还需要利用 MediaQueries，而不仅仅是 FlexBox CSS。是的，这是一章关于 Flex-Layout，那么为什么我要提到您需要结合 FlexBox CSS 利用 MediaQueries 呢？我提到这一点是为了指出 Flex-Layout 团队在这个领域（即，响应式 UX，而不仅仅是布局）已经为我们做好了准备。他们通过为静态 API 提供扩展来将 MediaQueries 抽象化，这意味着我们不必手工编写繁琐的规则集——因为他们在静态 API 上创建了扩展，我们可以利用在那里学到的知识并将扩展应用于在我们的 HTML 中创建自适应的 UX。这真的非常聪明！

# 集成 Flex-Layout

Flex-Layout 库作为一个自包含的模块，所以我们只需要在一个地方导入它。与上一章的路由集成更加直接。

现在让我们将 Flex-Layout 添加到我们的项目中。我们需要做的第一件事是安装该库。在您的终端中，导航到我们在第四章中开始创建的`realtycarousel`应用程序的根文件夹，并输入以下内容：

```ts
 npm install --save @angular/flex-layout
```

这将安装该库，这样我们就可以在任何一个 Angular 应用程序中导入它。

注意：如果您的 CLI 输出警告，比如类似于`"``@angular/flex-layout@5.0.0-beta.14`需要`@angular/cdk@⁵.0.0`的对等依赖，但没有安装。您必须自己安装对等依赖"（这就是发生在我身上的事情），只需像其他任何东西一样安装即可，如下所示：

```ts
npm install --save @angular/cdk@⁵.0.0
```

接下来，我们需要将其导入到我们的`RealtyCarousel`应用程序中。为此，我们需要向应用程序的主模块添加一些内容。在 IDE 中打开您的`RealtyCarousel`项目，然后从`src/app`目录中打开`app.module.ts`文件。在文件顶部的其他导入语句中，添加以下导入语句：

```ts
  import { FlexLayoutModule } from '@angular/flex-layout';  
```

（在我们为`RouterModule`添加的`import`语句的下面就可以了。）

我们还需要在`@NgModule`部分的导入数组中包含`FlexLayoutModule`，就像这样：（就在`RouterModule.forRoot(appRoutes)`语句下面，我们为`RouterModule`添加的那样。）

到此为止。我们现在可以利用 Flex-Layout 的功能。几乎我们在 Flex-Layout 中做的任何其他事情都是在我们的 HTML 中完成的。

让我们接下来看一下 Flex-Layout API，这是我们将在页面中利用 Flex-Layout 的方式（即组件模板）。

# Flex-Layout API

与 FlexBox CSS 相比，Flex-Layout 更容易使用的原因是它具有抽象出 CSS 的 API。我们仍然需要 CSS（记住，浏览器只能理解 HTML、JavaScript 和 CSS），但我所说的 CSS 将被抽象化是指当我们的应用程序被转译时，Angular Flex-Layout 会为我们注入 CSS。正如我所提到的，Flex-Layout 甚至没有 CSS 样式表，我们也不需要编写任何 CSS。

以下是 Flex-Layout API 的表格，详细说明了它们的用途，以及一个快速的语法示例：

| **类型** | **API** | **用于** | **示例** |
| --- | --- | --- | --- |
| 静态（对于容器） | `fxLayout` | 定义流的方向（即 flex-direction）。 | `<div fxLayout="row" fxLayout.xs="column">` `</div>` |
| 静态（对于容器） | `fxLayoutAlign` | 定义元素的对齐方式。 | `<div fxLayoutAlign="start stretch">` `</div>` |
| 静态（对于容器） | `fxLayoutWrap` | 定义元素是否应该换行。 | `<div fxLayoutWrap>` `</div>` |
| 静态（对于容器） | `fxLayoutGap` | 设置元素之间的间距。 | `<div fxLayoutGap="15px">` `</div>` |
| 静态（对于子元素） | `fxFlex` | 指定在其容器流布局中调整宿主元素的大小。 | `<div fxFlex="1 2 calc(15em + 20px)">` `</div>` |
| 静态（对于子元素） | `fxFlexOrder` | 定义 FlexBox 项目的顺序。 | `<div fxFlexOrder="2">` `</div>` |
| 静态（对于子元素） | `fxFlexOffset` | 在其容器流布局中偏移 FlexBox 项目。 | `<div fxFlexOffset="20px">` `</div>` |
| 静态（对于子元素） | `fxFlexAlign` | 类似于`fxLayoutAlign`，但适用于特定的 FlexBox 项目（而不是全部）。 | `<div fxFlexAlign="center">` `</div>` |
| 静态（对于子元素） | `fxFlexFill` | 将元素的尺寸最大化到其父容器的尺寸。 | `<div fxFlexFill>` `</div>` |

这些 API 有选项和默认值。例如，`fxLayout` API 默认为行，但也有列，以及行反转和列反转。

另外，在`fxLayout` API 的示例中，`.xs`与 Bootstrap 网格有类似的概念，它提供了一种允许不同视口尺寸的方式。因此，在前面表格中的第一个示例中，常规视口的布局将使元素在行内从左到右流动，而对于小视口，元素将堆叠在单列中。

在前面表格中的示例中，还有一个有趣的地方是在`fxFlex` API 中进行了计算。这有点像我们在第三章的 SASS 快速入门中所看到的，*Bootstrap - 网格布局和组件*，尽管 SASS 是由 Ruby 编译的，而 Flex-Layout 是由 TypeScript 编译的。

我不会在这里列举所有的选项，因为你购买这本书不是为了阅读文档，就像我写这本书不只是为了复制文档一样。当然，我会指引你去查找 Flex-Layout 的文档。你可以在他们的官方网站找到：[`github.com/angular/flex-layout/wiki/API-Documentation`](https://github.com/angular/flex-layout/wiki/API-Documentation)。

幸运的是，Flex-Layout 团队在文档方面做得非常出色。他们的维基还包括了几个实时布局演示，你可以看一看。这是直接链接：[`tburleson-layouts-demos.firebaseapp.com/#/docs`](https://tburleson-layouts-demos.firebaseapp.com/#/docs)。

# 使用 FlexBox 时的设计策略

由于 Flex-Layout 更多地是一种流动的方式，而不是网格，因此通常更容易考虑应用程序的垂直部分并为它们分配自己的容器。这是因为容器内的部分会随着视口尺寸变小而自动向下包裹。容器内的元素应该被视为属于一起。与 Bootstrap 等网格系统相比，思维方式是不同的；网格中的单元格标记了元素的物理边界。单元格内的元素不会自动换行，因为在设计/布局时，您会将元素插入特定的单元格中。另一种概念化网格和 FlexBox 之间的差异的方法是将网格视为二维的（即行和列 - 就像电子表格一样），将 FlexBox 视为一维的（即它要么水平流动，要么垂直流动）。

一旦您有了垂直容器的想法，您就可以考虑从左到右流动的子容器，然后随着视口尺寸变小，子容器向下包裹 - 当它向下包裹时，所有具有该子容器的元素都会一起移动。请记住，当我提到子容器时，我指的是 FlexBox 容器可以嵌套 - 这就是为什么开发人员可以控制布局的大部分原因。在布局页面时，将流程视为“从外到内”。这意味着您应该将页面分成大的垂直部分 - 例如标题、主体和页脚 - 然后深入到每个部分中添加子容器，这些子容器将从左到右流动。

很难用言语描述“流动”，因此像往常一样，最好的方法是尝试使用您的容器和元素，并研究随着视口尺寸调整它们的流动行为。本章包括三个组件模板（即*页面）的代码清单，以及它们的线框图。您将看到我如何为这些组件模板设计布局。在此过程中，我还会告诉您我为什么做出了一些决定。

# 将我们的组件与本书的章节和主题相关联

到目前为止，我们还没有讨论我们将在何时何地实施我们的组件。部分原因是直到第四章 *路由*，我们甚至都没有开始编写任何 Angular 代码，唯一的例外是我们在第一章 *快速入门*中的待办事项列表迷你应用。然而，现在我们已经开始编写 Angular 代码，现在是时候做了。

开始讨论的一个好地方是选择我们将使用 Flex-Layout 布局的组件模板。由于这本书更多地关注 Bootstrap 而不是 Flex-Layout，我们将使用 Bootstrap 的网格来布局我们应用程序中其余的组件模板，这占了大部分。

我们要做的第一件事是列出我们的线框图，作为参考，它们代表我们应用的*页面*（即组件模板），我们将选择其中三个，在接下来的部分*实现我们选择的线框图*中实现它们。然后，我们将看一下接下来的表格，它将向您展示我们将实现哪些组件模板，以及哪些章节，具体来说，我们将把它们与哪些主题配对。

以下是我们从第一章 *快速入门*中的 13 个线框图的列表：

+   首页

+   注册

+   登录

+   编辑个人资料（不在书中涵盖范围内）

+   房产列表（不在书中涵盖范围内）

+   创建列表

+   编辑列表

+   预览列表

+   房产详情（不在书中涵盖范围内）

+   照片列表

+   上传照片/创建卡片

+   编辑照片（不在书中涵盖范围内）

+   预览照片

以下是我们将在本书中一起实现的线框图的表格，以及它们关联的章节和主题的列表。您可以将其用作在概念上将我们的应用程序组合在一起的路线图，也就是说，从高层次上，您将知道我们将在哪一章中实现应用程序中组件模板的各个部分：

| **线框图/组件模板** | **关联章节** | **关联主题** |
| --- | --- | --- |
| 首页 | 3 | Bootstrap 网格 |
| 注册 | 3, 8, 10 | 模态对话框，ng-Bootstrap（输入框），表单 |
| 登录 | 14 | 认证 |
| 创建列表 | 5, 14 | Flex-Layout, 自定义验证 |
| 编辑列表 | 5, 10 | Flex-Layout, 表单 |
| 预览列表 | 5, 6, 9 | Flex-Layout, 组件，Angular Material（芯片） |
| 照片列表 | 6, 7 | 组件，模板 |
| 上传照片/创建照片卡 | 10 | 表单 |
| 预览照片 | 6, 9 | 组件，Angular Material（卡片） |

上表显示了我们将在我们的线框（即组件模板）中实施的主题。例如，通过查看从顶部开始的第四行，我们可以看到当我们实施我们的创建列表线框（即我们的`CreateListingComponent`）时，我们将使用本章的 Flex-Layout，以及来自第十四章 *高级 Angular 主题*的自定义验证。

请记住，每个线框都需要组件——尽管在相关章节列中没有列出第六章 *构建 Angular 组件*，以及相关主题列中的组件。我之所以对一些线框这样做，比如照片列表和预览照片，是因为我们将会更多地讨论组件，而不是比如注册或编辑列表线框。此外，某些线框将使我们更加关注其他主题。例如，您可以看到对于上传照片线框，我们将更多地关注表单，来自第十章 *使用表单*。

由于我们不会跳来跳去，这意味着在我们阅读本书时，我们将会多次回顾我们的大部分页面（即组件模板），两次、三次，甚至四次。

# 实施我们选择的线框

我在本章中选择要与您实施的三个线框（即组件模板）如下：

+   创建列表（包括因为视图中有许多部分和元素）

+   编辑列表（出于与创建列表相同的原因而包括）

+   预览列表（包括因为视图中有非常少的元素）

在上述线框的列表中，您可能已经注意到有三个线框被标记为*不在书中涵盖范围内*。以下是线框排除列表，以及排除原因：

+   **编辑个人资料**：这被排除在外，因为它只是另一个编辑表单（与编辑列表屏幕非常相似）

+   **房产列表**：这被排除在外，因为它只是另一个列表屏幕（很像照片列表屏幕）

+   **房产详情**：这被排除在外，因为从 Angular 的角度来看，这是一个无趣的静态屏幕

+   **编辑照片**：这个被排除了，因为这只是另一个编辑表单

但不要担心。我们将在剩下的页面中一起构建的应用程序的所有代码，包括书中不会实现的四个线框的代码，以及非基于 UI 的代码（例如 第十二章 中的基于 Python 的 API，*集成后端数据服务*，等等），都可以通过下载获得。我已经为你准备好了。

最后一个值得注意的点，然后我们将继续进行一些 Flex-Layout 编码。你可以看出我们的应用程序将需要一些线框被多次重新访问，以便我们可以完成它——也就是说，我们将分阶段构建我们的应用程序，看起来像是一种混乱的来回方式。这不是因为作者疯了——正如他的一些朋友喜欢给你讲述一些强有力的案例，证明恰恰相反——而是出于设计。记住，本书的理念是最大限度地提高你对材料的吸收效果，这样你就可以尽快成为 Angular 大师。在尽可能的范围内，我们将立即实施我们所涵盖的材料，以便它立即有意义，并且牢固。这就是目标，也是为什么我想包括前面的表格（即，将线框与章节和主题相关联）。

我的疯狂通常都是有条不紊的方法（眨眼）。现在让我们把注意力转向本章的三个线框的实现。

# 创建列表线框

在本节中，我们将汇集所有的知识和理解，学习为创建列表页面创建我们的应用程序页面。看一下下面的线框，我们将使用 Flex-Layout 将其转换为代码：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/952c07b6-0b5c-467b-a454-d51e1219ad9e.png)

另一个线框显示，我们将需要一个标题部分和一个两列布局来容纳表单和输入元素。

我们将首先在我们的应用程序中创建一个新组件，并将其命名为“创建列表”。在组件模板文件中，让我们向模板添加以下示例代码：

```ts
<h1>Create Listing</h1> <div  fxLayout="row"  fxLayoutAlign="space-between">
 Logo Here  </div> <div  class="bounds">
 <div  class="content"  fxLayout="row"  class="menu">
 <div  fxFlexOrder="1">Manage Listings</div>
 <div  fxFlexOrder="2">Manage Photos</div>
 <div  fxFlexOrder="3">Manage eCard</div>
 <div  fxFlexOrder="4">Business Opportunity</div>
 </div>
 <div  class="content"  fxLayout="row"  fxLayout.xs="column"  
            fxFlexFill  >
 <div  fxFlex="60"  class="sec1"  fxFlex.xs="55">  
        <form  action="/action_page.php">

 <label  for="lprice">Listing Price</label>
 <input  type="text"  id="lprice"  name="lprice"                 placeholder="Listing price">

 <label  for="country">Property Type</label>
 <select  id="country"  name="country">
 <option  value="australia">USA</option>  <option  value="canada">UK</option>
 <option  value="usa">UAE</option>
 </select>

 <label  for="laddress">Street Address</label>
  <input  type="text"  id="laddress"  name="laddress"              placeholder="Street Address">  <label  for="city">City</label>
  <input  type="text"  id="city"  name="city"  placeholder="City">  <label  for="state">State/Province</label>
 <select  id="state"  name="state">
 <option  value="New York">Australia</option>
 <option  value="New Jersey">Canada</option>
 <option  value="Texas">USA</option>
 </select>         <label  for="pcode">Postal Code</label>
 <input  type="text"  id="pcode"  name="pcode"              placeholder="postal code">

 <label  for="sfoot">Square Foot</label>
 <input  type="text"  id="sfoot"  name="sfoot"              placeholder="Square Foot">   <label  for="bedrooms"># Bedrooms</label>
 <input  type="text"  id="bedrooms"  name="bedrooms"              placeholder="Bedrooms">
  <label  for="bathrooms"># Bathrooms</label>
 <input  type="text"  id="bathrooms"  name="bathrooms"              placeholder="bathrooms">  <input  type="submit"  value="Submit">
 </form>
  </div>
  <div  fxFlex="40"  class="sec2"  >  <label  for="ldescription">Listing Description</label>
 <textarea  id="ldescription"  name="ldescription"              placeholder="Listing price"></textarea>
 </div>  </div>  </div>
```

在上面的代码中，我们使用`fxLayout`创建了一行，为我们的标志创建了一个占位符。接下来，我们创建了菜单链接，并使用`fxFlexOrder`对菜单链接进行排序。现在，我们需要创建一个两列布局，所以我们现在在`fxLayout`行内创建了两个子元素，每个`fxFlex`分别为 60 和 40。在这两列中，我们将放置我们的表单输入元素，以创建表单，如线框所示。运行应用程序，我们应该看到输出，如下面的截图所示：

现在，是时候进行一些代码操作了。我们将在我们的 Angular 项目中创建一个名为 edit-listing 的新组件，并在组件模板文件中重用相同的代码，以快速准备好**编辑列表**页面：

我们已经准备好了**创建列表**页面的布局。如果你仔细看，我们的标签并不完全在输入字段旁边。需要更新什么？没错，我们需要在主列内创建一个子列。通过作业来尝试一下。现在，同样的，我们可以轻松实现我们的编辑列表页面。

# 编辑列表线框

在上一节中，我们创建了我们的**创建列表**页面。在本节中，我们将学习为我们的编辑列表页面实现页面布局。看一下我们将要实现的示例。它不是看起来和**创建列表**页面完全一样吗？没错。

**创建**和**编辑列表**页面的布局大部分都是相同的，除了在启动**编辑**页面时加载数据，而在**创建**屏幕上，最初不会加载任何数据：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/0e242f70-fe76-4216-b713-a02a8102963b.png)

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/5ee464c0-2a23-4602-b2aa-8855b27e4577.png)

```ts
<h1>Edit Listing</h1>

<div fxLayout="row" fxLayoutAlign="space-between">
    Logo Here
  </div>

  <div class="bounds">

      <div class="content" 
         fxLayout="row" class="menu">

            <div fxFlexOrder="1">Manage Listings</div>
            <div fxFlexOrder="2">Manage Photos</div>
            <div fxFlexOrder="3">Manage eCard</div>
            <div fxFlexOrder="4">Business Opportunity</div>

      </div>

    <div class="content" 
         fxLayout="row"
         fxLayout.xs="column" 
         fxFlexFill >

        <div fxFlex="60" class="sec1" fxFlex.xs="55">

            <form action="/action_page.php">

              <label for="lprice">Listing Price</label>
              <input type="text" id="lprice" name="lprice" 
                   placeholder="Listing price">

              <label for="country">Property Type</label>
              <select id="country" name="country">
                <option value="australia">USA</option>
                <option value="canada">UK</option>
                <option value="usa">UAE</option>
              </select>

              <label for="laddress">Street Address</label>
              <input type="text" id="laddress" name="laddress" 
                    placeholder="Street Address">

              <label for="city">City</label>
              <input type="text" id="city" name="city" 
                    placeholder="City">

              <label for="state">State/Province</label>
              <select id="state" name="state">
                <option value="New York">Australia</option>
                <option value="New Jersey">Canada</option>
                <option value="Texas">USA</option>
              </select>

              <label for="pcode">Postal Code</label>
              <input type="text" id="pcode" name="pcode" 
                   placeholder="postal code">

              <label for="sfoot">Square Foot</label>
              <input type="text" id="sfoot" name="sfoot" 
                   placeholder="Square Foot">

              <label for="bedrooms"># Bedrooms</label>
              <input type="text" id="bedrooms" name="bedrooms" 
                    placeholder="Bedrooms">

              <label for="bathrooms"># Bathrooms</label>
              <input type="text" id="bathrooms" name="bathrooms" 
                     placeholder="bathrooms">

              <input type="submit" value="Submit">
            </form>
        </div>
        <div fxFlex="40" class="sec2" >

            <label for="ldescription">Listing Description</label>
            <textarea id="ldescription" name="ldescription" 
                 placeholder="Listing price"></textarea>

        </div>

    </div>
```

在上面的代码中，我们创建了两行，一行用于标题部分，另一行用于内容行。在内容行内，我们使用`fxRow`创建了两个子列，它们将用表单输入字段元素填充。输出将与创建列表页面完全相同。

# 总结

本章提供了对令人兴奋的技术的快速介绍。当然，可以专门撰写一本专门介绍 FlexBox CSS 和 Flex-Layout 的小书，所以仅仅在几页中介绍并不能充分展现它应有的价值。如果有一个行业变化迅速，那就是我们的行业，因此应该提到替代技术 - 如果技术足够令人兴奋，甚至可能获得自己的章节 - 无论是哪本技术书籍和哪些技术。这正是 Flex-Layout 和这本书的情况。我希望向你深入介绍 Flex-Layout。

我们从快速回顾四种布局技术的选项开始，解释了为什么 FlexBox CSS 是其中最佳选择。然后我向你介绍了 Flex-Layout，并提出了一些令人信服的理由，说明为什么你应该考虑使用它而不是 FlexBox。接下来，我们看到了如何将 Flex-Layout 集成到我们的 Angular 项目中，并查看了一些其 API。最后，我们回到了我们的线框图（即组件），并将它们与本书中的章节相关联，然后实现了与本章相关的组件。

我希望你喜欢这一章，并且会尽量在你的网页开发项目中尝试使用 Flex-Layout。我预测许多 Angular 开发者将选择 Flex-Layout 作为布局组件的首选工具。对于我的下一个项目，我已经倾向于使用 Flex-Layout 而不是 Bootstrap 的网格来设计所有组件模板。

在下一章中，我们将学习任何 Angular 应用程序的构建块 - 组件。我们将深入学习并使用 Angular 组件创建一些很酷的东西。祝阅读愉快。


# 第六章：构建 Angular 组件

由于整个 Angular 由几个相互关联的部分组成，几乎不可能选择 Angular 的某一部分比其他部分更重要。删除其中任何一个部分都会使整个系统受损，甚至可能变得无用。话虽如此，如果我必须选择一个真正重要的部分，我会选择组件。组件有几个非常酷的特点，比如当我们构建组件时，我们基本上也在扩展 HTML，因为我们正在创建自定义 HTML 标签。组件是 TypeScript 类，正如我们稍后在本章中将看到的那样，我们将代码链接到自定义 HTML 标签的方式是通过`@Component`注释。我也会在本章后面解释注释是什么。

在此之后使用的术语简要说明：我使用“部分”一词而不是“组件”一词，以避免混淆，因为“组件”一词是一个多义词-在不同的上下文中有不同的含义。此外，当谈论视图（即屏幕）时，我从经典的 Web 应用程序角度使用“页面”一词，而不是字面意义上的意思。

Angular 应用程序包含一个根组件。但是，在讨论应用程序的屏幕或视图时，有必要提及其他充当该视图的根组件的组件。例如，注册屏幕有一个根组件。

以下是我们将一起涵盖的主题的项目列表：

+   一个 Angular 应用程序作为组件树

+   `@Component`注释

+   `@Component`注释的属性

+   内容投影

+   生命周期钩子

+   组件接口

+   需要实现与本章相关的三个线框的组件

# Angular 应用程序架构-组件树

Angular 应用程序基本上是一个组件树。正如我们在之前的章节中学到的，Angular 是一个单页面应用程序框架，因此有一个单页面来展示其组件树。我们已经看到 Angular 有一个顶层组件，称为根组件，根据我们希望应用程序对用户操作做出的响应，我们让根组件加载其他组件。这些其他组件（暂时称它们为*次级根组件*）反过来递归地渲染其他组件。我们在第四章中设置路由的方式是将 URL 映射到我们的*次级根组件*，每个*页面*一个组件，当用户点击导航（即菜单）链接时，它们就会显示出来。

所有这些都是可能的原因是组件是可组合的。这意味着我们的组件由其他组件组成，因此是嵌套的。我们可以在任意深的组件层次结构中嵌套我们的组件，因此在本节的开头就有了这样的陈述，*Angular 应用程序基本上是一个组件树*。

Angular 框架会递归地加载和渲染我们的组件。

# 设计 Angular 应用程序

就像大多数工程项目一样，软件项目也需要有一个设计和架构应用程序的过程。开始的典型方式是将你正在构建的东西分解成独立的工作块。在 Angular 的术语中，这意味着我们需要将我们的应用程序分解成独立的组件，每个组件负责某些事情，比如显示计算结果或接受用户输入。

一旦我们有了需要使用的组件列表（无论是第三方组件还是自定义组件），我们需要把它们当作黑匣子——或数学函数。让我解释一下我的意思。

当我说我们需要把组件当作黑匣子对待时，我是在建议我们不应该在这个阶段（即我们只是列举它们时）让我们的思绪被它们的实现所占据。我们将在本章稍后关注构建我们的组件，但现在，把它们当作黑匣子就足够了。

当我说我们需要把组件当作数学函数来对待时，我只是建议我们考虑输出会是什么，以及函数（也就是我们的组件）需要什么输入。组件的输入和输出构成了它们的公共接口。我们稍后会更仔细地研究组件接口。

# 将你的组件分解为子组件

一个应用程序中的组件数量，甚至每个页面中的组件数量，都各不相同。它可以从几个到几百甚至更多。然而，对于将组件（比如作为特定页面的顶级组件的子组件）分解为子组件，有一个很好的经验法则。如果你记住了组件的可重用性，当你将组件分解为子组件时，你只需要问自己这个问题：“这个组件有两个或更多部分可以在其他地方重用吗？”如果答案是肯定的，你可能会受益于进一步分解。如果答案是否定的，那么你就完成了，不需要再进一步分解组件。

让我们考虑一个简单的例子，只是为了让这个问题不那么抽象。假设你在页面上有一个商品清单，每个商品占据一行，商品就是一个组件。我们还假设每个商品都有一个缩略图，用于显示该商品。如果缩略图可以在其他地方使用，比如在结账页面或商品详细页面，那么这个缩略图应该是它自己的组件，是商品组件的子组件。

从商品清单示例中放大一点，从页面视图开始，你可以采取这种方法来帮助你在规划组件时开始：

+   你的页面页眉也是一个组件

+   你可能在页面右侧有一个快速链接部分，这也将是另一个组件

+   你有你的主要内容部分，占据了大部分屏幕空间，这也将是一个组件

+   你的页面页脚也是一个组件

从前面的组件中，所有这些组件都可能是可重用的，除了主要内容部分。您可能希望您的页面标题和页面页脚出现在应用程序中的每个页面上，并且您可能希望在各个页面上重新显示快速链接部分。出于这些原因，这些组件可能已经很好了。不需要进一步的拆分。您需要拆分主要内容组件的原因是它不可重用，因为您不太可能拥有相同页面的两个副本！

# 组件责任

被架构化的 Angular 应用程序将具有不仅可重用而且有明确定义边界的组件。也就是说，它们具有关注点分离。每个组件只做一件事，并且做得很好。这些组件应该相互抽象，它们不应该了解彼此的细节（即实现）。它们应该了解彼此的唯一事情是如何与彼此通信。这是通过它们的公共接口实现的，我们很快会看到这一点。

目前，您需要知道的是，当您计划应用程序的组件时，您应该列出它们的责任。也就是说，写下它们将要做什么。敏锐的读者可能会看到用例图和组件责任列表之间的联系，因为组件是用户将如何与应用程序交互的方式。

# 注解

注解是 TypeScript 的一个新特性。它们是以`@`符号为前缀的符号，我们将其添加到我们的代码中（即用于装饰我们的类）。注解可以出现在我们的类声明顶部，或者在我们的函数顶部，甚至在我们的类属性顶部。一般来说，注解的作用是在它们附加的地方（即我们的类、函数或属性）注入样板代码。虽然我们不需要注解，因为我们可以选择自己编写样板代码，但我们最好利用它们，因为样板代码不应该一遍又一遍地编写。此外，通过使用注解而不是手写样板代码，不仅可以消除单调乏味，而且我们不必处理容易出错的代码。我们将在本书的各个章节中看到更多的注解，但让我们专注于本章的`@Component`和`@NgModule`装饰器。

# @Component

虽然注解可以出现在我们的类声明顶部，或者在我们的函数顶部，甚至在我们的类属性顶部，但`@Component`注解将始终出现在我们组件类声明的顶部。

为了使`@Component`注解对我们可用，我们必须像这样导入它：

```ts
import { Component } from '@angular/core';
```

让我们仔细看一下那行代码。这是 JavaScript，具体来说是 ES6。如果你还记得第二章中的*ECMAScript 和 TypeScript 速成课程*，这个语句的大括号部分是 ES6 中称为*解构*的新构造。此外，没有明确的路径指向`@angular/core`模块。我们让 CLI 和 TypeScript 编译器来找出模块在哪里，以及如何加载和使其在我们的类中可用。

# @Component 装饰器的属性

`@Component`装饰器为配置我们的组件提供了许多属性。让我们来看看它们。

# 选择器

`selector`是`@Component`注解的一个属性，它的值（类型为字符串）是为我们的自定义 HTML 标签命名的。我喜欢汽车，所以这里有一个`car`组件的示例代码，显示了它的注解、选择器和类名：

```ts
@Component({
 selector: 'car'
})
class CarComponent {
}
```

当 Angular 看到我们的自定义 HTML 标签`<car></car>`时，它会创建我们的`CarComponent`的一个实例，并将我们的自定义标签替换为浏览器实际理解的一些 HTML。好的，但是在我们的组件类中，我们在哪里添加东西，使我们的组件不再只是一个幽灵般的光环？下一节就是答案（即`template`属性）。

# 模板和模板 URL

我们可怜的小`car`组件目前还没有可见的主体。这是因为 Angular 需要知道在渲染我们的`car`组件时要添加什么浏览器友好的 HTML，而我们还没有为 Angular 提供这个。提供的方法是使用`template`属性（类型为字符串）来保存 Angular 在创建`CarComponent`类的实例后将为我们渲染的 HTML（每当它看到我们的自定义标签`<car></car>`时）。让我们通过加强我们之前的`@Component`注解来纠正这一点：

```ts
@Component({
  selector: 'car',
  template: '<h3>What production car has the fastest acceleration 
     time from 0 to 60?</h3><p>Tesla </p>'
})
class CarComponent {
}
```

如果我们的组件需要大量 HTML 会发生什么？好吧，这就是为什么我们有另一个可以使用的属性，`templateUrl`*。*`templateUrl`属性为我们提供了一种将组件的 HTML 从组件类外部化并放在单独文件中的方法。您的`template`属性看起来可能是这样的：

```ts
template: 'car.html'
```

# styles 和 stylesUrls

`styles`属性用于您期望的用途-向我们的组件模板添加样式。就像`template`属性一样，值的类型是字符串。此外，因为在多行上间隔 CSS 最容易阅读，我们将使用反引号字符（在 ES6 中是新的，因此也在 TypeScript 中可用），它使我们能够创建所谓的*模板文字*。让我们向`CarComponent`类添加`styles`参数，看看这可能是什么样子：

```ts
@Component({
 selector: 'car',
  template: '<h3>What production car has the fastest acceleration 
     time from 0 to 60?</h3><p>Tesla </p>',
  styles: [`
    .car {
      color: #008000;
      font-weight: bold; 
    }
  `]
})
class CarComponent {
}
```

这就是`styles`属性的全部内容。我敢打赌你可以猜到`styleUrls`属性的作用。是的-它的工作原理就像`templateUrl`属性一样。它为我们提供了一种将组件的 CSS 从组件类外部化并将其放在外部样式表中的方法。请注意，我提到了*文件*，即*文件*的复数形式。`styleUrls`属性接受字符串数组的值（与`templateUrl`属性的值的类型为字符串相反）-因此，如果我们想要，我们可以将多个样式表传递给它*。*

因此，通过使用模板，`templateUrl`，styles 和`styleUrls`属性的组合，我们可以将 HTML（即我们的组件模板）和我们想要应用于模板的 CSS 封装在我们的组件类中-感谢`@Component`注释为我们提供的属性。由于`selector`属性，我们可以在组件的父模板中使用自定义 HTML 标记。您开始对所有这些东西如何组合在一起有了良好的感觉吗？如果没有，别担心-当我们开始实现示例应用程序的视图时，您很快就会明白。

# 视图封装

视图封装是非常方便和非常酷的东西-就像 Angular 中的大多数东西一样-用于配置我们的 CSS 的范围。

通常，当我们创建（或更改）CSS 类时，样式会应用于整个应用程序，而不限于特定页面、组件等。Angular 通过允许我们将样式封装（即限制或包含）到包含给定样式表/CSS 的组件中，为我们提供了对此的一定程度的控制。这是通过`@Component`注释的另一个属性`encapsulation`来实现的。

我们可以将组件样式的封装设置为以下三个可能值之一：

+   `ViewEncapsulation.Emulated`: 这是默认值，效果是我们的样式将仅限于我们的组件。它们不会影响我们页面上的其他任何东西。但是，我们的组件仍将继承或访问全局可访问的样式。

+   `ViewEncapsulation.Native`: 这基本上与`ViewEncapsulation.Emulated`相同，只是我们要求 Angular 阻止或保护我们的组件免受任何全局定义的样式影响。效果是我们的组件将免受未分配给我们`@Component`注释的`styles`或`styleUrls`属性的任何样式的影响。

+   `ViewEncapsulation.None`: 这是我们会使用的设置，如果我们不想控制 CSS 隔离的级别。换句话说，如果我们希望让我们组件的 CSS 影响其他页面资产，并且还希望我们的组件继承全局定义的 CSS 规则集，这就是我们会使用的设置。

这很酷，不是吗？多么棒的功能！如果你仔细想想，这是使代码重用成为可能的事情之一，甚至在不同的应用程序之间，而不仅仅是在同一个应用程序中。如果我们想要保证我们的组件在 Angular 应用程序中看起来相同，无论任何给定应用程序的样式如何，我们可以将我们组件的`encapsulation`属性设置为`ViewEncapsulation.Native`，然后就可以了。

# 模块与 NgModule

术语非常重要，因为由于语义的原因很容易混淆事物。当涉及的主题中的语言/术语包含重载词时，这一点尤为真实，就像 Angular 作为主题一样。例如，我们已经看到，我们必须非常明确地说明我们所说的*组件*和*页面*的含义。同样的事情也适用于*模块*这个词，所以在继续之前，我想在这一点上澄清一些事情。

正如我们在第二章中所看到的，*ECMAScript 和 TypeScript 速成课*，模块的概念在 ES6 中是新的。在 JavaScript 中，当我们谈论模块时，通常是指一个代码文件，然后我们可以将其导入到我们执行脚本的上下文中，使其封装的函数对我们的脚本可用。Angular 模块，或`NgModule`，是由多个文件组成的模块，因此通常被称为包。因为我们像导入 JavaScript 模块一样对待这个`NgModule`或包，我们经常认为它们是等价的，但它们并不是。

本章重点是组件，但当我们将对后端 API 的调用封装在一个统一的包中时，我们还将在第十一章中看一下如何构建我们自己的`NgModules`，*依赖注入和服务*。

在我们离开关于`NgModule`的讨论之前，将进一步讨论推迟到以后的章节，我想至少触及一下它的一些参数，因为`@NgModule`是我提到过的另一个存在的注解。

# @NgModule 装饰器的属性

如果您查看我们在第四章中开始构建的示例应用程序中的`app.module.ts`文件，您会看到在我们的`AppModule`类上的`@NgModule`注解中有四个参数。让我们快速看一下这四个参数以及我们用它们做什么：

+   **声明**：这是我们列出需要打包在这个`NgModule`中的组件和指令的地方。

+   **导入**：这使得其他模块的导出声明对我们的`NgModule`可用。

+   **提供者**：这是我们列出服务和值的地方，以便它们为**依赖注入**（**DI**）所知。它们被添加到根作用域，并被注入到其他具有它们作为依赖项的服务或指令中。我们将在第十二章中介绍 DI，*集成后端数据服务*。

+   **引导**：这是我们列出我们希望 Angular 在应用程序启动时引导的组件。

在我们的应用程序中只能有一个`NgModule`，我们在其中使用 Bootstrap 参数，因为引导过程始于只有一个模块。

# 内容投影

内容投影的概念为组件开发人员提供了一种可以增加其可重用性的机制。特别是，我指的是它们的数据显示方式（即呈现方式）。

这意味着，我们不再试图创建一个组件，为每种可能的方式都有属性，而是可以更改其模板（这几乎是不可能的），以便使用组件的开发人员可以变化这些属性的值，以自定义渲染方式。内容投影提供了一种以更少的仪式实现这一点的方法。

我们使用的机制是一对 `ng-content` 标签，就像这样：`<ng-content></ng-content>`。

我们将在照片列表页面中实践这一点，但现在让我给你展示一个人为的例子。让我们修改我们的 `CarComponent` 模板为以下代码片段（添加一对 `ng-content` 标签）：

```ts
template: '<h3>What production car has the fastest acceleration time from 0 to 60?</h3><ng-content></ng-content>'
```

这样做的目的是使 CarComponent 的父组件能够将内容投影到 CarComponent 的模板中，从而根据需要更改模板。假设我们不仅仅想在常规文本中显示汽车制造商，而是想在一组 `<p>` 标签中显示汽车制造商。

父组件将如下所示：

```ts
<car>
    <strong>Tesla</strong>
</car>
```

而不是如下所示：

```ts
<car></car>
```

再次，这是一个人为的例子。另外，Angular 的整个重点是拥有动态数据，但我们在这里没有做到。例如，我们会将汽车问题和答案数据绑定到组件模板中的元素，而不是将其硬编码（在这种情况下是 *哪辆量产汽车的 0 到 60 加速时间最快？* 和 *特斯拉*）。然而，我们简化的硬编码代码以最直接的方式说明了内容投影的概念——即不使数据动态化，而我们将在本书的后面部分做一些动态化。

# 投影多个部分

可以包含多对 `ng-content` 标签。然而，由于 Angular 无法确定哪个投影内容已替换了哪组 `ng-content` 标签，我们需要以某种方式标记 `ng-content` 标签，以使它们彼此区分开来。

一种简单的方法是通过类名标记或标记`ng-content`标签，以便预期投影的内容替换所需的一组`ng-content`标签。我们使用`ng-content`的名为`select`的属性来标记标签。让我们扩展我们的虚构`CarComponent`示例，看看这在具有两对`ng-content`标签时会是什么样子：

```ts
template: '<ng-content select=".question"></ng-content><ng-content select=".answer"></ng-content>'
```

以下是父组件的样子：

```ts
<car>
    <h3 class="question">What production car has the fastest acceleration 
       time from 0 to 60?</h3>
    <span select="answer"><strong>Tesla</strong></span>
</car>
```

通过使用`ng-content`标签及其`select`属性，如果您有多个内容投影目标，您可以创建可由消费者定制的组件。

# 生命周期钩子

与几乎所有活着的事物一样，从我们太阳系中的恒星到您可能买来装饰餐桌的花朵，Angular 组件也有一个生命周期，它们从诞生到消亡经历的不同阶段或阶段。

我们可以在这些不同的阶段钩入任何我们希望 Angular 为我们运行的代码，因为 Angular 为我们提供了特殊的方法，每个组件生命周期阶段都有一个方法，Angular 会为我们调用。我们所要做的就是提供我们希望 Angular 运行的代码，我们是通过在组件类中添加与生命周期钩子同名的函数来实现的。

组件有一组生命周期钩子，其子组件（即子组件）也有一组生命周期钩子。以下表列出了最常见的生命周期钩子：

| **生命周期钩子** | **类型** | **在...时调用** |
| --- | --- | --- |
| `constructor` | 组件 | Angular 在类上调用`new`时创建组件。 |
| `ngOnInit` | 组件 | 组件已完全初始化。 |
| `ngOnChanges` | 组件 | 输入属性发生变化（每次变化调用一次）。 |
| `ngOnDestroy` | 组件 | Angular 即将销毁组件。 |
| `ngAfterContentInit` | 子 | 组件的内容投影发生后。 |
| `ngAfterContentChecked` | 子 | Angular 在内容上运行其变更检测算法。 |
| `ngAfterViewInit` | 子 | 组件的视图已完全初始化。 |
| `ngAfterViewChecked` | 子 | Angular 在视图上运行其变更检测算法。 |

# 最常见的生命周期钩子

从前面的八个生命周期钩子中，你最有可能只使用其中的三个（在大多数情况下）。所有这三个都属于组件类型的生命周期钩子：

+   `ngOnInit`：我们的组件初始化逻辑将放在这里。你可能会认为构造函数是添加初始化逻辑的地方，但`ngOnInit`更可取，因为通过我们的接口（即输入属性）进行的任何数据绑定都已经完成。构造函数阶段并非如此。

+   `ngOnChanges`：当我们想知道哪些输入属性已经改变，以及它们被改变成了什么，这就是需要查看的地方。

+   `ngOnDestroy`：这是我们为组件插入清理逻辑的地方（如果我们有任何需要清理的东西 - 否则，我们就不使用它）。

这是一个我们如何钩入`ngOnInit`生命周期钩子的例子（我们只是向控制台输出一些内容）：

```ts
class CarComponent {
    ngOnInit()  {
        console.log('An instance of our CarComponent has 
            been fully initialized.');
    }
}
```

# 组件接口 - 输入和输出，以及数据流

如果你要在特定屏幕上创建一个组件的图表（即视图/页面），在它们之间画箭头来表示数据流，箭头将从一个组件的输出指向另一个组件的输入。

在代码中，正如我们将在实现中看到的那样，我们绑定输出和输入的方式是在我们的组件模板中（即在 HTML 中）。但是要在 HTML 中进行绑定，我们需要在代码中创建我们的组件，并且我们需要给它们接口。

让我们快速看一个具体的例子，它将展示父组件如何将数据传递给它的子组件。为了演示这一点，让我们首先创建我们的两个组件。

这是我们的`DadComponent`，它将是父组件：

```ts
import {Component } from '@angular/core';
@Component({
    selector: 'dad',
    template: `<h1>Hello. {{message}}.</h1> <br/> 
        <son *ngFor="let name of arrSonNames" 
        [Name]="name">
        </son>
    `,
})
export class DadComponent { 
    message : string = "I'm a Dad";
    arrSonNames = ['Justin','','Brendan'];
}
```

这是我们的`SonComponent`，它将是子组件：

```ts
import { Component, Input, OnInit } from '@angular/core';
@Component({
    selector: 'son',
    template: `<h2>Hi. I'm a son, and my name is {{_name}}.</h2>`
})
export class SonComponent implements OnInit {
    _name: string;
    constructor() {
        console.log("The son component was just instantiated.");
    }
    ngOnInit(){
        console.log("The son component is now fully initialized.");
    }
    @Input()
    set Name(name : string ) {
        this._name = (name && name.trim()) || "I am a son."; 
    }
    get Name() {
        return this._name;
    }
}
```

这段代码中发生了很多事情。我不会描述前面代码块中发生了什么。相反，我希望你花几分钟时间研究一下，看看你能否弄清楚发生了什么。你应该从以前的章节中获得足够的信息，再加上一些关于 JavaScript/TypeScript 的基本知识，以及对 getter 和 setter 的理解（因为许多语言都有）。我知道你能做到——试一试。我会给你两个提示：1）`@Input()`是一个装饰器，在这种情况下，它创建了`SonComponent`的公共接口；2）`DadComponent`最终会创建三个`SonComponent`的实例。其中两个儿子会知道自己的名字，不幸的是，其中一个儿子不会知道自己的名字。他会说什么？知道自己名字的儿子叫什么？你能看出为什么会创建三个儿子吗？你能猜到会写入控制台什么，以及会写入多少次吗？

我们将在我们的实现中看到很多这种模式，所以如果看起来奇怪，或者似乎有点复杂，并且你不能回答我提出的所有问题，不要担心。过一段时间，这些东西应该变得很自然。是的，我将从现在开始解释我们的实现代码——不是详细到极致，但足够让你理解手头的材料。目前，我只是想让你感受一下通过组件接口传递数据是什么样子。

# 我们三个页面的组件实现

我们现在有足够的知识来实现（即，在代码中创建）我们示例应用程序以下三个页面所需的组件：

+   预览列表

+   照片列表

+   预览照片

为了生成这些组件，我们将利用 Angular CLI 原理图。运行以下命令，我们应该期望自动生成组件和所需的文件：

```ts
ng generate component photo-listing
ng generate component preview-listing
ng generate component preview-photo
```

一旦命令成功运行，我们应该看到如下屏幕截图所示的输出：

！[](assets/21ffb974-aa8f-4b2c-aa74-aa5c58aa2b9e.png)

在上面的屏幕截图中，我们可以注意到已为组件生成了相应的文件，并且`app.module.ts`文件已经更新为最新生成的组件。

到目前为止，我们应用程序的最终项目结构如下所示：

！[](assets/ee18d776-dfb0-4d9a-8c20-fe27b2ef2770.png)

# 摘要

在本章中，我们涵盖了很多内容。您可能并没有完全理解上一节中的一些代码，这没关系，因为当我们一起为示例应用程序实现页面时，您会变得擅长这些内容。由于本章是关于组件的，我只是想向您展示如何设置父组件和子组件的一般结构，以及如何通过子组件的公共接口从父组件传递数据。但是，现在您应该对 Angular 应用程序只是一组组件的树有了相当好的理解。分解组件为子组件的经验法则是什么，注解和装饰器是什么。

我们还研究了`@Component`注解/装饰器是什么，它的属性是什么，以及如何配置它们。然后，我们转向了`@NgModule`装饰器是什么，它的一些属性是什么，以及它们的作用是什么。然后，我们研究了内容投影是什么，以及如何使用它允许其他开发人员自定义他们的渲染。

最后，我们学习了什么是生命周期钩子，如何使用它们以及为什么要使用它们。然后，我们转向了组件接口是什么以及如何创建它们。最后，我们研究了我们三个页面（预览列表、照片列表和预览照片）所需的组件的实现。

在下一章，第七章，*模板、指令和管道*，我们将深入研究组件的模板部分，因为那里是所有数据绑定和渲染发生的地方——将我们的 Angular 应用程序从一堆 0 和 1 带到我们的屏幕上。

Angular 提供了许多工具，以指令和管道的形式，供我们利用，这样我们就可以告诉它如何在画布上绘制。所以，翻过页面，让我们了解如何让 Angular 开始在应用程序画布上放置我们的组件绘制，从而使我们的应用程序生动起来——这就是我们将把我们的组件放置到我们的三个页面（预览列表、照片列表和预览照片）上的地方。


# 第七章：模板、指令和管道

模板定义了组件在网页上的显示和布局方式。Angular 提供了几个内置指令，让开发人员控制他们的组件的显示方式——从是否显示或隐藏组件，到在页面上多次渲染组件。内置指令还提供了一种将类和样式绑定到组件的机制。

在第六章，*构建 Angular 组件*中，我们看了组件的结构以及如何将我们的应用程序分解为一棵组件树。

在本章中，您将学习如何控制组件在其父模板中的显示。具体来说，我们将一起讨论以下内容：

+   模板

+   指令

+   管道

# 模板

在上一章中，我们已经了解了组件模板是什么以及如何创建它们。然而，到目前为止，我们只看到了静态 HTML。在本节中，我想稍微放大一下，和您一起看一些模板语法，这些语法允许我们创建动态 HTML，这当然是 Angular 的主要目标之一。

在 Angular 中，模板语法为我们提供了一种机制，使我们的 HTML 动态化——具体来说，用于数据绑定、属性绑定和事件绑定。在本章中，我们将看看这三种绑定类型。Angular 赋予我们创建生成动态 HTML 模板或操作 DOM 的能力，是通过一组符号。

以下是我们可以使用的六个基本符号：

+   `{{ }}` 用于字符串插值和单向数据绑定

+   `[( )]` 用于双向数据绑定

+   `#` 用于变量声明

+   `( )` 用于事件绑定

+   `[ ]` 用于属性绑定

+   `*` 用于前置结构指令，例如`ngFor`，正如我们将看到的

# 指令

指令的三种类型是：组件、属性指令和结构指令。然而，我们实际上只会涵盖其中的两种——属性指令和结构指令。原因是我们已经花了整整一章的时间来覆盖第一种指令，也就是组件。没错！组件实际上是隐藏的指令！具体来说（这说明了组件与属性和结构指令的区别），组件是具有模板的指令。当然，这必须意味着属性和结构指令没有模板。

好的，那么指令到底是什么？让我们给术语“指令”一个明确定义，以消除在讨论接下来的两种指令之前可能引起的任何混淆。我们将使用的定义是：Angular 指令是提供特定 DOM 操作的构造。DOM（或 HTML DOM）是文档对象模型的缩写，不是 Angular 的东西，而是浏览器的东西。所有现代浏览器在加载网页时都会创建一个 DOM，这是一个可以被 JavaScript 访问的对象树。没有 DOM，Angular（以及任何其他操作 DOM 的 Web 框架）都不会存在。

正如我们在第六章中所看到的，构建 Angular 组件符合我们对指令的定义，因为它们确实是提供特定 DOM 操作的构造。它们的模板不仅被注入到我们的页面中（替换它们的自定义 HTML 标签），而且它们本身包含数据、属性和事件绑定，进一步操作 DOM。

我们已经以各种方式充分解释了组件，并将在接下来的章节中看到它们在实现我们的线框时的实际应用。

剩下的两种指令类型不会在我们的页面或视图中注入任何 HTML 模板，因为它们没有任何模板。然而，它们会操作 DOM，正如我们之前对指令的定义所要求的那样。现在让我们来看看这两种类型的指令分别是做什么的。

# 属性指令

属性指令通过改变特定 DOM 元素的外观或行为来操作 DOM。这些类型的指令被括号括起来，是 HTML 元素的属性。括号是符号（我们在本章开头列出的五种符号之一），它们向 Angular 发出信号，告诉它可能需要改变指令所属元素的外观或行为。

最后一句话很啰嗦，让我们看一个你最有可能使用的属性指令的代码示例。我所指的指令名为`hidden`，它将导致 Angular 要么显示要么隐藏它的元素：

```ts
<div [hidden]="usertype != 'admin'">
  This element, and its contents, will be hidden for all users that are not Admins. 
</div>
```

在前面的代码中，我们隐藏了`div`元素和所有非管理员用户类型的嵌入式 HTML。在这里，`usertype`和`admin`当然是应用上下文的东西，只是用作示例来说明 Angular 可以做什么。

更一般地说，`hidden`属性指令与要评估的表达式相关联。表达式必须评估为布尔值（即`true`或`false`）。如果表达式评估为`true`，Angular 将从视图中隐藏该元素。相反，如果表达式评估为`false`，Angular 将不做任何改变，并且该元素将在视图中显示。

就像我在之前的章节中所做的那样，我会确保将您指向官方在线文档。正如您现在所知，我不喜欢其他许多 IT 书籍采取的方法，即机械地重复文档。虽然在某种程度上是不可避免的，但有些书籍的大部分页面都是这样。因此，我将继续远离这种陷阱，并将继续以更好的方式添加所有可能的价值。

也就是说，属性指令的官方在线文档可以在[`angular.io/guide/attribute-directives`](https://angular.io/guide/attribute-directives)找到。

# 结构指令

结构指令通过添加或删除特定的 DOM 元素来操作 DOM。就像我们有语法可以用来向 Angular 发出信号，告诉它我们有一个需要注意的属性指令一样，使用括号符号，我们也有结构指令的等价物。

我们用来向 Angular 发出信号，告诉它我们有一个结构指令需要注意的语法是星号（*）。结构指令以星号为前缀，这向 Angular 发出信号，告诉它可能需要向 DOM 添加或删除元素。正如我在本章开头列举的那样，星号是我们可以在模板语法中使用的符号之一。

# NgFor

正如我们看一个属性指令的代码示例，你最有可能使用的，现在让我们来看一个结构指令的代码示例，你可能会经常使用——`NgFor`：

```ts
<ul>
 <li *ngFor='let car of [{"make":"Porsche", "model":"Carrera"}, {"make":"Ferrari", "model":"488 Spider"}]'>
   {{ car.make }}: {{ car.model }}
 </li>
</ul>
```

之前的`ngFor`代码示例输出如下：

```ts
Porsche: Carrera
Ferrari: 488 Spider
```

在上面的代码中，有几件事我想指出；首先是`*ngFor`结构指令。让我们用项目符号形式来看一下这些：

+   `ngFor`接受一个可迭代对象，并循环遍历它，向 DOM 添加元素

+   指令语法的一般形式是 `*ngFor="let <value> of <collection>"`

+   `NgFor`（注意大写 N）指的是定义指令的类

+   `ngFor`（注意小写 n）既是属性名称，也是`NgFor`类的一个实例

+   其余的结构指令遵循与`NgFor`相同的大小写约定（参见前两个项目符号）。

+   我们可以嵌套使用`ngFor`（就像我们可以嵌套使用`for each`...in 循环一样）

接下来，我提供给`ngFor`指令的集合并不代表我们通常如何向指令传递数据。我之所以以这种方式编码是为了简洁。我们通常会这样做，即在组件类中定义数据（即我们的集合），并将其分配给一个变量，然后在附加到指令的语句中使用该变量。

# 访问迭代的索引值

我们经常会对迭代的索引值感兴趣——也许是为了抓取每个第 n 个对象，或者按照 x 的数量分组，或者可能我们想要实现某种自定义分页。无论需要读取迭代的当前索引值是什么，我们都可以使用`index`关键字将索引设置为表达式中的变量。

以下是一些演示这一点的示例代码：

```ts
<ul> 
  <li *ngFor="let car of cars; let i = index">
    Car #{{ i + 1 }}: {{ car.model }}
  </li>
</ul>
```

在上面的代码示例中，让我们假设汽车集合是在其他地方填充的，比如在组件类中。

此外，Angular 会为我们更新每次迭代的索引值，而我们所要做的就是引用它。

请注意，我们使用 `{{ i + 1 }}` 来输出汽车编号。这是因为，与大多数数组或可迭代对象一样（在大多数语言中，但肯定在 JavaScript 和 TypeScript 中），索引是从零开始的。另外，请注意，双大括号内的表达式 `i + 1` 不仅仅是一个变量。在 Angular 中，双大括号内插入的任何内容都会被评估。如果我们愿意，甚至可以在那里插入函数调用。

结构指令的官方在线文档可在 [`angular.io/guide/structural-directives`](https://angular.io/guide/structural-directives) 上找到。

# 内置指令

我们有几个内置指令可供我们使用。让我们在接下来的部分中看看这些。

+   `NgFor`（我们已经涵盖了这个，作为结构指令的第一个示例）

+   `NgIf`

+   `NgSwitch`、`NgCase` 和 `NgDefault`

+   `NgStyle`

+   `NgClass`

+   `NgNonBindable`

# NgIf

当我们想要在 DOM 中显示或移除元素时，我们使用 `NgIf` 指令。我们向指令传递一个表达式，它必须求值为布尔值。如果求值为 `true`，元素将在视图上显示。相反，如果表达式求值为 `false`，元素将从 DOM 中移除。

请注意，我们还可以绑定到 `hidden` 属性（属性绑定将在下文中描述）来实现相同的视觉效果，但是属性绑定方法和使用 `NgIf` 指令之间存在区别。区别在于，使用 `hidden` 的属性绑定只是隐藏元素，而使用 `NgIf` 指令会从 DOM 中实际移除元素。

以下是代码中 `NgIf` 的样子（在我们的汽车示例中的上下文中，假设我们有一个 `horsepower` 属性）：

```ts
<ul *ngFor="let car of cars">
  <li *ngIf="car.horsepower > 350">
    The {{ car.make }} {{ car.model }} is over 350 HP. 
  </li>
</ul>
```

在大多数传统编程语言中，当有一系列传统的 `if`、`then` 和 `else` 语句中要检查的替代事物时，有时使用 `switch` 语句（如果语言支持）更有意义。Java、JavaScript 和 TypeScript 是支持这种条件构造的语言的例子（当然还有许多其他语言）。Angular 也给了我们这种能力，所以我们可以更加表达和高效地编写我们的代码。

让我们在下一节中看看在 Angular 中如何实现这一点。

# NgSwitch、NgCase 和 NgDefault

在一些编程语言中，比如 Java、JavaScript 和 TypeScript，`switch`语句不能单独使用。它需要与其他语句和关键字一起使用，即`case`和`default`。Angular 的`NgSwitch`指令的工作方式完全相同，`NgSwitch`与`NgCase`和`NgDefault`一起使用。

让我们通过创建一个包含我们的汽车数据、样式和模板的组件来丰富一下这里稍微大一点的例子，该组件使用`NgSwitch`，`NgCase`和`NgDefault`：

```ts
@Component({
  selector: 'car-hp',
  template: `
    <h3>Cars styled by their HP range</h3>
    <ul *ngFor="let car of cars" [ngSwitch]="car.horsepower"> 
      <li *ngSwitchCase="car.horsepower >= 375" class="super-car">
        {{ car.make }} {{ car.model }} 
      </li>
      <li *ngSwitchCase="car.horsepower >= 200 && car.horsepower 
          < 375" class="sports-car">
        {{ car.make }} {{ car.model }}
      </li>
      <li *ngSwitchDefault class="grandma-car">
        {{ car.make }} {{ car.model }}
      </li>
    </ul>
  `,
  styles: [`
    .super-car {
      color:#fff;
      background-color:#ff0000;
    },
    .sports-car {
      color:#000;
      background-color:#ffa500; 
    },
    .grandma-car {
      color:#000;
      background-color:#ffff00; 
    } 
  `],
  encapsulation: ViewEncapsulation.Native 
})
class CarHorsepowerComponent {
  cars: any[] = [
    {
      "make": "Ferrari",
      "model": "Testerosa",
      "horsepower": 390
    },
    {
      "make": "Buick",
      "model": "Regal",
      "horsepower": 182 
    }, 
    {
      "make": "Porsche",
      "model": "Boxter",
      "horsepower": 320
    }, 
    {
      "make": "Lamborghini",
      "model": "Diablo",
      "horsepower": 485
    }
  ];
}
```

在前面的代码中，我们构建了一个完整的组件

`CarHorsepowerComponent`。在父组件模板中，Angular 将用我们在`CarHorsepowerComponent`中创建的模板替换我们自定义的 HTML 元素`<car-hp>`的实例（这是因为我们将`car-hp`分配给了我们的`CarHorsepowerComponent`类的组件注解的`selector`属性）。

我们还在组件类中包含了传递给`NgFor`指令的集合数据，而不是在之前的例子中内联在分配给`NgFor`指令的表达式中。

这是一个简单的例子，其模板遍历我们的汽车集合，并根据当前汽车的马力应用三种样式之一到汽车的品牌和型号上-这是通过`NgSwitch`、`NgCase`和`NgDefault`指令实现的。具体来说，这是结果：

+   如果汽车的马力等于或大于 375 马力，我们将认为它是一辆超级跑车，并且将汽车的品牌和型号以白色字体呈现在红色背景上

+   如果汽车的马力等于或大于 200 马力，但小于 375 马力，我们将认为它只是一辆跑车，并且将汽车的品牌和型号以黑色字体呈现在橙色背景上

+   如果汽车的马力低于 200 马力，这是我们的*默认*（或*通用*）情况，我们将认为它是一辆适合祖母开车的汽车，并且将汽车的品牌和型号以黑色字体呈现在黄色背景上-因为大多数祖母都觉得蜜蜂的颜色搭配很吸引人

当然，祖母的评论只是为了娱乐价值，我并不是故意冒犯任何需要花费整整 8 秒，*甚至更多*时间从 0 到 60 英里/小时加速的人（眨眼）。说实话，我的一辆车（2016 年本田思域）只有 158 马力——相信我，我曾经在上坡路上被一位开英菲尼迪 Q50 的祖母超过。这就是为什么在那可怕的经历之后的几天内，我买了一些更强大的东西（大笑）。

我想在上一个示例中指出的最后一件事是`NgSwitch`指令的使用方式。您会注意到我以不同的格式编写了它，即`[ngSwitch]="car.horsepower"`，而不是`*ngSwitch="car.horsepower"`。这是因为在使用结构指令时，Angular 对我们施加了一条规则，即我们不能有多个使用星号符号作为指令名称前缀的结构指令。为了解决这个问题，我们使用了属性绑定符号`[ ]`（一对方括号）。

# NgStyle

`NgStyle`指令用于设置元素的样式属性。让我们重新设计之前的`CarHorsepowerComponent`示例，该示例用于演示`NgSwitch`，`NgCase`和`NgDefault`，以展示如何使用`NgStyle`更好地实现相同的期望结果（即有条件地设置元素样式）：

```ts
@Component({
  selector: 'car-hp',
  template: `
    <h3>Cars styled by their HP range</h3>
    <ul *ngFor="let car of cars"> 
      <li [ngStyle]="{ getCarTextStyle(car.horsepower) }" >
        {{ car.make }} {{ car.model }}
      </li> 
    </ul>
  `,
  encapsulation: ViewEncapsulation.Native 
})
class CarHorsepowerComponent {
  getCarTextStyle(horsepower) {
    switch (horsepower) {
      case (horsepower >= 375):
        return 'color:#fff; background-color:#ff0000;';
      case (horsepower >= 200 && horsepower < 375):
        return 'color:#000; background-color:#ffa500;';
      default:
        return 'color:#000; background-color:#ffff00;';
    }
  }
  cars: any[] = [
    {
      "make": "Ferrari",
      "model": "Testerosa",
      "horsepower": 390
    },
    {
      "make": "Buick",
      "model": "Regal",
      "horsepower": 182 
    }, 
    {
      "make": "Porsche",
      "model": "Boxter",
      "horsepower": 320
    }, 
    {
      "make": "Lamborghini",
      "model": "Diablo",
      "horsepower": 485
    }
  ];
}
```

在我们重新设计原始的`CarHorsepowerComponent`类时，我们通过将逻辑移入类中的一个函数来简化了组件模板。我们删除了组件注释的样式属性，而是创建了一个函数（即`getCarTextStyle`）来返回样式文本给调用函数，以便我们可以设置正确的样式。

虽然这是一种更清晰的方法，但我们可以做得更好。由于我们正在为汽车文本设置样式，我们可以完全更改样式类，而不是通过文本传递实际的样式规则集。

在下一节中，关于`NgClass`，我们将再次重写我们的代码，以了解如何完成这一点。

# NgClass

`NgClass`指令类似于`NgStyle`指令，但用于设置样式类（从组件注释的样式属性中的 CSS 规则集），而不是通过原始 CSS 规则集设置样式。

以下代码示例是最后三个代码示例中最好的选择，以实现我们想要做的事情：

```ts
@Component({
  selector: 'car-hp',
  template: `
    <h3>Cars styled by their HP range</h3>
    <ul *ngFor="let car of cars"> 
      <li [ngClass]=" getCarTextStyle(car.horsepower) " >
        {{ car.make }} {{ car.model }}
      </li> 
    </ul>
  `,
  styles: [`
    .super-car {
      color:#fff;
      background-color:#ff0000;
    },
    .sports-car {
      color:#000;
      background-color:#ffa500; 
    },
    .grandmas-car {
      color:#000;
      background-color:#ffff00; 
    } 
 `], 
 encapsulation: ViewEncapsulation.Native 
})
class CarHorsepowerComponent {
  getCarTextStyle() {
    switch (horsepower) {
      case (horsepower >= 375):
        return 'super-car';
      case (horsepower >= 200 && horsepower < 375):
        return 'sports-car';
      default:
        return 'grandmas-car';
    }
  }
  cars: any[] = [
    {
      "make": "Ferrari",
      "model": "Testerosa",
      "horsepower": 390
    },
    {
      "make": "Buick",
      "model": "Regal",
      "horsepower": 182 
    }, 
    {
      "make": "Porsche",
      "model": "Boxter",
      "horsepower": 320
    }, 
    {
       "make": "Lamborghini",
       "model": "Diablo",
       "horsepower": 485
    }
  ];
}  
```

在这里，我们保留了组件注释的`styles`属性，保持了模板的轻量和清晰，我们的函数只返回要分配给我们的`NgClass`指令的 CSS 类的名称。

# NgNonBindable

我们要介绍的最后一个指令是`NgNonBindable`指令。当我们希望 Angular 忽略模板语法中的特殊符号时，就会使用`NgNonBindable`。为什么我们要这样做呢？嗯，假设你和我决定创建一个在线的 Angular 教程，而网站本身要使用 Angular 进行编码。如果我们想要将文本`{{ my_value }}`呈现到视图中，Angular 会尝试在当前范围内查找`my_value`变量来绑定值，然后插入文本。由于这不是我们希望 Angular 做的事情，我们需要一种方法来指示 Angular，“嘿，顺便说一句，现在不要尝试评估和字符串插值任何东西，只需像对待任何其他普通文本一样呈现这些符号”。

比如，这是一个`span`元素的样子：

```ts
<p>
To have Angular perform one-way binding, and render the value of my_value onto the view, we use the    double curly braces symbol like this: <span ngNonBindable>{{ my_value }}</span>
</p>
```

请注意`NgNonBindable`指令在开放的`<span>`标记中的位置。当 Angular 看到`ngNonBindable`时，它将忽略双大括号，并且不会单向绑定任何内容。相反，它将让原始文本呈现到视图中。

# 使用 NgModel 指令进行数据绑定

我们在示例中看到了单向数据绑定的一个例子，该示例演示了如何使用`NgFor`指令。换句话说，单向数据绑定是使用双大括号符号`{{ }}`完成的。我们在双大括号中包含的变量（例如示例中的`car.make`和`car.model`）是单向绑定的（即从组件类到模板），转换为字符串，并呈现到视图中。它不允许将任何更改绑定回组件类。

为了实现双向数据绑定，从而也允许在视图中绑定对组件类的更改，我们必须使用`NgModel`指令。

当我们实现我们的线框时，我们将看到这一点，但现在让我向你展示一下它是什么样子的。为了使用`NgModel`，我们必须首先从`forms`包中导入一个名为`FormsModule`的 Angular 模块，就像这样：

```ts
import { FormsModule } from '@angular/forms';
```

然后，要使用这个指令，我们会有类似这样的东西：

```ts
<div [(ngModel)]="my_content"></div>
```

将这段代码放在这里不仅会导致视图模板显示组件类中`my_content`的值，而且对视图模板中这个`div`的任何更改都会被绑定回组件类。

# 事件绑定

在我们实现示例应用程序的线框时，我们将看到很多事件绑定。为了绑定我们感兴趣的元素上要监听的事件，我们将事件名称括在括号中（这是我们在模板语法中可以使用的特殊符号之一）。为此，我们分配一个语句在事件触发时运行。

这是一个 JavaScript 警报的例子，当有人点击`<span>`元素时将会触发：

```ts
<span (click)="alert('This is an example of event binding in Angular');"></span>
```

在上面的代码中，我们附加了一个`click`事件，并调用一个带有消息的警报框。

# 属性绑定

我们在先前的例子中已经看到了属性绑定，但为了完整起见，我在这里很简要地给出另一个例子：

```ts
<p class="card-text" [hidden]="true">This text will not show.</p>
```

在这个先前的例子中，我们将要设置的属性括在方括号中（这是我们在模板语法中可以使用的特殊符号之一）。当然，在这个例子中这并不是很有用，因为我已经将布尔值硬编码为`true`，而不是使用要求评估的表达式，但这个例子的重点是集中在`[hidden]`部分。

# 自定义指令

Angular 是可扩展的。我们不仅可以轻松创建自定义组件（这样我们就不受限于使用第三方提供的现成组件），还可以创建自定义属性指令，这样我们就不受限于 Angular 默认提供的内容。

我会留下一些我们在 Angular 中可以做的自定义事情，比如自定义属性指令、自定义管道（我们将在下一节中看到管道是什么），以及自定义表单验证，直到第十四章，*高级 Angular 主题*。我们将在第十章，*使用表单*中看到表单验证。我选择将这本书中涵盖的所有高级内容都放在一个章节中是有充分理由的——让你有时间先消化基础知识。当高级章节出现时，接近书的末尾，你将准备好并更容易吸收那些信息。

# 管道

管道用于格式化我们模板视图中的数据。管道将接受数据作为输入，并将其转换为我们期望的格式，以便向最终用户显示。我们可以在我们项目中的任何 Angular 模板或视图中使用`pipe`属性（`|`）。

在我们开始创建示例之前，让我快速概述一下。假设我们从后端服务获取产品的价格为 100，并根据用户的国家或偏好，我们可能希望以$100 的方式显示价值，如果用户来自美国，或者以 INR 100 的方式显示价值，如果用户来自印度。因此，我们能够在没有任何主要复杂性的情况下转换我们显示价格的方式。这要归功于货币管道运算符。

Angular 提供了许多内置管道，可以直接在我们的模板中使用。此外，我们还可以创建自定义管道来扩展我们应用程序的功能。

以下是 Angular 提供的所有内置管道的列表：

+   小写管道

+   大写管道

+   日期管道

+   货币管道

+   JSON 管道

+   百分比管道

+   小数管道

+   切片管道

我们将通过一些有趣的实际示例来了解每个可用的内置管道。到目前为止，我们可以利用我们在 Angular 项目中创建的任何现有模板文件。

我们需要一些数据，我们想要使用我们的管道来处理和转换。我将在我们的`app.component.ts`文件中快速创建一个数据集：

```ts
products: any[] = [ {  "code": "p100",
  "name": "Moto",
  "price": 390.56
 }, {  "code": "p200",
  "name": "Micro",
  "price": 240.89
 }, {  "code": "p300",
  "name": "Mini",
  "price": 300.43
 } ];
```

我们在应用程序组件中创建了一个产品的样本数据集。好了，现在我们可以在我们的`app.component.html`文件中应用我们的管道了。我们将在模板中保持简单。我们将只创建一个表格并绑定表中的值。如果你今天感觉有点冒险，那就继续使用 Flex-Layout 为我们的应用程序创建一个布局，我们在第五章中学到了*Flex-Layout – Angular's Responsive Layout Engine*：

```ts
<h4>Learning Angular Pipes</h4> <table>
  <tr>
  <td>Product Code</td>
  <td>Product Name</td>
  <td>Product Price</td>
  </tr>
  <tr  *ngFor="let product of products">
  <td>{{product.code}}</td>
  <td>{{product.name}}</td>
  <td>{{product.price}}</td>
  </tr>  </table>
```

在上面的示例代码中，我们创建了一个表格，并使用数据绑定将数据绑定到我们的模板中。现在是时候在我们的模板中使用管道运算符了。要应用任何管道，我们必须在数据中添加管道运算符，如下面的语法所示：

```ts
{{ data | <pipe name> }}
```

我们可以通过应用大写管道轻松地将我们的产品名称转换为大写，如下所示：

```ts
<td>{{product.name | uppercase }}</td>
```

同样地，我们也可以使用小写管道，这将使所有字符变为小写：

```ts
<td>{{product.name | lowercase }}</td>
```

你可能会说那太简单了？确实如此！让我们继续。类似地，我们将使用数字管道操作符来显示或隐藏小数点。

为了显示产品价格，我们想要添加货币；没问题，我们将使用货币管道：

```ts
<td>{{product.price | currency }}</td>
```

在前面的例子中，我们通过添加货币管道来转换了产品价格。剩下的管道操作符就留给你作业了。

当我们使用货币管道时，默认情况下会添加`$ currency`。

我们可以通过给货币管道加参数来自定义它。我们将学习如何向管道操作符传递参数。我们将不得不通过以下方式扩展管道操作符的语法来传递参数：

```ts
{{ data | pipe : <parameter1 : parameter2> }}
```

前面的语法看起来类似于我们学习如何定义管道操作符的方式，只是现在它有两个参数。根据我们的需求，我们可以定义任意数量的参数的管道操作符。在前面的例子中，我们使用了货币操作符，所以让我们传递参数来扩展货币管道操作符：

```ts
<td>{{ product.price | currency: 'INR' }}</td>
```

我们正在向我们的货币管道操作符传递`INR`参数。现在，货币管道操作符的输出将不再是`$`，而是如下所示的屏幕截图中显示的内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/6a445fcb-47d2-494e-8ff7-1c9a932b9260.png)

在本节中，我们已经学会了使用内置的管道操作符。现在，我们将学习如何创建我们自己的自定义管道。

# 自定义管道

Angular 在自定义管道和自定义指令的领域也是可扩展的。然而，我将推迟我们对自定义管道的讨论，直到第十四章，“高级 Angular 主题”。我在这里包含了这一部分作为一个占位符，以及对以后的覆盖的提醒，也是为了完整性。

# 总结

在本章中，我们放大了组件模板，以及我们用于创建它们的模板语法。我们的模板语法包括符号、指令和管道。

我们已经看到指令只是没有模板的组件，它们有两种主要的类型——**属性指令**和**结构指令**。无论它们的类型或类别如何，我们都可以通过将它们添加为元素的属性来将指令与 HTML 元素关联（或附加）。

我们已经介绍了我们可以在模板语法中使用的以下特殊符号。我们还介绍了我们可以在模板语法中使用的内置指令。接下来，我们介绍了事件绑定，以及属性绑定，最后，我们介绍了管道，它为我们提供了格式化数据的方式，以便按照我们期望的方式呈现到视图中。

我们知道 Angular 是可扩展的，并且它为我们提供了创建自定义指令和自定义管道的机制，但我们将推迟讨论任何自定义内容到[第十四章]《高级 Angular 主题》。

在下一章，[第八章]《使用 NG Bootstrap 工作》，我们将重新戴上组件帽子，以便探索`ng-bootstrap`为我们在构建 Angular 应用程序时带来了什么。
