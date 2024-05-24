# Angular2 切换指南（三）

> 原文：[`zh.annas-archive.org/md5/AE0A0B893569467A0AAE20A9EA07809D`](https://zh.annas-archive.org/md5/AE0A0B893569467A0AAE20A9EA07809D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Angular 2 路由器和表单

到目前为止，我们已经熟悉了框架的核心。我们知道如何定义组件和指令来开发我们应用程序的视图。我们还知道如何将与业务相关的逻辑封装到服务中，并使用 Angular 2 的依赖注入机制将所有内容连接起来。

在本章中，我们将解释一些概念，这些概念将帮助我们构建真实的 Angular 2 应用程序。它们如下：

+   框架的基于组件的路由器。

+   使用 Angular 2 表单。

+   开发基于模板的表单。

+   开发自定义表单验证器。

让我们开始吧！

# 开发“Coders repository”应用程序

在解释前面提到的概念的过程中，我们将开发一个包含开发人员存储库的示例应用程序。在我们开始编码之前，让我们解释一下应用程序的结构。

“Coders repository”将允许其用户通过填写有关他们的详细信息的表单或提供开发人员的 GitHub 句柄并从 GitHub 导入其个人资料来添加开发人员。

### 注意

为了本章的目的，我们将在内存中存储开发人员的信息，这意味着在刷新页面后，我们将丢失会话期间存储的所有数据。

应用程序将具有以下视图：

+   所有开发人员的列表。

+   一个添加或导入新开发人员的视图。

+   显示给定开发人员详细信息的视图。此视图有两个子视图：

+   **基本详情**：显示开发人员的姓名及其 GitHub 头像（如果有）。

+   **高级资料**：显示开发人员已知的所有详细信息。

应用程序主页的最终结果将如下所示：

![开发“Coders repository”应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00023.jpeg)

图 1

### 注意

在本章中，我们将只构建列出的视图中的一些。应用程序的其余部分将在第七章中解释，*解释管道和与 RESTful 服务通信*。

每个开发人员将是以下类的实例：

```ts
// ch6/ts/multi-page-template-driven/developer.ts
export class Developer {
  public id: number;
  public githubHandle: string;
  public avatarUrl: string;
  public realName: string;
  public email: string;
  public technology: string;
  public popular: boolean;
}
```

所有开发人员将驻留在`DeveloperCollection`类中：

```ts
// ch6/ts/multi-page-template-driven/developer_collection.ts
class DeveloperCollection {
  private developers: Developer[] = [];
  getUserByGitHubHandle(username: string) {
    return this.developers
            .filter(u => u.githubHandle === username)
            .pop();
  }
  getUserById(id: number) {
    return this.developers
             .filter(u => u.id === id)
             .pop();
  }
  addDeveloper(dev: Developer) {
    this.developers.push(dev);
  }
  getAll() {
    return this.developers;
  }
}
```

这里提到的类封装了非常简单的逻辑，并没有任何特定于 Angular 2 的内容，因此我们不会深入讨论任何细节。

现在，让我们继续实现，通过探索新的路由器。

# 探索 Angular 2 路由器

正如我们已经知道的那样，为了引导任何 Angular 2 应用程序，我们需要开发一个根组件。 "Coders repository"应用程序并没有什么不同；在这种特定情况下唯一的额外之处是我们将有多个页面需要使用 Angular 2 路由连接在一起。

让我们从路由器配置所需的导入开始，并在此之后定义根组件：

```ts
// ch6/ts/step-0/app.ts
import {
  ROUTER_DIRECTIVES,
  ROUTER_PROVIDERS,
  Route,
  Redirect,
  RouteConfig,
  LocationStrategy,
  HashLocationStrategy
} from 'angular2/router';
```

在前面的片段中，我们直接从 Angular 2 路由器模块中导入了一些东西，这些东西是在框架的核心之外外部化的。

使用`ROUTER_DIRECTIVES`，路由器提供了一组常用的指令，我们可以将其添加到根组件使用的指令列表中。这样，我们将能够在模板中使用它们。

导入`ROUTE_PROVIDERS`包含一组与路由器相关的提供者，例如用于将`RouteParams`令牌注入组件构造函数的提供者。

`RouteParams`令牌提供了从路由 URL 中访问参数的能力，以便对给定页面关联的逻辑进行参数化。我们稍后将演示此提供程序的典型用例。

导入`LocationStrategy`类是一个抽象类，定义了`HashLocationStrategy`（用于基于哈希的路由）和`PathLocationStrategy`（利用历史 API 用于基于 HTML5 的路由）之间的公共逻辑。

### 注意

`HashLocationStrategy`不支持服务器端渲染。这是因为页面的哈希值不会发送到服务器，因此服务器无法找到与给定页面关联的组件。除了 IE9 之外，所有现代浏览器都支持 HTML5 历史 API。您可以在书的最后一章中找到有关服务器端渲染的更多信息。

我们没有看到的最后导入是`RouteConfig`，它是一个装饰器，允许我们定义与给定组件关联的路由；以及`Route`和`Redirect`，分别允许我们定义单个路由和重定向。使用`RouteConfig`，我们可以定义一组路由的层次结构，这意味着 Angular 2 的路由器支持嵌套路由，这与其前身 AngularJS 1.x 不同。

## 定义根组件并引导应用程序

现在，让我们定义一个根组件并配置应用程序的初始引导：

```ts
// ch6/ts/step-0/app.ts
@Component({
  selector: 'app',
  template: `…`,
  providers: [DeveloperCollection],
  directives: [ROUTER_DIRECTIVES]
})
@RouteConfig([…])
class App {}

bootstrap(…);
```

在前面的片段中，您可以注意到一个我们已经熟悉的语法，来自第四章，“开始使用 Angular 2 组件和指令”和第五章，“Angular 2 中的依赖注入”。我们定义了一个带有`app`选择器的组件，稍后我们将看一下`template`，以及提供者和指令的集合。

`App`组件使用了一个名为`DeveloperCollection`的单个提供者。这是一个包含应用程序存储的所有开发人员的类。您可以注意到我们添加了`ROUTER_DIRECTIVES`；它包含了 Angular 路由中定义的所有指令的数组。在这个数组中的一些指令允许我们链接到`@RouteConfig`装饰器中定义的其他路由（`routerLink`指令），并声明与不同路由相关联的组件应该呈现的位置（`router-outlet`）。我们将在本节后面解释如何使用它们。

现在让我们来看一下`bootstrap`函数的调用：

```ts
bootstrap(App, [
  ROUTER_PROVIDERS,
  provide(LocationStrategy, { useClass: HashLocationStrategy })
)]);
```

作为`bootstrap`的第一个参数，我们像往常一样传递应用程序的根组件。第二个参数是整个应用程序都可以访问的提供者列表。在提供者集中，我们添加了`ROUTER_PROVIDERS`，并且还配置了`LocationStrategy`令牌的提供者。Angular 2 使用的默认`LocationStrategy`令牌是`PathLocationStrategy`（即基于 HTML5 的令牌）。然而，在这种情况下，我们将使用基于哈希的令牌。

默认位置策略的两个最大优势是它得到了 Angular 2 的服务器渲染模块的支持，并且应用程序的 URL 对最终用户看起来更自然（没有使用`#`）。另一方面，如果我们使用`PathLocationStrategy`，我们可能需要配置我们的应用程序服务器，以便正确处理路由。

## 使用 PathLocationStrategy

如果我们想使用`PathLocationStrategy`，我们可能需要提供`APP_BASE_HREF`。例如，在我们的情况下，`bootstrap`配置应该如下所示：

```ts
import {APP_BASE_HREF} from 'angular2/router';
//...
bootstrap(App, [
  ROUTER_PROVIDERS,
  // The following line is optional, since it's
  // the default value for the LocationStrategy token
  provide(LocationStrategy, { useClass: PathLocationStrategy }),
  provide(APP_BASE_HREF, {
    useValue: '/dist/dev/ch6/ts/multi-page-template-driven/'
  }
)]);
```

默认情况下，与`APP_BASE_HREF`令牌关联的值是`/`；它表示应用程序内的基本路径名称。例如，在我们的情况下，“Coders repository”将位于`/ch6/ts/multi-page-template-driven/`目录下（即`http://localhost:5555/dist/dev/ch6/ts/multi-page-template-driven/`）。

## 使用@RouteConfig 配置路由

作为下一步，让我们来看看放置在`@RouteConfig`装饰器中的路由声明。

```ts
// ch6/ts/step-0/app.ts
@Component(…)
@RouteConfig([
  new Route({ component: Home, name: 'Home', path: '/' }),
  new Route({
    component: AddDeveloper,
    name: 'AddDeveloper',
    path: '/dev-add'
  }),
  //…
  new Redirect({
    path: '/add-dev',
    redirectTo: ['/dev-add']
  })
]) 
class App {}
```

正如前面的片段所示，`@RouteConfig`装饰器接受一个路由数组作为参数。在这个例子中，我们定义了两种类型的路由：使用`Route`和`Redirect`类。它们分别用于定义应用程序中的路由和重定向。

每个路由必须定义以下属性：

+   `component`：与给定路由相关联的组件。

+   `name`：用于在模板中引用的路由名称。

+   `path`：用于路由的路径。它将显示在浏览器的位置栏中。

### 注意

`Route`类还支持一个数据属性，其值可以通过使用`RouteData`令牌注入到其关联组件的构造函数中。数据属性的一个示例用例可能是，如果我们想要根据包含`@RouteConfig`声明的父组件的类型来注入不同的配置对象。

另一方面，重定向只包含两个属性：

+   `path`：用于重定向的路径。

+   `redirectTo`：用户被重定向到的路径。

在前面的例子中，我们声明希望用户打开路径`/add-dev`的页面被重定向到`['/dev-add']`。

现在，为了使一切正常运行，我们需要定义`AddDeveloper`和`Home`组件，这些组件在`@RouteConfig`中被引用。最初，我们将提供一个基本的实现，随着章节的进行逐步扩展。在`ch6/ts/step-0`中，创建一个名为`home.ts`的文件，并输入以下内容：

```ts
import {Component} from 'angular2/core';
@Component({
  selector: 'home',
  template: `Home`
})
export class Home {}
```

不要忘记在`app.ts`中导入`Home`组件。现在，打开名为`add_developer.ts`的文件，并输入以下内容：

```ts
import {Component} from 'angular2/core';

@Component({
  selector: 'dev-add',
  template: `Add developer`
})
export class AddDeveloper {}
```

## 使用 routerLink 和 router-outlet

我们已经声明了路由和与各个路由相关联的所有组件。唯一剩下的就是定义根`App`组件的模板，以便将所有内容链接在一起。

将以下内容添加到`ch6/ts/step-0/app.ts`中`@Component`装饰器内的`template`属性中：

```ts
@Component({
  //…
  template: `
    <nav class="navbar navbar-default">
      <ul class="nav navbar-nav">
        <li><a [routerLink]="['/Home']">Home</a></li>
        <li><a [routerLink]="['/AddDeveloper']">Add developer</a></li>
      </ul>
    </nav>
    <router-outlet></router-outlet>
  `,
  //…
})
```

在上面的模板中有两个特定于 Angular 2 的指令：

+   `routerLink`：这允许我们添加到特定路由的链接。

+   `router-outlet`：这定义了当前选定路由相关的组件需要被渲染的容器。

让我们来看一下`routerLink`指令。它接受一个路由名称和参数的数组作为值。在我们的例子中，我们只提供了一个以斜杠为前缀的单个路由名称（因为这个路由在根级别）。注意，`routerLink`使用的路由名称是在`@RouteConfig`内部的路由声明的`name`属性声明的。在本章的后面，我们将看到如何链接到嵌套路由并传递路由参数。

这个指令允许我们独立于我们配置的`LocationStrategy`来声明链接。例如，假设我们正在使用`HashLocationStrategy`；这意味着我们需要在模板中的所有路由前加上`#`。如果我们切换到`PathLocationStrategy`，我们就需要移除所有的哈希前缀。`routerLink`的另一个巨大好处是它对我们透明地使用 HTML5 历史推送 API，这样就可以节省我们大量的样板代码。

上一个模板中的下一个对我们新的指令是`router-outlet`。它的责任类似于 AngularJS 1.x 中的`ng-view`指令。基本上，它们都有相同的作用：指出`target`组件应该被渲染的位置。这意味着根据定义，当用户导航到`/`时，`Home`组件将在`router-outlet`指出的位置被渲染，当用户导航到`/dev-add`时，`AddDeveloper`组件也是一样。

现在我们有这两条路线已经在运行了！打开`http://localhost:5555/dist/dev/ch6/ts/step-0/`，你应该会看到以下的截图：

![使用 routerLink 和 router-outlet](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00024.jpeg)

图 2

如果没有，请看一下`ch6/ts/step-1`，里面包含了最终结果。

## 使用 AsyncRoute 进行懒加载

AngularJS 1.x 模块允许我们将应用程序中逻辑相关的单元分组在一起。然而，默认情况下，它们需要在初始应用程序的`bootstrap`期间可用，并且不允许延迟加载。这要求在初始页面加载期间下载整个应用程序的代码库，对于大型单页应用程序来说，这可能是无法接受的性能损失。

在一个完美的场景中，我们希望只加载与用户当前浏览页面相关的代码，或者根据与用户行为相关的启发式预取捆绑模块，这超出了本书的范围。例如，从我们示例的第一步打开应用程序：`http://localhost:5555/dist/dev/ch6/ts/step-1/`。一旦用户在`/`，我们只需要`Home`组件可用，一旦他或她导航到`/dev-add`，我们希望加载`AddDeveloper`组件。

让我们在 Chrome DevTools 中检查实际发生了什么：

![使用 AsyncRoute 进行延迟加载](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00025.jpeg)

图 3

我们可以注意到在初始页面加载期间，我们下载了与所有路由相关的组件，甚至不需要的`AddDeveloper`。这是因为在`app.ts`中，我们明确要求`Home`和`AddDeveloper`组件，并在`@RouteConfig`声明中使用它们。

在这种特定情况下，加载这两个组件可能看起来不像是一个大问题，因为在这一步，它们非常简单，没有任何依赖关系。然而，在现实生活中的应用程序中，它们将导入其他指令、组件、管道、服务，甚至第三方库。一旦需要任何组件，它的整个依赖图将被下载，即使在那一点上并不需要该组件。

Angular 2 的路由器提供了解决这个问题的解决方案。我们只需要从`angular2/router`模块中导入`AsyncRoute`类，并在`@RouteConfig`中使用它，而不是使用`Route`：

```ts
// ch6/ts/step-1-async/app.ts

import {AsyncRoute} from 'angular2/router';
@Component(…)
@RouteConfig([
  new AsyncRoute({
    loader: () =>
      System.import('./home')
        .then(m => m.Home),
      name: 'Home',
      path: '/'
    }),
  new AsyncRoute({
    loader: () =>
      System.import('./add_developer')
        .then(m => m.AddDeveloper),
      name: 'AddDeveloper',
      path: '/dev-add'
    }),
    new Redirect({ path: '/add-dev', redirectTo: ['/dev-add'] })
])
class App {}
```

`AsyncRoute`类的构造函数接受一个对象作为参数，该对象具有以下属性：

+   `loader`：返回一个需要用与给定路由相关联的组件解析的 promise 的函数。

+   `name`：路由的名称，可以在模板中使用它（通常在`routerLink`指令内部）。

+   `path`：路由的路径。

一旦用户导航到与`@RouteConfig`装饰器中的任何异步路由定义匹配的路由，其关联的加载程序将被调用。当加载程序返回的 promise 被解析为目标组件的值时，该组件将被缓存和渲染。下次用户导航到相同的路由时，将使用缓存的组件，因此路由模块不会下载相同的组件两次。

### 注意

请注意，前面的示例使用了 System，但是 Angular 的`AsyncRoute`实现并不与任何特定的模块加载器耦合。例如，可以使用 require.js 实现相同的结果。

# 使用 Angular 2 表单

现在让我们继续实现应用程序。在下一步中，我们将在`AddDeveloper`和`Home`组件上工作。您可以通过扩展`ch6/ts/step-0`中当前的内容继续实现，或者如果您还没有达到步骤 1，您可以继续在`ch6/ts/step-1`中的文件上工作。

Angular 2 提供了两种开发带有验证的表单的方式：

+   基于模板驱动的方法：提供了一个声明性的 API，我们可以在组件的模板中声明验证。

+   基于模型驱动的方法：使用`FormBuilder`提供了一个命令式的 API。

在下一章中，我们将探讨两种方法。让我们从模板驱动的方法开始。

## 开发模板驱动的表单

对于每个**CRUD**（**创建检索更新和删除**）应用程序，表单都是必不可少的。在我们的情况下，我们想要为输入我们想要存储的开发者的详细信息构建一个表单。

在本节结束时，我们将拥有一个表单，允许我们输入给定开发者的真实姓名，添加他或她喜欢的技术，输入电子邮件，并声明他或她是否在社区中受欢迎。最终结果将如下所示：

![Developing template-driven forms](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00026.jpeg)

图 4

将以下导入添加到`add_developer.ts`：

```ts
import {
  FORM_DIRECTIVES,
  FORM_PROVIDERS
} from 'angular2/common;
```

我们需要做的下一件事是将`FORM_DIRECTIVES`添加到`AddDeveloper`组件使用的指令列表中。`FORM_DIRECTIVES`指令包含一组预定义指令，用于管理 Angular 2 表单，例如`form`和`ngModel`指令。

`FORM_PROVIDERS`是一个包含一组预定义提供程序的数组，我们可以在应用程序的类中使用它们的令牌来注入与其关联的值。

现在将`AddDeveloper`的实现更新为以下内容：

```ts
@Component({
  selector: 'dev-add',
  templateUrl: './add_developer.html',
  styles: […],
  directives: [FORM_DIRECTIVES],
  providers: [FORM_PROVIDERS]
})
export class AddDeveloper {
  developer = new Developer();
  errorMessage: string;
  successMessage: string;
  submitted = false;
  technologies: string[] = [
    'JavaScript',
    'C',
    'C#',
    'Clojure'
  ];
  constructor(private developers: DeveloperCollection) {}
  addDeveloper() {}
}
```

`developer`属性包含与当前要添加到表单中的开发者相关的信息。最后两个属性，`errorMessage`和`successMessage`，分别用于在成功将开发者成功添加到开发者集合中或发生错误时显示当前表单的错误或成功消息。

## 深入研究模板驱动表单的标记

作为下一步，让我们创建`AddDeveloper`组件的模板（`step-1/add_developer.html`）。将以下内容添加到文件中：

```ts
<span *ngIf="errorMessage"
       class="alert alert-danger">{{errorMessage}}</span>
<span *ngIf="successMessage"
       class="alert alert-success">{{successMessage}}</span>
```

这两个元素旨在在添加新开发人员时显示错误和成功消息。当`errorMessage`和`successMessage`分别具有非假值时（即，与空字符串、`false`、`undefined`、`0`、`NaN`或`null`不同的值），它们将可见。

现在让我们开发实际的表单：

```ts
<form #f="ngForm" (ngSubmit)="addDeveloper()"
      class="form col-md-4" [hidden]="submitted">
  <div class="form-group">
    <label class="control-label"
           for="realNameInput">Real name</label>
    <div>
      <input id="realNameInput" class="form-control"
             type="text" ngControl="realName" required
             [(ngModel)]="developer.realName">
    </div>
  </div>
  <button class="btn btn-default"
          type="submit" [disabled]="!f.form.valid">Add</button>
  <!-- MORE CODE TO BE ADDED -->
</form> 
```

我们使用 HTML 的`form`标签声明一个新的表单。一旦 Angular 2 在父组件的模板中找到带有包含表单指令的这样的标签，它将自动增强其功能，以便用作 Angular 表单。一旦表单被 Angular 处理，我们可以应用表单验证和数据绑定。之后，使用`#f="ngForm"`，我们将为模板定义一个名为`f`的局部变量，这允许我们引用当前的表单。表单元素中剩下的最后一件事是提交事件处理程序。我们使用一个我们已经熟悉的语法`(ngSubmit)="expr"`，在这种情况下，表达式的值是附加到组件控制器的`addDeveloper`方法的调用。

现在，让我们来看一下类名为`control-group`的`div`元素。

### 注意

请注意，这不是一个特定于 Angular 的类；这是 Bootstrap 定义的一个`CSS`类，我们使用它来提供表单更好的外观和感觉。

在其中，我们可以找到一个没有任何 Angular 特定标记的`label`元素和一个允许我们设置当前开发人员的真实姓名的输入元素。我们将控件设置为文本类型，并声明其标识符等于`realNameInput`。`required`属性由 HTML5 规范定义，并用于验证。通过在元素上使用它，我们声明这个元素需要有一个值。虽然这个属性不是特定于 Angular 的，但使用`ngControl`属性，Angular 将通过包含验证行为来扩展`required`属性的语义。这种行为包括在控件状态改变时设置特定的`CSS`类，并管理框架内部保持的状态。

`ngControl`指令是`NgControlName`指令的选择器。它通过在值更改时对它们运行验证并在控件生命周期期间应用特定类来增强表单控件的行为。您可能熟悉这一点，因为在 AngularJS 1.x 中，表单控件在其生命周期的特定阶段装饰有`ng-pristine`、`ng-invalid`和`ng-valid`类等。

以下表总结了框架在表单控件生命周期中添加的`CSS`类：

| 类 | 描述 |
| --- | --- |
| `ng-untouched` | 控件尚未被访问 |
| `ng-touched` | 控件已被访问 |
| `ng-pristine` | 控件的值尚未更改 |
| `ng-dirty` | 控件的值已更改 |
| `ng-valid` | 控件附加的所有验证器都返回`true` |
| `ng-invalid` | 控件附加的任何验证器具有`false`值 |

根据这个表，我们可以定义我们希望所有具有无效值的输入控件以以下方式具有红色边框：

```ts
input.ng-dirty.ng-invalid {
  border: 1px solid red;
}
```

在 Angular 2 的上下文中，前面的`CSS`的确切语义是对所有已更改且根据附加到它们的验证器无效的输入元素使用红色边框。

现在，让我们探讨如何将不同的验证行为附加到我们的控件上。

## 使用内置表单验证器

我们已经看到，我们可以使用`required`属性来改变任何控件的验证行为。Angular 2 提供了另外两个内置验证器，如下所示：

+   `minlength`：允许我们指定给定控件应具有的值的最小长度。

+   `maxlength`：允许我们指定给定控件应具有的值的最大长度。

这些验证器是用 Angular 2 指令定义的，可以以以下方式使用：

```ts
<input id="realNameInput" class="form-control"
       type="text" ngControl="realName"
       minlength="2"
       maxlength="30">
```

通过这种方式，我们指定希望输入的值在`2`和`30`个字符之间。

## 定义自定义控件验证器

`Developer`类中定义的另一个数据属性是`email`字段。让我们为这个属性添加一个输入字段。在前面表单的按钮上方，添加以下标记：

```ts
<div class="form-group">
  <label class="control-label" for="emailInput">Email</label>
  <div>
    <input id="emailInput"
           class="form-control"
           type="text" ngControl="email"
     [(ngModel)]="developer.email"/>
  </div>
</div>
```

我们可以将`[(ngModel)]`属性视为 AngularJS 1.x 中`ng-model`指令的替代方法。我们将在*使用 Angular 2 进行双向数据绑定*部分详细解释它。

尽管 Angular 2 提供了一组预定义的验证器，但它们并不足以满足我们的数据可能存在的各种格式。有时，我们需要为特定于应用程序的数据定义自定义验证逻辑。例如，在这种情况下，我们想要定义一个电子邮件验证器。一个典型的正则表达式，在一般情况下有效（但并不涵盖定义电子邮件地址格式的整个规范），如下所示：`/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/`。

在`ch6/ts/step-1/add_developer.ts`中，定义一个函数，该函数接受 Angular 2 控件的实例作为参数，并在控件的值为空或与前面提到的正则表达式匹配时返回`null`，否则返回`{ 'invalidEmail': true }`：

```ts
function validateEmail(emailControl) {
  if (!emailControl.value ||
    /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(emailControl.value)) {
    return null;
  } else {
    return { 'invalidEmail': true };
  }
}
```

现在，从模块`angular2/common`和`angular2/core`导入`NG_VALIDATORS`和`Directive`，并将此验证函数包装在以下指令中：

```ts
@Directive({
  selector: '[email-input]',
  providers: [provide(NG_VALIDATORS, {
    useValue: validateEmail, multi: true
  })]
})
class EmailValidator {}
```

在上述代码中，我们为令牌`NG_VALIDATORS`定义了一个多提供者。一旦我们注入与该令牌关联的值，我们将获得一个包含所有附加到给定控件的验证器的数组（有关多提供者的部分，请参阅第五章, *Angular 2 中的依赖注入*）。

使我们的自定义验证工作的唯一两个步骤是首先将`email-input`属性添加到电子邮件控件中：

```ts
<input id="emailInput"
   class="form-control"
 **email-input**
   type="text" ngControl="email"
   [(ngModel)]="developer.email"/>
```

接下来，将指令添加到组件`AddDeveloper`指令使用的列表中：

```ts
@Component({
  selector: 'dev-add',
  templateUrl: './add_developer.html',
  styles: [`
    input.ng-touched.ng-invalid {
      border: 1px solid red;
    }
  `],
  directives: [FORM_DIRECTIVES, **EmailValidator**],
  providers: [FORM_PROVIDERS]
})
class AddDeveloper {…}
```

### 注意

我们正在使用`AddDeveloper`控件的外部模板。关于给定模板是否应该被外部化或内联在具有`templateUrl`或`template`的组件中，没有最终答案。最佳实践规定，我们应该内联短模板并外部化较长的模板，但没有具体定义哪些模板被认为是短的，哪些是长的。模板应该内联还是放入外部文件的决定取决于开发人员的个人偏好或组织内的常见惯例。

## 使用 Angular 与选择输入

作为下一步，我们应该允许应用程序的用户输入开发人员最精通的技术。我们可以定义一个技术列表，并在表单中显示为选择输入。

在`AddDeveloper`类中，添加`technologies`属性：

```ts
class AddDeveloper {
  …
  technologies: string[] = [
    'JavaScript',
    'C',
    'C#',
    'Clojure'
  ];
  …
}
```

现在在模板中，在`submit`按钮的上方，添加以下标记：

```ts
<div class="form-group">
  <label class="control-label"
         for="technologyInput">Technology</label>
  <div>
    <select class="form-control"
            ngControl="technology" required
            [(ngModel)]="developer.technology">
        <option *ngFor="#t of technologies"
                [value]="t">{{t}}</option>
    </select>
  </div>
</div>
```

就像我们之前声明的输入元素一样，Angular 2 将根据选择输入的状态添加相同的类。为了在选择元素的值无效时显示红色边框，我们需要修改`CSS`规则：

```ts
@Component({
  …
  styles: [
    `input.ng-touched.ng-invalid,
     select.ng-touched.ng-invalid {
      border: 1px solid red;
    }`
  ],
  …
})
class AddDeveloper {…}
```

### 注意

注意，将所有样式内联到组件声明中可能是一种不好的做法，因为这样它们就无法重复使用。我们可以将所有组件中的通用样式提取到单独的文件中。`@Component`装饰器有一个名为`styleUrls`的属性，类型为`array`，我们可以在其中添加对给定组件使用的提取样式的引用。这样，如果需要，我们可以仅内联特定于组件的样式。

在此之后，我们将使用`ngControl="technology"`声明控件的名称等于"technology"。通过使用`required`属性，我们将声明应用程序的用户必须指定当前开发人员精通的技术。让我们最后一次跳过`[(ngModel)]`属性，看看如何定义选择元素的选项。

在`select`元素内部，我们将使用以下方式定义不同的选项：

```ts
<option *ngFor="#t of technologies"
        [value]="t">{{t}}</option>
```

这是我们已经熟悉的语法。我们将简单地遍历`AddDeveloper`类中定义的所有技术，并对于每种技术，我们将显示一个值为技术名称的选项元素。

## 使用 NgForm 指令

我们已经提到，表单指令通过添加一些额外的 Angular 2 特定逻辑来增强 HTML5 表单的行为。现在，让我们退一步，看看包围输入元素的表单：

```ts
<form #f="ngForm" (ngSubmit)="addDeveloper()"
      class="form col-md-4" [hidden]="submitted">
  …
</form>
```

在上面的片段中，我们定义了一个名为`f`的新标识符，它引用了表单。我们可以将表单视为控件的组合；我们可以通过表单的 controls 属性访问各个控件。此外，表单还具有**touched**、**untouched**、**pristine**、**dirty**、**invalid**和**valid**属性，这些属性取决于表单中定义的各个控件。例如，如果表单中的控件都没有被触摸过，那么表单本身的状态就是 untouched。然而，如果表单中的任何控件至少被触摸过一次，那么表单的状态也将是 touched。同样，只有当表单中的所有控件都有效时，表单才会有效。

为了说明`form`元素的用法，让我们定义一个带有选择器`control-errors`的组件，该组件显示给定控件的当前错误。我们可以这样使用它：

```ts
<label class="control-label" for="realNameInput">Real name</label>
<div>
  <input id="realNameInput" class="form-control" type="text"
     ngControl="realName" [(ngModel)]="developer.realName"
         required maxlength="50">
  <control-errors control="realName"
    [errors]="{
      'required': 'Real name is required',
      'maxlength': 'The maximum length of the real name is 50 characters'
      }"
   />
</div>
```

请注意，我们还向`realName`控件添加了`maxlength`验证器。

`control-errors`元素具有以下属性：

+   `control`：声明我们想要显示错误的控件的名称。

+   `errors`：创建控制错误和错误消息之间的映射。

现在在`add_developer.ts`中添加以下导入：

```ts
import {NgControl, NgForm} from 'angular2/common';
import {Host} from 'angular2/core';
```

在这些导入中，`NgControl`类是表示单个表单组件的抽象类，`NgForm`表示 Angular 表单，`Host`是与依赖注入机制相关的参数装饰器，我们已经在第五章中介绍过，*Angular 2 中的依赖注入*。

以下是组件定义的一部分：

```ts
@Component({
  template: '<div>{{currentError}}</div>',
  selector: 'control-errors',
  inputs: ['control', 'errors']
})
class ControlErrors {
  errors: Object;
  control: string;
  constructor(@Host() private formDir: NgForm) {}
  get currentError() {…}
}
```

`ControlErrors`组件定义了两个输入：`control`——使用`ngControl`指令声明的控件的名称（`ngControl`属性的值）——和`errors`——错误和错误消息之间的映射。它们可以分别由`control-errors`元素的`control`和`errors`属性指定。

例如，如果我们有控件：

```ts
<input type="text" ngControl="foobar" required />
```

我们可以通过以下方式声明其关联的`control-errors`组件：

```ts
<control-errors control="foobar"
      [errors]="{
       'required': 'The value of foobar is required'
      }"></control-errors>
```

在上面片段中的`currentError` getter 中，我们需要做以下两件事：

+   找到使用`control`属性声明的组件的引用。

+   返回与使当前控件无效的任何错误相关联的错误消息。

以下是实现此行为的代码片段：

```ts
@Component(…)
class ControlErrors {
  …
  get currentError() {
    let control = this.formDir.controls[this.control];
    let errorsMessages = [];
    if (control && control.touched) {
      errorsMessages = Object.keys(this.errors)
        .map(k => control.hasError(k) ? this.errors[k] : null)
        .filter(error => !!error);
    }
    return errorsMessages.pop();
  }
}
```

在`currentError`的实现的第一行中，我们使用注入表单的`controls`属性获取目标控件。它的类型是`{[key: string]: AbstractControl}`，其中键是我们用`ngControl`指令声明的控件的名称。一旦我们获得了目标控件的实例引用，我们可以检查它的状态是否被触摸（即是否已聚焦），如果是，我们可以循环遍历`ControlError`实例的`errors`属性中的所有错误。`map`函数将返回一个包含错误消息或`null`值的数组。唯一剩下的事情就是过滤掉所有的`null`值，并且只获取错误消息。一旦我们获得了每个错误的错误消息，我们将通过从`errorMessages`数组中弹出它来返回最后一个。

最终结果应如下所示：

![使用 NgForm 指令](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00027.jpeg)

图 5

如果在实现`ControlErrors`组件的过程中遇到任何问题，您可以查看`ch6/ts/multi-page-template-driven/add_developer.ts`中的实现。

每个控件的`hasError`方法接受一个错误消息标识符作为参数，该标识符由验证器定义。例如，在前面定义自定义电子邮件验证器的示例中，当输入控件具有无效值时，我们将返回以下对象字面量：`{ 'invalidEmail': true }`。如果我们将`ControlErrors`组件应用于电子邮件控件，则其声明应如下所示：

```ts
  <control-errors control="email"
    [errors]="{ 'invalidEmail': 'Invalid email address' }"/>
```

# Angular 2 的双向数据绑定

关于 Angular 2 最著名的传言之一是，双向数据绑定功能被移除，因为强制的单向数据流。这并不完全正确；Angular 2 的表单模块实现了一个带有选择器`[(ngModel)]`的指令，它允许我们轻松地实现双向数据绑定——从视图到模型，以及从模型到视图。

让我们来看一个简单的组件：

```ts
// ch6/ts/simple-two-way-data-binding/app.ts

import {Component} from 'angular2/core';
import {bootstrap} from 'angular2/platform/browser';
import {NgModel} from 'angular2/common';

@Component({
  selector: 'app',
  directives: [NgModel],
  template: `
    <input type="text" [(ngModel)]="name"/>
    <div>{{name}}</div>
  `,
})
class App {
  name: string;
}

bootstrap(App, []);
```

在上面的示例中，我们从`angular2/common`包中导入了指令`NgModel`。稍后，在模板中，我们将属性`[(ngModel)]`设置为值`name`。

起初，语法`[(ngModel)]`可能看起来有点不寻常。从第四章*使用 Angular 2 组件和指令入门*中，我们知道语法`(eventName)`用于绑定由给定组件触发的事件（或输出）。另一方面，我们使用语法`[propertyName]="foobar"`通过将属性（或在 Angular 2 组件术语中的输入）的值设置为表达式`foobar`的评估结果来实现单向数据绑定。`NgModel`语法将两者结合起来，以实现双向数据绑定。这就是为什么我们可以将其视为一种语法糖，而不是一个新概念。与 AngularJS 1.x 相比，这种语法的主要优势之一是我们可以通过查看模板来判断哪些绑定是单向的，哪些是双向的。

### 注意

就像`(click)`有其规范语法`on-click`和`[propertyName]`有`bind-propertyName`一样，`[(ngModel)]`的替代语法是`bindon-ngModel`。

如果你打开`http://localhost:5555/dist/dev/ch6/ts/simple-two-way-data-binding/`，你会看到以下结果：

![使用 Angular 2 进行双向数据绑定](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00028.jpeg)

图 6

一旦你改变输入框的值，它将自动更新以下标签。

我们已经在前面的模板中使用了`NgModel`指令。例如，我们绑定了开发人员的电子邮件：

```ts
<input id="emailInput"
       class="form-control" type="text"
       ngControl="email" [(ngModel)]="developer.email"
       email-input/>
```

这样，一旦我们改变文本输入的值，附加到`AddDeveloper`组件实例的开发人员对象的电子邮件属性的值就会被更新。

# 存储表单数据

让我们再次查看`AddDeveloper`组件控制器的接口：

```ts
export class AddDeveloper {
  submitted: false;
  successMessage: string;
  developer = new Developer();
  //…
  constructor(private developers: DeveloperCollection) {}
  addDeveloper(form) {…}
}
```

它有一个`Developer`类型的字段，我们使用`NgModel`指令将表单控件绑定到其属性。该类还有一个名为`addDeveloper`的方法，该方法在表单提交时被调用。我们通过绑定`submit`事件来声明这一点：

```ts
<!-- ch6/ts/multi-page-template-driven/add_developer.html -->
<form #f="form" (ngSubmit)="addDeveloper()"
      class="form col-md-4" [hidden]="submitted">
  …
  <button class="btn btn-default"
      type="submit" [disabled]="!f.form.valid">Add</button>
</form>
```

在上面的片段中，我们可以注意到两件事。我们使用`#f="ngForm"`引用了表单，并将按钮的 disabled 属性绑定到表达式`!f.form.valid`。我们已经在前一节中描述了`NgForm`控件；一旦表单中的所有控件都具有有效值，其 valid 属性将为 true。

现在，假设我们已经为表单中的所有输入控件输入了有效值。这意味着其**submit**按钮将被启用。一旦我们按下*Enter*或点击**Add**按钮，将调用`addDeveloper`方法。以下是此方法的示例实现：

```ts
class AddDeveloper {
  //…
addDeveloper() {
    this.developer.id = this.developers.getAll().length + 1;
    this.developers.addDeveloper(this.developer);
    this.successMessage = `Developer ${this.developer.realName} was successfully added`;
    this.submitted = true;
  }
```

最初，我们将当前开发人员的`id`属性设置为`DeveloperCollection`中开发人员总数加一。稍后，我们将开发人员添加到集合中，并设置`successMessage`属性的值。就在这之后，我们将提交属性设置为`true`，这将导致隐藏表单。

# 列出所有存储的开发人员

现在我们可以向开发人员集合添加新条目了，让我们在“Coders repository”的首页上显示所有开发人员的列表。

打开文件`ch6/ts/step-1/home.ts`并输入以下内容：

```ts
import {Component} from 'angular2/core';
import {DeveloperCollection} from './developer_collection';

@Component({
  selector: 'home',
  templateUrl: './home.html'
})
export class Home {
  constructor(private developers: DeveloperCollection) {}
  getDevelopers() {
    return this.developers.getAll();
  }
}
```

这对我们来说并不新鲜。我们通过提供外部模板并实现`getDevelopers`方法来扩展`Home`组件的功能，该方法将其调用委托给构造函数中注入的`DeveloperCollection`实例。

模板本身也是我们已经熟悉的东西：

```ts
<table class="table" *ngIf="getDevelopers().length > 0">
  <thead>
    <th>Email</th>
    <th>Real name</th>
    <th>Technology</th>
    <th>Popular</th>
  </thead>
  <tr *ngFor="#dev of getDevelopers()">
    <td>{{dev.email}}</td>
    <td>{{dev.realName}}</td>
    <td>{{dev.technology}}</td>
    <td [ngSwitch]="dev.popular">
      <span *ngSwitchWhen="true">Yes</span>
      <span *ngSwitchWhen="false">Not yet</span>
    </td>
  </tr>
</table>
<div *ngIf="getDevelopers().length == 0">
  There are no any developers yet
</div>
```

我们将所有开发人员列为 HTML 表格中的行。对于每个开发人员，我们检查其 popular 标志的状态。如果其值为`true`，那么在**Popular**列中，我们显示一个带有文本`Yes`的 span，否则我们将文本设置为`No`。

当您在**添加开发人员**页面输入了一些开发人员，然后导航到主页时，您应该看到类似以下截图的结果：

![列出所有存储的开发人员](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00029.jpeg)

图 7

### 注意

您可以在`ch6/ts/multi-page-template-driven`找到应用程序的完整功能。

# 摘要

到目前为止，我们已经解释了 Angular 2 中路由的基础知识。我们看了一下如何定义不同的路由，并实现与它们相关的组件，这些组件在路由更改时显示出来。为了链接到不同的路由，我们解释了`routerLink`，并且我们还使用了`router-outlet`指令来指出与各个路由相关的组件应该被渲染的位置。

我们还研究了 Angular 2 表单功能，包括内置和自定义验证。之后，我们解释了`NgModel`指令，它为我们提供了双向数据绑定。

在下一章中，我们将介绍如何开发基于模型的表单和子路由以及参数化路由，使用`Http`模块进行 RESTful 调用，并使用自定义管道转换数据。


# 第七章：解释管道和与 RESTful 服务通信

在上一章中，我们介绍了框架的一些非常强大的功能。然而，我们可以更深入地了解 Angular 的表单模块和路由器的功能。在接下来的章节中，我们将解释如何：

+   开发模型驱动的表单。

+   定义参数化路由。

+   定义子路由。

+   使用`Http`模块与 RESTful API 进行通信。

+   使用自定义管道转换数据。

我们将在扩展“Coders repository”应用程序的功能过程中探索所有这些概念。在上一章的开头，我们提到我们将允许从 GitHub 导入开发者。但在我们实现这个功能之前，让我们扩展表单的功能。

# 在 Angular 2 中开发模型驱动的表单

这些将是完成“Coders repository”最后的步骤。您可以在`ch6/ts/step-1/`（或`ch6/ts/step-2`，具体取决于您之前的工作）的基础上构建，以便使用我们将要介绍的新概念扩展应用程序的功能。完整的示例位于`ch7/ts/multi-page-model-driven`。

这是我们在本节结束时要实现的结果：

![在 Angular 2 中开发模型驱动的表单](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00030.jpeg)

在上面的截图中，有以下两种表单：

+   一个用于从 GitHub 导入现有用户的表单，其中包含：

+   GitHub 句柄的输入。

+   一个指出我们是否要从 GitHub 导入开发者或手动输入的复选框。

+   一个用于手动输入新用户的表单。

第二种形式看起来与我们在上一节中完成的方式完全一样。然而，这一次，它的定义看起来有点不同：

```ts
<form class="form col-md-4"
      [ngFormModel]="addDevForm" [hidden]="submitted">
  <!-- TODO -->
</form>
```

请注意，这一次，我们没有`submit`处理程序或`#f="ngForm"`属性。相反，我们使用`[ngFormModel]`属性来绑定到组件控制器内定义的属性。通过使用这个属性，我们可以绑定到一个叫做`ControlGroup`的东西。正如其名称所示，`ControlGroup`类包括一组控件以及与它们关联的验证规则集。

我们需要使用类似的声明来*导入开发者*表单。然而，这一次，我们将提供不同的`[ngFormModel]`属性值，因为我们将在组件控制器中定义一个不同的控件组。将以下片段放在我们之前介绍的表单上方：

```ts
<form class="form col-md-4"
   [ngFormModel]="importDevForm" [hidden]="submitted">
<!-- TODO -->
</form>
```

现在，让我们在组件的控制器中声明`importDevForm`和`addDevForm`属性：

```ts
import {ControlGroup} from 'angular2/common';
@Component(…)
export class AddDeveloper {
  importDevForm: ControlGroup;
  addDevForm: ControlGroup;
  …
  constructor(private developers: DeveloperCollection,
    fb: FormBuilder) {…}
  addDeveloper() {…}
}
```

最初，我们从`angular2`模块中导入了`ControlGroup`类，然后在控制器中声明了所需的属性。让我们还注意到`AddDeveloper`的构造函数有一个额外的参数叫做`fb`，类型为`FormBuilder`。

`FormBuilder`提供了一个可编程的 API，用于定义`ControlGroups`，在这里我们可以为组中的每个控件附加验证行为。让我们使用`FormBulder`实例来初始化`importDevForm`和`addDevForm`属性：

```ts
…
constructor(private developers: DeveloperCollection,
  fb: FormBuilder) {
  this.importDevForm = fb.group({
    githubHandle: ['', Validators.required],
    fetchFromGitHub: [false]
  });
  this.addDevForm = fb.group({
    realName: ['', Validators.required],
    email: ['', validateEmail],
    technology: ['', Validators.required],
    popular: [false]
  });
}
…
```

`FormBuilder`实例有一个名为`group`的方法，允许我们定义给定表单中各个控件的默认值和验证器等属性。

根据前面的片段，`importDevForm`有两个我们之前介绍的字段：`githubHandle`和`fetchFromGitHub`。我们声明`githubHandle`控件的值是必填的，并将`fetchFromGitHub`控件的默认值设置为`false`。

在第二个表单`addDevForm`中，我们声明了四个控件。对于`realName`控件的默认值，我们将其设置为空字符串，并使用`Validators.requred`来引入验证行为（这正是我们为`githubHandle`控件所做的）。作为电子邮件输入的验证器，我们将使用`validateEmail`函数，并将其初始值设置为空字符串。用于验证的`validateEmail`函数是我们在上一章中定义的：

```ts
function validateEmail(emailControl) {
  if (!emailControl.value ||
     /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(emailControl.value)) {
    return null;
  } else {
    return { 'invalidEmail': true };
  }
}
```

我们在这里定义的最后两个控件是`technology`控件，其值是必填的，初始值为空字符串，以及`popular`控件，其初始值设置为`false`。

## 使用控件验证器的组合

我们看了一下如何将单个验证器应用于表单控件。然而，在一些应用程序中，领域可能需要更复杂的验证逻辑。例如，如果我们想要将必填和`validateEmail`验证器都应用于电子邮件控件，我们应该这样做：

```ts
this.addDevForm = fb.group({
  …
  email: ['', Validators.compose([
    Validators.required,
    validateEmail]
  )],
  …
});
```

`Validators`对象的`compose`方法接受一个验证器数组作为参数，并返回一个新的验证器。新的验证器的行为将是由作为参数传递的各个验证器中定义的逻辑组成，并且它们将按照它们在数组中被引入的顺序应用。

传递给`group`方法的对象文字的属性名称应与我们在模板中为输入设置的`ngControl`属性的值相匹配。

这是`importDevForm`的完整模板：

```ts
<form class="form col-md-4"
   [ngFormModel]="importDevForm" [hidden]="submitted" >
  <div class="form-group">
    <label class="control-label"
           for="githubHandleInput">GitHub handle</label>
    <div>
      <input id="githubHandleInput"
             class="form-control" type="text"
             [disabled]="!fetchFromGitHub" 
             ngControl="githubHandle">
      <control-errors control="githubHandle"
        [errors]="{
          'required': 'The GitHub handle is required'
        }"></control-errors>
    </div>
  </div>
  <div class="form-group">
    <label class="control-label"
           for="fetchFromGitHubCheckbox">
       Fetch from GitHub
    </label>
    <input class="checkbox-inline" id="fetchFromGitHubCheckbox"
           type="checkbox" ngControl="fetchFromGitHub"
           [(ngModel)]="fetchFromGitHub">
  </div>
</form>
```

在前面的模板中，您可以注意到一旦提交的标志具有值`true`，表单将对用户隐藏。在第一个输入元素旁边，我们将`ngControl`属性的值设置为`githubHandle`。

### 注意

请注意，给定输入元素的`ngControl`属性的值必须与我们在组件控制器中的`ControlGroup`定义中用于相应控件声明的名称相匹配。

关于`githubHandle`控件，我们还将`disabled`属性设置为等于表达式评估的结果：`!fetchFromGitHub`。这样，当`fetchFromGitHub`复选框未被选中时，`githubHandle`控件将被禁用。类似地，在前几节的示例中，我们使用了先前定义的`ControlErrors`组件。这次，我们设置了一个带有消息**GitHub 句柄是必需的**的单个错误。

`addDevForm`表单的标记看起来非常相似，因此我们不会在这里详细描述它。如果您对如何开发它的方法不是完全确定，可以查看`ch7/ts/multi-page-model-driven/add_developer.html`中的完整实现。

我们要查看的模板的最后部分是`Submit`按钮：

```ts
<button class="btn btn-default"
        (click)="addDeveloper()"
        [disabled]="(fetchFromGitHub && !importDevForm.valid) ||
                    (!fetchFromGitHub && !addDevForm.valid)">
  Add
</button>
```

单击按钮将调用组件控制器中定义的`addDeveloper`方法。在`[disabled]`属性的值设置为的表达式中，我们最初通过使用与复选框绑定的属性的值来检查选择了哪种表单，也就是说，我们验证用户是否想要添加新开发人员或从 GitHub 导入现有开发人员。如果选择了第一个选项（即，如果复选框未被选中），我们将验证添加新开发人员的`ControlGroup`是否有效。如果有效，则按钮将启用，否则将禁用。当用户选中复选框以从 GitHub 导入开发人员时，我们也会执行相同的操作。

# 探索 Angular 的 HTTP 模块

现在，在我们为导入现有开发人员和添加新开发人员开发表单之后，是时候在组件的控制器中实现其背后的逻辑了。

为此，我们需要与 GitHub API 进行通信。虽然我们可以直接从组件的控制器中进行此操作，但通过这种方式，我们可以将其与 GitHub 的 RESTful API 耦合在一起。为了进一步分离关注点，我们可以将与 GitHub 通信的逻辑提取到一个名为`GitHubGateway`的单独服务中。打开一个名为`github_gateway.ts`的文件，并输入以下内容：

```ts
import {Injectable} from 'angular2/core';
import {Http} from 'angular2/http';

@Injectable()
export class GitHubGateway {
  constructor(private http: Http) {}
  getUser(username: string) {
    return this.http
            .get(`https://api.github.com/users/${username}`);
  }
}
```

最初，我们从`angular2/http`模块导入了`Http`类。所有与 HTTP 相关的功能都是外部化的，并且在 Angular 的核心之外。由于`GitHubGateway`接受一个依赖项，需要通过框架的 DI 机制进行注入，因此我们将其装饰为`@Injectable`装饰器。

我们将要使用的 GitHub 的 API 中唯一的功能是用于获取用户的功能，因此我们将定义一个名为`getUser`的单个方法。作为参数，它接受开发者的 GitHub 句柄。

### 注意

请注意，如果您每天对 GitHub 的 API 发出超过 60 个请求，您可能会收到错误**GitHub API 速率限制已超出**。这是由于没有 GitHub API 令牌的请求的速率限制。有关更多信息，请访问[`github.com/blog/1509-personal-api-tokens`](https://github.com/blog/1509-personal-api-tokens)。

在`getUser`方法中，我们使用了在`constructor`函数中收到的`Http`服务的实例。`Http`服务的 API 尽可能接近 HTML5 fetch API。但是，有一些区别。其中最重要的一个是，在撰写本内容时，`Http`实例的所有方法都返回`Observables`而不是`Promises`。

`Http`服务实例具有以下 API：

+   `request(url: string | Request, options: RequestOptionsArgs)`: 对指定的 URL 进行请求。可以使用`RequestOptionsArgs`配置请求：

```ts
http.request('http://example.com/', {
  method: 'get',
  search: 'foo=bar',
  headers: new Headers({
    'X-Custom-Header': 'Hello'
	})
});
```

+   `get(url: string, options?: RequestOptionsArgs)`: 对指定的 URL 进行 get 请求。可以使用第二个参数配置请求头和其他选项。

+   `post(url: string, options?: RequestOptionsArgs)`: 对指定的 URL 进行 post 请求。可以使用第二个参数配置请求体、头和其他选项。

+   `put(url: string, options?: RequestOptionsArgs)`: 对指定的 URL 进行 put 请求。可以使用第二个参数配置请求头和其他选项。

+   `patch(url: string, options?: RequestOptionsArgs)`: 发送一个 patch 请求到指定的 URL。请求头和其他选项可以使用第二个参数进行配置。

+   `delete(url: string, options?: RequestOptionsArgs)`: 发送一个 delete 请求到指定的 URL。请求头和其他选项可以使用第二个参数进行配置。

+   `head(url: string, options?: RequestOptionsArgs)`: 发送一个 head 请求到指定的 URL。请求头和其他选项可以使用第二个参数进行配置。

## 使用 Angular 的 HTTP 模块

现在，让我们实现从 GitHub 导入现有用户的逻辑！打开文件 `ch6/ts/step-2/add_developer.ts` 并输入以下导入：

```ts
import {Response, HTTP_PROVIDERS} from 'angular2/http';
import {GitHubGateway} from './github_gateway';
```

将 `HTTP_PROVIDERS` 和 `GitHubGateway` 添加到 `AddDeveloper` 组件的提供者列表中：

```ts
@Component({
  …
  providers: [GitHubGateway, FORM_PROVIDERS, HTTP_PROVIDERS]
})
class AddDeveloper {…}
```

作为下一步，我们必须在类的构造函数中包含以下参数：

```ts
constructor(private githubAPI: GitHubGateway,
  private developers: DeveloperCollection,
  fb: FormBuilder) {
  //…
}
```

这样，`AddDeveloper` 类的实例将有一个名为 `githubAPI` 的私有属性。

唯一剩下的就是实现 `addDeveloper` 方法，并允许用户使用 `GitHubGateway` 实例导入现有的开发者。

用户按下 **添加** 按钮后，我们需要检查是否需要导入现有的 GitHub 用户或添加新的开发者。为此，我们可以使用 `fetchFromGitHub` 控件的值：

```ts
if (this.importDevForm.controls['fetchFromGitHub'].value) {
  // Import developer
} else {
  // Add new developer
}
```

如果它有一个真值，那么我们可以调用 `githubAPI` 属性的 `getUser` 方法，并将 `githubHandle` 控件的值作为参数传递：

```ts
this.githubAPI.getUser(model.githubHandle)
```

在 `getUser` 方法中，我们将调用 `Http` 服务的 `get` 方法，该方法返回一个可观察对象。为了获取可观察对象即将推送的结果，我们需要向其 `subscribe` 方法传递一个回调函数：

```ts
this.githubAPI.getUser(model.githubHandle)
  .map((r: Response) => r.json())
  .subscribe((res: any) => {
    // "res" contains the response of the GitHub's API 
  });
```

在上面的代码片段中，我们首先建立了 HTTP `get` 请求。之后，我们将得到一个可观察对象，通常会发出一系列的值（在这种情况下，只有一个值—请求的响应），并将它们映射到它们的主体的 JSON 表示。如果响应失败或其主体不是有效的 JSON 字符串，那么我们将得到一个错误。

### 注意

请注意，为了减小 RxJS 的体积，Angular 的核心团队只包含了它的核心部分。为了使用 `map` 和 `catch` 方法，您需要在 `add_developer.ts` 中添加以下导入：

```ts
**import 'rxjs/add/operator/map';**
**import 'rxjs/add/operator/catch';**

```

现在让我们实现订阅回调的主体：

```ts
let dev = new Developer();
dev.githubHandle = res.login;
dev.email = res.email;
dev.popular = res.followers >= 1000;
dev.realName = res.name;
dev.id = res.id;
dev.avatarUrl = res.avatar_url;
this.developers.addDeveloper(dev);
this.successMessage = `Developer ${dev.githubHandle} successfully imported from GitHub`;
```

在前面的例子中，我们设置了一个新的`Developer`实例的属性。在这里，我们建立了从 GitHub 的 API 返回的对象与我们应用程序中开发者表示之间的映射。我们还认为如果开发者拥有超过 1,000 个粉丝，那么他或她就是受欢迎的。

`addDeveloper`方法的整个实现可以在`ch7/ts/multi-page-model-driven/add_developer.ts`中找到。

### 注意

为了处理失败的请求，我们可以使用可观察实例的`catch`方法：

```ts
 **this.githubAPI.getUser(model.githubHandle)**
 **.catch((error, source, caught) => {**
 **console.log(error)**
 **return error;**
 **})**

```

# 定义参数化视图

作为下一步，让我们为每个开发者专门创建一个页面。在这个页面内，我们将能够详细查看他或她的个人资料。一旦用户在应用程序的主页上点击任何开发者的名称，他或她应该被重定向到一个包含所选开发者详细资料的页面。最终结果将如下所示：

![定义参数化视图](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00031.jpeg)

为了做到这一点，我们需要将开发者的标识符传递给显示开发者详细资料的组件。打开`app.ts`并添加以下导入：

```ts
import {DeveloperDetails} from './developer_details';
```

我们还没有开发`DeveloperDetails`组件，所以如果运行应用程序，你会得到一个错误。我们将在下一段定义组件，但在此之前，让我们修改`App`组件的`@RouteConfig`定义：

```ts
@RouteConfig([
  //…
  new Route({
    component: DeveloperDetails,
    name: 'DeveloperDetails',
    path: '/dev-details/:id/...'
  }),
  //…
])
class App {}
```

我们添加了一个单一路由，与`DeveloperDetails`组件相关联，并且作为别名，我们使用了字符串`"DeveloperDetails"`。

`component`属性的值是对组件构造函数的引用，该构造函数应该处理给定的路由。一旦应用程序的源代码在生产中被压缩，组件名称可能会与我们输入的名称不同。这将在使用`routerLink`指令在模板中引用路由时创建问题。为了防止这种情况发生，核心团队引入了`name`属性，在这种情况下，它等于控制器的名称。

### 注意

尽管到目前为止的所有示例中，我们将路由的别名设置为与组件控制器的名称相同，但这并不是必需的。这个约定是为了简单起见，因为引入两个名称可能会令人困惑：一个用于指向路由，另一个用于与给定路由相关联的控制器。

在`path`属性中，我们声明该路由有一个名为`id`的单个参数，并用`"..."`提示框架，这个路由将在其中有嵌套路由。

现在，让我们将当前开发人员的`id`作为参数传递给`routerLink`指令。在你的工作目录中打开`home.html`，并用以下内容替换我们显示开发人员的`realName`属性的表格单元格：

```ts
<td>
  <a [routerLink]="['/DeveloperDetails',
      { 'id': dev.id }, 'DeveloperBasicInfo']">
    {{dev.realName}}
  </a>
</td>
```

`routerLink`指令的值是一个包含以下三个元素的数组：

+   `'/DeveloperDetails'`：显示根路由的字符串

+   `{ 'id': dev.id }`：声明路由参数的对象文字

+   `'DeveloperBasicInfo'`：显示在组件别名为`DeveloperDetails`的嵌套路由中应该呈现的组件的路由名称

# 定义嵌套路由

现在让我们跳到`DeveloperDetails`的定义。在你的工作目录中，创建一个名为`developer_details.ts`的文件，并输入以下内容：

```ts
import {Component} from 'angular2/core';
import {
  ROUTER_DIRECTIVES,
  RouteConfig,
  RouteParams
} from 'angular2/router';
import {Developer} from './developer';
import {DeveloperCollection} from './developer_collection';

@Component({
  selector: 'dev-details',
  template: `…`,
})
@RouteConfig(…)
export class DeveloperDetails {
  public dev: Developer;
  constructor(routeParams: RouteParams,
    developers: DeveloperCollection) {
    this.dev = developers.getUserById(
      parseInt(routeParams.params['id'])
    );
  }
}
```

在上面的代码片段中，我们定义了一个带有控制器的组件`DeveloperDetails`。您可以注意到，在控制器的构造函数中，通过 Angular 2 的 DI 机制，我们注入了与`RouteParams`令牌相关联的参数。注入的参数为我们提供了访问当前路由可见参数的权限。我们可以使用注入对象的`params`属性访问它们，并使用参数的名称作为键来访问目标参数。

由于我们从`routeParams.params['id']`得到的参数是一个字符串，我们需要将其解析为数字，以便获取与给定路由相关联的开发人员。现在让我们定义与`DeveloperDetails`相关的路由：

```ts
@Component(…)
@RouteConfig([{
    component: DeveloperBasicInfo,
    name: 'DeveloperBasicInfo',
    path: '/'
  },
  {
    component: DeveloperAdvancedInfo,
    name: 'DeveloperAdvancedInfo',
    path: '/dev-details-advanced'
  }])
export class DeveloperDetails {…}
```

在上面的代码片段中，对我们来说没有什么新的。路由定义遵循我们已经熟悉的完全相同的规则。

现在，让我们在组件的模板中添加与各个嵌套路由相关的链接：

```ts
@Component({
  selector: 'dev-details',
  directives: [ROUTER_DIRECTIVES],
  template: `
    <section class="col-md-4">
      <ul class="nav nav-tabs">
        <li>
          <a [routerLink]="['./DeveloperBasicInfo']">
            Basic profile
          </a>
        </li>
        <li>
          <a [routerLink]="['./DeveloperAdvancedInfo']">
            Advanced details
          </a>
        </li>
      </ul>
      <router-outlet/>
    </section>
  `,
})
@RouteConfig(…)
export class DeveloperDetails {…}
```

在模板中，我们声明了两个相对于当前路径的链接。第一个指向`DeveloperBaiscInfo`，这是在`DeveloperDetails`组件的`@RouteConfig`中定义的第一个路由的名称，相应地，第二个指向`DeveloperAdvancedInfo`。

由于这两个组件的实现非常相似，让我们只看一下`DeveloperBasicInfo`。作为练习，您可以开发第二个，或者查看`ch7/ts/multi-page-model-driven/developer_advanced_info.ts`中的实现：

```ts
import {
  Component,
  Inject,
  forwardRef,
  Host
} from 'angular2/core';
import {DeveloperDetails} from './developer_details';
import {Developer} from './developer';

@Component({
  selector: 'dev-details-basic',
  styles: […],
  template: `
    <h2>{{dev.realName}}</h2>
    <img *ngIf="dev.avatarUrl == null"
      class="avatar" src="./gravatar-60-grey.jpg" width="150">
    <img *ngIf="dev.avatarUrl != null"
      class="avatar" [src]="dev.avatarUrl" width="150">
  `
})
export class DeveloperBasicInfo {
  dev: Developer;
  constructor(@Inject(forwardRef(() => DeveloperDetails))
    @Host() parent: DeveloperDetails) {
    this.dev = parent.dev;
  }
}
```

在上述代码片段中，我们结合了`@Inject`参数装饰器和`@Host`来注入父组件。在`@Inject`内部，我们使用`forwardRef`，因为在`developer_basic_info`和`developer_details`之间存在循环依赖（在`developer_basic_info`中，我们导入`developer_details`，而在`developer_details`中，我们导入`developer_basic_info`）。

我们需要一个对父组件实例的引用，以便获取与所选路由对应的当前开发者的实例。

# 使用管道转换数据

现在是 Angular 2 为我们提供的最后一个构建块的时间，这是我们尚未详细介绍的管道。

就像 AngularJS 1.x 中的过滤器一样，管道旨在封装所有数据转换逻辑。让我们来看看我们刚刚开发的应用程序的主页模板：

```ts
…
<td [ngSwitch]="dev.popular">
  <span *ngSwitch-when="true">Yes</span>
  <span *ngSwitch-when="false">Not yet</span>
</td>
…
```

在上述代码片段中，根据`popular`属性的值，我们使用`NgSwitch`和`NgSwitchThen`指令显示了不同的数据。虽然这样可以工作，但是有些冗余。

## 开发无状态管道

让我们开发一个管道，转换`popular`属性的值并在`NgSwitch`和`NgSwitchThen`的位置使用它。该管道将接受三个参数：应该被转换的值，当值为真时应该显示的字符串，以及在值为假时应该显示的另一个字符串。

通过使用 Angular 2 自定义管道，我们将能够简化模板为：

```ts
<td>{{dev.popular | boolean: 'Yes': 'No'}}</td>
```

我们甚至可以使用表情符号：

```
<td>{{dev.popular | boolean: '👍': '👎'}}</td>
```ts

我们将管道应用到值上的方式与在 AngularJS 1.x 中的方式相同。我们传递给管道的参数应该用冒号（`:`）符号分隔。

为了开发一个 Angular 2 管道，我们需要以下导入：

```
import {Pipe, PipeTransform} from 'angular2/core';
```ts

`Pipe`装饰器可用于向实现数据转换逻辑的类添加元数据。`PipeTransform`是一个具有名为 transform 的单个方法的接口：

```
import {Pipe, PipeTransform} from 'angular2/core';

@Pipe({
  name: 'boolean'
})
export class BooleanPipe implements PipeTransform {
  constructor() {}
  transform(flag: boolean, args: string[]): string {
    return flag ? args[0] : args[1];
  }
}
```ts

上述代码片段是`BooleanPipe`的整个实现。管道的名称决定了它在模板中的使用方式。

在能够使用管道之前，我们需要做的最后一件事是将`BooleanPipe`类添加到`Home`组件使用的管道列表中（`BooleanPipe`已经通过`@Pipe`装饰器附加了元数据，所以它的名称已经附加到它上面）：

```
@Component({
  …
  pipes: [BooleanPipe],
})
export class Home {
  constructor(private developers: DeveloperCollection) {}
  getDevelopers() {…}
}
```ts

## 使用 Angular 内置的管道

Angular 2 提供了以下一组内置管道：

+   `CurrencyPipe`：此管道用于格式化货币数据。作为参数，它接受货币类型的缩写（即`"EUR"`，`"USD"`等）。可以按以下方式使用：

```
{{ currencyValue | currency: 'USD' }} <!-- USD42 -->
```ts

+   `DatePipe`：此管道用于日期转换。可以按以下方式使用：

```
{{ dateValue | date: 'shortTime'  }} <!-- 12:00 AM -->
```ts

+   `DecimalPipe`：此管道用于转换十进制数。它接受的参数形式为`"{minIntegerDigits}.{minFractionDigits}-{maxFractionDigits}"`。可以按以下方式使用：

```
{{ 42.1618 | number: '3.1-2' }} <!-- 042.16 -->
```ts

+   `JsonPipe`：这将 JavaScript 对象转换为 JSON 字符串。可以按以下方式使用：

```
{{ { foo: 42 } | json }} <!-- { "foo": 42 } -->
```ts

+   `LowerCasePipe`：将字符串转换为小写。可以按以下方式使用：

```
{{ FOO | lowercase }} <!-- foo -->
```ts

+   `UpperCasePipe`：将字符串转换为大写。可以按以下方式使用：

```
{{ 'foo' | uppercase }} <!-- FOO -->
```ts

+   `PercentPipe`：这将数字转换为百分比。可以按以下方式使用：

```
{{ 42 | percent: '2.1-2' }}  <!-- 4,200.0% -->
```ts

+   `SlicePipe`：返回数组的一个切片。该管道接受切片的起始和结束索引。可以按以下方式使用：

```
{{ [1, 2, 3] | slice: 1: 2 }} <!-- 2 -->
```ts

+   `AsyncPipe`：这是一个`有状态`管道，接受一个 observable 或一个 promise。我们将在本章末尾看一下它。

## 开发有状态的管道

之前提到的所有管道之间有一个共同点——每次将它们应用于相同的值并传递相同的参数集时，它们都会返回完全相同的结果。具有引用透明属性的这种管道称为纯管道。

`@Pipe`装饰器接受以下类型的对象文字：`{ name: string, pure?: boolean }`，其中`pure`属性的默认值为`true`。这意味着当我们使用`@Pipe`装饰器装饰给定的类时，我们可以声明我们希望管道实现的逻辑是有状态的还是无状态的。纯属性很重要，因为如果管道是无状态的（即，对于相同的值和相同的参数集合应用时返回相同的结果），则可以优化变更检测。

现在让我们构建一个有状态的管道！我们的管道将向 JSON API 发出 HTTP `get`请求。为此，我们将使用`angular2/http`模块。

### 注意

请注意，在管道中具有业务逻辑并不被认为是最佳实践。这种类型的逻辑应该被提取到一个服务中。这里的示例仅用于学习目的。

在这种情况下，管道需要根据请求的状态（即是否挂起或已完成）来保持不同的状态。我们将以以下方式使用管道：

```
{{ "http://example.com/user.json" | fetchJson | json }}
```ts

这样，我们就可以在 URL 上应用`fetchJson`管道，一旦我们从远程服务获得响应并且请求的承诺已经解决，我们就可以在响应中得到的对象上应用`json`管道。该示例还展示了如何在 Angular 2 中链式应用管道。

同样，在前面的示例中，为了开发一个无状态的管道，我们需要导入`Pipe`和`PipeTransform`。然而，这次，由于 HTTP 请求功能，我们还需要从`'angular2/http'`模块导入`Http`和`Response`类：

```
import {Pipe, PipeTransform} from 'angular2/core';
import {Http, Response} from 'angular2/http';
import 'rxjs/add/operator/toPromise';
```ts

每当将`fetchJson`管道应用于与上一次调用中获得的参数不同的参数时，我们需要发起新的 HTTP `get`请求。这意味着作为管道的状态，我们至少需要保留远程服务响应的值和最后的 URL：

```
@Pipe({
  name: 'fetchJson',
  pure: false
})
export class FetchJsonPipe implements PipeTransform {
  private data: any;
  private prevUrl: string;
  constructor(private http: Http) {}
  transform(url: string): any {…}
}
```ts

剩下的逻辑只有`transform`方法：

```
…
transform(url: string): any {
  if (this.prevUrl !== url) {
    this.http.get(url).toPromise(Promise)
      .then((data: Response) => data.json())
      .then(result => this.data = result);
    this.prevUrl = url;
  }
  return this.data || {};
}
…
```ts

在其中，我们最初将作为参数传递的 URL 与我们当前保留引用的 URL 进行比较。如果它们不同，我们将使用传递给`constructor`函数的`Http`类的本地实例发起新的 HTTP `get`请求。一旦请求完成，我们将将响应解析为 JSON，并将`data`属性设置为结果。

现在，假设管道已经开始了`Http get`请求，在请求完成之前，变更检测机制再次调用了管道。在这种情况下，我们将比较`prevUrl`属性和`url`参数。如果它们相同，我们将不会执行新的`http`请求，并立即返回`data`属性的值。如果`prevUrl`的值与`url`不同，我们将开始一个新的请求。

## 使用有状态的管道

现在让我们使用我们开发的管道！我们将要实现的应用程序为用户提供了一个文本输入和一个按钮。一旦用户在文本输入中输入一个值并按下按钮，文本输入框下方将显示与 GitHub 用户对应的头像，如下面的屏幕截图所示：

![使用有状态的管道](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00032.jpeg)

现在，让我们开发一个示例组件，允许我们输入 GitHub 用户的句柄：

```
// ch7/ts/statful_pipe/app.ts

@Component({
  selector: 'app',
  providers: [HTTP_PROVIDERS],
  pipes: [FetchJsonPipe, ObjectGetPipe],
  template: `
    <input type="text" #input>
    <button (click)=" setUsername(input.value)">Get Avatar</button>
`
})
class App {
  username: string;
  setUsername(user: string) {
    this.username = user;
  }
}
```ts

在前面的例子中，我们添加了`FetchJsonPipe`用于`App`组件。唯一剩下的就是显示用户的 GitHub 头像。我们可以通过修改前面组件的模板来轻松实现这一点，使用以下`img`声明：

```
<img width="160" [src]="(('https://api.github.com/users/' + username) | fetchJson).avatar_url">
```ts

最初，我们将 GitHub 句柄附加到用于从 API 获取用户的基本 URL 上。后来，我们对其应用了`fetchJson`过滤器，并从返回的结果中得到了`avatar_url`属性。

### 注意

虽然前面的例子可以工作，但在管道中放入业务逻辑是不自然的。最好将与 GitHub API 通信的逻辑实现为一个服务，或者至少在组件中调用`Http`类的实例的`get`方法。

## 使用 Angular 的 AsyncPipe

Angular 的`AsyncPipe`转换方法接受 observable 或 promise 作为参数。一旦参数推送一个值（即 promise 已解析或 observable 的`subscribe`回调被调用并传递了一个值），`AsyncPipe`将返回它作为结果。让我们看看以下例子：

```
// ch7/ts/async-pipe/app.ts
@Component({
  selector: 'greeting',
  template: 'Hello {{ greetingPromise | async }}'
})
class Greeting {
  greetingPromise = new Promise<string>(resolve => this.resolve = resolve);
  resolve: Function;
  constructor() {
    setTimeout(_ => {
      this.resolve('Foobar!');
    }, 3000);
  }
}
```ts

在这里，我们定义了一个 Angular 2 组件，它有两个属性：`greetingPromise`的类型为`Promise<string>`，`resolve`的类型为`Function`。我们用一个新的`Promise<string>`实例初始化了`greetingPromise`属性，并将`resolve`属性的值设置为`promise`的`resolve`回调函数。

在类的构造函数中，我们启动了一个持续 3,000 毫秒的超时，在其回调函数中，我们解析了 promise。一旦 promise 被解析，表达式`{{ greetingPromise | async }}`的值将被评估为字符串`Foobar!`。用户在屏幕上看到的最终结果是文本**Hello Foobar!**。

当我们将`async`管道与`Http`请求或与推送值序列的 observable 结合使用时，`async`管道非常强大。

### 使用 observables 和 AsyncPipe

我们已经熟悉了前几章中的 observables 的概念。我们可以说，observable 对象允许我们订阅一系列值的发射，例如：

```
let observer = new Observable<number>(observer => {
  setInterval(() => {
    observer.next(new Date().getTime());
  }, 1000);
});
observer.subscribe(date => console.log(date));
```ts

一旦我们订阅了可观察对象，它将开始每秒发出值，这些值将被打印在控制台中。让我们将这段代码与组件的定义结合起来，实现一个简单的计时器：

```
// ch7/ts/async-pipe/app.ts
@Component({
  selector: 'timer'
})
class Timer {
  username: string;
  timer: Observable<number>;
  constructor() {
    let counter = 0;
    this.timer = new Observable<number>(observer => {
      setInterval(() => {
        observer.next(new Date().getTime());
      }, 1000);
    });
  }
}
```ts

为了能够使用计时器组件，唯一剩下的事情就是添加它的模板。我们可以通过使用`async`管道直接在我们的模板中订阅可观察对象：

```
{{ timer | async | date: "medium" }}
```

这样，每秒我们将得到可观察对象发出的新值，并且`date`管道将把它转换成可读形式。

# 总结

在本章中，我们深入研究了 Angular 2 表单，通过开发一个模型驱动的表单，并将其与`http`模块结合起来，以便能够将开发人员添加到我们的存储库中。我们看了一些新的基于组件的路由的高级特性，并了解了如何使用和开发我们定制的有状态和无状态管道。

下一章将致力于我们如何使我们的 Angular 2 应用程序对 SEO 友好，通过利用模块 universal 提供的服务器端渲染。我们还将看看 angular-cli 和其他工具，这些工具使我们作为开发人员的体验更好。


# 第八章：开发体验和服务器端渲染

我们已经熟悉了 Angular 2 的所有核心概念。我们知道如何开发基于组件的用户界面，利用框架提供的所有构建模块——指令、组件、依赖注入、管道、表单和全新的基于组件的路由器。

接下来，我们将看看从头开始构建**单页应用程序**（**SPA**）时应该从哪里开始。本章描述了如何执行以下操作：

+   对于性能敏感的应用程序，请使用 Web Workers。

+   使用服务器端渲染构建友好的 SEO 应用程序。

+   尽快启动项目。

+   增强我们作为开发者的体验。

所以，让我们开始吧！

# 在 Web Workers 中运行应用程序

在谈论前端 Web 开发的性能时，我们可以指的是网络、计算或渲染性能。在本节中，我们将集中讨论渲染和计算性能。

首先，让我们将 Web 应用程序和视频，以及浏览器和视频播放器进行对比。在浏览器中运行的 Web 应用程序和视频播放器中播放的视频文件之间最大的区别是，Web 页面需要动态生成，而视频已经被录制、编码和分发。然而，在这两种情况下，应用程序的用户都会看到一系列帧；核心区别在于这些帧是如何生成的。在视频处理领域，当我们播放视频时，视频已经被录制；视频解码器的责任是根据压缩算法提取单个帧。与此相反，在 Web 上，JavaScript 和 CSS 负责生成由浏览器渲染引擎渲染的帧。

在浏览器的上下文中，我们可以将每一帧视为在给定时刻的网页快照。不同的帧快速地一个接一个地渲染，因此理论上，应用程序的最终用户应该看到它们平滑地结合在一起，就像在视频播放器中播放视频一样。

在 Web 上，我们试图达到 60 帧每秒（每秒帧数），这意味着每帧大约有 16 毫秒在屏幕上计算和渲染。这段时间包括浏览器进行布局和页面渲染所需的时间，以及我们的 JavaScript 需要执行的时间。

最后，我们只有不到 16 毫秒的时间（因为浏览器渲染功能需要时间，取决于它需要执行的计算）来完成 JavaScript 的执行。如果超过这个持续时间，帧速率将下降一半。由于 JavaScript 是单线程语言，所有计算都需要在主 UI 线程中进行，这在计算密集型应用程序（如图像或视频处理、大型 JSON 字符串的编组和解组等）的情况下，可能会导致用户体验非常差，因为帧会被丢弃。

HTML5 引入了一个名为**Web Workers**的 API，它允许在浏览器环境中执行客户端代码到多个线程中。简单起见，标准不允许个别线程之间共享内存，而是允许通过消息传递进行通信。Web Workers 和主 UI 线程之间交换的消息必须是字符串，这经常需要对 JSON 字符串进行序列化和反序列化。

个别工作线程之间以及工作线程和主 UI 线程之间缺乏共享内存带来了一些限制，比如：

+   工作线程无法访问 DOM。

+   全局变量不能在个别计算单元（即工作线程和主 UI 线程以及反之）之间共享。

## Web Workers 和 Angular 2

由于 Angular 2 的平台不可知设计，核心团队决定利用这个 API，在 2015 年夏天，谷歌将 Web Workers 支持嵌入到了框架中。这个特性使得大多数 Angular 2 应用程序可以在单独的线程上运行，使得主 UI 线程只负责渲染。这有助于我们更容易地实现 60 帧每秒的目标，而不是在单个线程中运行整个应用程序。

Web Workers 支持默认情况下是未启用的。启用它时，我们需要记住一些事情——在一个准备好使用 Web Workers 的应用程序中，组件不会在主 UI 线程中运行，这不允许我们直接操作 DOM。在这种情况下，我们需要使用绑定，比如输入、输出，以及`NgModel`的组合。

## 在 Web Worker 中引导运行应用程序。

让我们将我们在第四章中开发的待办事项应用程序，在 Web Workers 中运行。您可以在 `ch8/ts/todo_webworkers/` 找到我们将要探索的示例。

首先，让我们讨论需要进行的更改。看一下 `ch4/ts/inputs-outputs/app.ts`。注意，在 `app.ts` 中，我们包含了来自 `angular2/platform/browser` 模块的 `bootstrap` 函数。这是我们需要修改的第一件事！在后台进程中运行的应用程序的 `bootstrap` 过程是不同的。

在重构我们的代码之前，让我们看一下一张图表，说明了在 Web Workers 中运行的典型 Angular 2 应用程序的 `bootstrap` 过程：

![在 Web Worker 中运行应用程序的引导过程](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00033.jpeg)

*Jason Teplitz* 在 *AngularConnect 2015* 上介绍了在 Angular 2 中实现 Web Worker 支持的这张图表。

该图分为两部分：**UI** 和 **Web Worker**。UI 显示了在主 UI 线程初始化期间执行的操作；图表的 **Web Worker** 部分显示了应用程序在后台线程中如何启动。现在，让我们逐步解释 `bootstrap` 过程。

首先，用户打开 `index.html` 页面，触发以下两个文件的下载：

+   用于在 Web Worker 中运行的 Angular 2 的 UI 捆绑包。

+   `system.js` 捆绑包（我们在第三章中讨论了全局对象 System，*TypeScript Crash Course*。我们可以将 `system.js` 捆绑包视为模块加载器的 polyfill）。

使用`system.js`，我们下载了用于初始化在主 UI 线程中运行的应用程序部分的脚本。此脚本在 Web Worker 中启动了`loader.js`。这是在后台线程中运行的第一个脚本。一旦工作线程启动，`loader.js`将下载`system.js`和 Angular 2 的捆绑包，这些捆绑包旨在在后台线程中运行。第一个请求通常会命中缓存，因为主线程已经请求了`system.js`。使用模块加载器，我们下载了负责引导后台应用程序`background_bootstrap.js`的脚本，最终将在后台启动我们应用程序的功能。

从现在开始，我们构建的整个应用程序将在 Web Worker 中运行，并将与主 UI 线程交换消息，以响应用户事件和渲染指令。

现在我们已经了解了在使用工作线程时初始化期间事件的基本流程，让我们重构我们的待办事项应用程序以利用它们。

## 将应用程序迁移到 Web Worker

在`index.html`中，我们需要添加以下脚本：

```ts
  <!-- ch8/ts/todo_webworkers/index.html -->
  …
  <script src="/node_modules/systemjs/dist/system.src.js">
  </script>
  <script src="/node_modules/angular2/bundles/angular2-polyfills.js"></script>
  <script src="/node_modules/angular2/bundles/web_worker/ui.dev.js">
  </script>
  <script>
  System.config({
    baseURL: '/dist/dev/ch8/ts/todo_webworkers/'
  });
  System.import('./bootstrap.js')
    .catch(function () {
      console.log('Report this error to https://github.com/mgechev/switching-to-angular2/issues', e);
    });
  </script>
  …
```

在上述片段中，我们包括了对`system.js`、`angular2-polyfills`（包括`zone.js`）和 Angular 库使用的其他文件的引用，以及需要在主 UI 线程中运行的捆绑包`ui.dev.js`。

在此之后，我们将通过设置模块加载器的`baseURL`属性来配置`system.js`。接下来，我们将显式导入包含用于在 Web Worker 中启动`loader.js`脚本的逻辑的`bootstrap.js`文件。

让我们探索`bootstrap.js`，这是经过转译的`bootstrap.js`的原始文件：

```ts
// ch8/ts/todo_webworkers/bootstrap.ts
import {platform, Provider} from 'angular2/core';
import {
  WORKER_RENDER_APPLICATION,
  WORKER_RENDER_PLATFORM,
  WORKER_SCRIPT
} from 'angular2/platform/worker_render';

platform([WORKER_RENDER_PLATFORM])
  .application([WORKER_RENDER_APPLICATION,
     new Provider(WORKER_SCRIPT, {useValue: 'loader.js'})]);
```

在这个文件中，我们将平台设置为`WORKER_RENDER_PLATFORM`类型，将应用程序类型设置为`WORKER_RENDER_APPLICATION`。我们配置了用于注入`WORKER_SCRIPT`令牌的提供程序，以使用值`'loader.js'`。正如我们所说，`loader.js`将在后台线程中运行。该脚本位于应用程序的根目录中。

现在，我们可以移动到*在 Web Worker 中运行应用程序的引导*部分中给出的图表的右侧。`loader.js`中的逻辑非常简单：

```ts
// ch8/ts/todo_webworkers/loader.ts
importScripts("/node_modules/systemjs/dist/system.src.js",
      "/node_modules/angular2/bundles/web_worker/worker.dev.js",
   "/node_modules/angular2/bundles/angular2-polyfills.js");

System.config({
  baseURL: '/dist/dev/ch8/ts/todo_webworkers/',
});

System.import('./background_app.js')
.then(() => console.log('The application has started successfully'),
  error => console.error('Error loading background', error));
```

作为第一步，我们导入`system.js`，Angular 2 的 Web Workers 捆绑包（`worker.dev.js`）以及所有必需的`polyfills`。然后，我们配置模块加载器的后台实例并导入`background_app`文件，该文件包含我们应用的逻辑以及 Web Workers 的引导调用。

现在，让我们探讨如何在 Web Worker 中引导应用程序：

```ts
import {platform} from 'angular2/core';
import {
  WORKER_APP_PLATFORM,
  WORKER_APP_APPLICATION
} from 'angular2/platform/worker_app';

// Logic for the application…

platform([WORKER_APP_PLATFORM])
  .application([WORKER_APP_APPLICATION])
  .bootstrap(TodoApp);
```

就像在主 UI 线程中引导一样，我们指定平台的类型和我们要引导的应用程序的类型。在最后一步中，我们设置根组件，就像在标准引导过程中所做的那样。`TodoApp`组件在`background_app`文件的导入和初始化调用之间定义。

## 使应用程序与 Web Workers 兼容

正如我们所说，运行在 Web Worker 上下文中的代码无法访问 DOM。让我们看看我们需要做哪些更改来解决这个限制。

这是`InputBox`组件的原始实现：

```ts
// ch4/ts/inputs-outputs/app.ts
@Component({
  selector: 'input-box',
  template: `
    <input #todoInput [placeholder]="inputPlaceholder">
    <button (click)="emitText(todoInput.value);
      todoInput.value = '';">
      {{buttonLabel}}
    </button>
  `
})
class InputBox {
  @Input() inputPlaceholder: string;
  @Input() buttonLabel: string;
  @Output() inputText = new EventEmitter<string>();
  emitText(text: string) {
    this.inputText.emit(text);
  }
}
```

请注意，在模板内部，我们将输入元素命名为`todoInput`并在表达式集中使用它的引用作为单击事件的处理程序。由于我们直接在模板内部访问 DOM 元素，这段代码将无法在 Web Worker 中运行。为了解决这个问题，我们需要重构代码片段，使其使用 Angular 2 绑定而不是直接触摸任何元素。我们可以在单向绑定有意义时使用输入，或者使用`NgModel`来实现双向数据绑定，这需要更多的计算资源。

让我们使用`NgModel`：

```ts
// ch8/ts/todo_webworkers/background_app.ts
import {NgModel} from 'angular2/common';
@Component({
  selector: 'input-box',
  template: `
    <input [placeholder]="inputPlaceholder" [(ngModel)]="input">
    <button (click)="emitText()">
      {{buttonLabel}}
    </button>
  `
})
class InputBox {
  @Input() inputPlaceholder: string;
  @Input() buttonLabel: string;
  @Output() inputText = new EventEmitter<string>();
  input: string;
  emitText() {
    this.inputText.emit(this.input);
    this.input = '';
  }
}
```

在这个版本的`InputBox`组件中，我们将在输入元素和`InputBox`组件的输入属性之间创建双向数据绑定。一旦用户点击按钮，将调用`emitText`方法，这将触发由`inputText EventEmitter`发出的新事件。为了重置输入元素的值，我们利用了我们声明的双向数据绑定，并将输入属性的值设置为空字符串。

### 注意

将组件模板中的整个逻辑移动到它们的控制器中带来了许多好处，比如改进了可测试性、可维护性、代码重用和清晰度。

前面的代码与 Web Workers 环境兼容，因为`NgModel`指令基于一个不直接操作 DOM 的抽象，在幕后与主 UI 线程异步交换消息。

总之，我们可以说，在 Web Workers 的上下文中运行应用程序时，我们需要牢记以下两点：

+   我们需要使用不同的引导过程。

+   我们不应直接访问 DOM。

违反第二点的典型情况如下：

+   通过选择元素并直接使用浏览器的原生 API 或第三方库来操作页面的 DOM。

+   访问使用`ElementRef`注入的原生元素。

+   在模板中创建对元素的引用并将其作为参数传递给方法。

+   直接操作模板中引用的元素。

在所有这些情况下，我们需要使用 Angular 提供的 API。如果我们根据这种做法构建我们的应用程序，我们不仅将从能够在 Web Workers 中运行它们中受益，而且在我们希望在不同平台上使用它们时，还将增加代码重用。

记住这一点将使我们能够利用服务器端渲染。

# 单页应用程序的初始加载

在本节中，我们将探讨服务器端渲染是什么，为什么我们需要在我们的应用程序中使用它，以及我们如何在 Angular 2 中使用它。

对于我们的目的，我们将解释用户打开在 Angular 2 中实现的 SPA 时的典型事件流程。首先，我们将跟踪禁用服务器端渲染时的事件，然后，我们将看到如何通过启用它来从这个功能中受益。我们的示例将在 HTTP 1.1 的上下文中进行说明。

![单页应用程序的初始加载](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00034.jpeg)

这张图片展示了浏览器的第一个请求以及加载典型 SPA 时相应的服务器响应。客户端最初将看到的结果是 HTML 页面的初始内容，没有任何渲染的组件。

假设我们部署了我们在第四章构建的待办事项应用程序到一个具有`https://example.com`域关联的 Web 服务器上。

一旦用户导航到`https://example.com/`，浏览器将打开一个新的 HTTP GET 请求，获取根资源（/）。当服务器收到请求时，它将用一个 HTML 文件作为响应，而在我们的情况下，它将看起来像这样：

```ts
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Switching to Angular 2</title>
  <link rel="stylesheet" href="bootstrap.min.css">
</head>
<body>
  <app>Loading...</app>
  <script src="es6-shim.min.js"></script>
  <script src="Reflect.js"></script>
  <script src="system.src.js"></script>
  <script src="angular2-polyfills.js"></script>
  <script src="Rx.min.js"></script>
  <script src="angular2.js"></script>
  <script src="router.js"></script>
  <script src="http.min.js"></script>
  <script>…</script>
</body>
</html>
```

浏览器将接收此内容作为响应的主体。当标记呈现到屏幕上时，用户将只看到标签：**加载中...**。

接下来，浏览器将查找 HTML 文件中外部资源的所有引用，比如样式和脚本，并开始下载它们。在我们的情况下，其中一些是 bootstrap.css，es6-shim.min.js，Reflect.js，system.src.js 和 angular2-polyfills.js。

一旦所有引用的资源都可用，用户将看不到任何显著的视觉进展（除非已经将下载的 CSS 文件中的样式应用到页面上）。这种情况直到 JavaScript 虚拟机处理了与应用程序实现相关的所有引用脚本之后才会改变。在这一点上，Angular 将根据当前 URL 和引导程序的配置知道需要渲染哪个组件。

如果与页面相关联的组件在我们的主应用程序包之外的单独文件中定义，那么框架将需要下载它以及其整个依赖图。如果组件的模板和样式是外部化的，Angular 还需要下载它们，然后才能渲染请求的页面。

在此之后，框架将能够编译与目标组件相关联的模板并渲染页面。

在先前的情景中，存在以下两个主要问题：

+   搜索引擎不擅长索引 JavaScript 生成的动态内容。这意味着我们的 SPA 的 SEO（搜索引擎优化）将受到影响。

+   在大型应用程序和/或网络连接差的情况下，用户体验将很差。

在过去，我们通过不同的变通方法解决了使用 AngularJS 1.x 构建的应用程序中的 SEO 问题，比如使用无头浏览器来渲染请求的页面，将其缓存到磁盘上，然后提供给搜索引擎。然而，有一个更加优雅的解决方案。

## 使用服务器端渲染的 SPA 的初始加载

几年前，诸如`Rendr`、`Derby`、`Meteor`等库引入了同构 JavaScript 应用程序的概念，后来被重命名为通用应用程序。实质上，通用应用程序可以在客户端和服务器上运行。只有在 SPA 与浏览器 API 之间耦合较低的情况下，才能实现这种可移植性。这种范式的最大好处是应用程序可以在服务器上重新渲染，然后发送到客户端。

通用应用程序不是特定于框架的；我们可以在任何可以在浏览器环境之外运行的框架中利用它们。从概念上讲，服务器端渲染的实践在各个平台和库中都非常相似；只是其实现细节可能有所不同。例如，Angular 2 Universal 模块实现了服务器端渲染，支持 node.js 以及 ASP.NET，在我撰写本文时，后者仍在进行中。

![使用服务器端渲染加载 SPA 的初始加载](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00035.jpeg)

前面的图片显示了服务器对初始浏览器`GET`请求的响应。这一次，与加载 SPA 的典型情景相比，浏览器将获得 HTML 页面的渲染内容。

让我们追踪具有启用服务器端渲染功能的相同应用程序中事件的流程。在这种情况下，一旦服务器接收到浏览器的 HTTP `GET`请求，它将在 node.js 环境中在服务器上运行 SPA。所有的 DOM 调用都将被重定向到服务器端的 DOM 实现，并在所使用的平台的上下文中执行。同样，所有使用`http`模块的 AJAX 调用都将由模块的服务器端实现处理。这样，应用程序无论是在浏览器还是服务器的上下文中运行，都不会有任何区别。

一旦 SPA 的渲染版本可用，就可以将其序列化为 HTML 并发送到浏览器。这一次，在应用程序初始化期间，用户将立即看到他们请求的页面，而不是**加载中...**标签。

请注意，在此时，客户端将拥有应用程序的渲染版本，但所有引用的外部资源，如脚本和样式，仍然需要可用。这意味着最初，外部文件中声明的 CSS 样式将不会应用，并且应用程序将不会对任何与用户相关的交互做出响应，如鼠标和键盘事件。

### 注意

请注意，如果脚本被内联到服务器端渲染的页面中，应用程序将对用户事件做出响应。然而，内联大块的 JavaScript 通常被认为是一种不良实践，因为它会大幅增加页面的大小，并阻止脚本缓存。这两者都会影响网络性能。

当 JavaScript 虚拟机处理与页面相关的 JavaScript 时，我们的 SPA 将准备就绪。

## Angular 2 的服务器端渲染

在 2015 年上半年，Patrick Stapleton 和 Jeff Whelpley 宣布他们开始开发**Universal**模块。Universal 是一个库，允许我们使用 Angular 2 构建通用（也称为**同构**）JavaScript 应用程序；换句话说，它提供了服务器端渲染支持。

使用 Angular 2 和 Universal 构建的应用程序在处理完所请求页面的所有 JavaScript 之前将无法响应。这是一个我们已经提到过的缺点，对所有服务器端渲染的应用程序都适用。然而，Patrick 和 Jeff 引入了**preboot.js**，这是一个轻量级的库，将被内联到服务器渲染的页面中，并在初始客户端请求后可用。

Preboot.js 有几种策略来管理应用程序完全初始化之前接收到的客户端事件。它们如下：

+   记录并回放事件。

+   立即响应事件。

+   在页面重新渲染时保持焦点。

+   缓冲客户端重新渲染以实现更平滑的过渡。

+   如果用户点击按钮，冻结页面直到引导程序完成。

在撰写本文时，Universal 模块仍在积极开发中。但是，您可以尝试使用 Angular 2 通用启动器[`github.com/angular/universal-starter`](https://github.com/angular/universal-starter)。

# 增强我们的开发体验

作为开发人员，我们的经验可以通过提高生产力或允许我们在项目上更有乐趣来增强。这可以通过我们日常使用的所有工具、IDE、文本编辑器等来实现。在本节中，我们将简要介绍一些流行的 IDE 和文本编辑器，以便利用 Angular 2 提供的静态代码分析功能。

在本节的第二部分，我们将看到热重载是什么，以及在开发 Angular 2 应用程序时如何利用它。

## 文本编辑器和 IDE

正如我们在本书开头已经提到的，核心团队在增强 Angular 2 的工具支持方面付出了很大的努力。首先，该框架是用 TypeScript 构建的，这自然地允许我们在开发过程中使用静态类型。一些具有很好 TypeScript 支持的文本编辑器和 IDE 如下：

+   **IntelliJ Idea**：由 JetBrains 开发的通用 IDE。

+   **WebStorm**：JetBrains 专门为 Web 开发开发的 IDE。

+   **VSCode**：一款由微软开发的跨平台文本编辑器，使用 TypeScript 编写。

+   **Sublime Text**：一款跨平台文本编辑器。

+   **Atom**：一款跨平台文本编辑器。

最近，JetBrains 宣布在 IntelliJ Idea 和 WebStorm 中提供了先进的 Angular 2 支持，支持组件和绑定的自动完成。

尽管在撰写本文时，并非所有提到的 IDE 和文本编辑器都具有针对 Angular 2 的支持，但 Angular 2 具有出色的设计。它允许我们对应用程序的代码库进行高级静态代码分析，以便在不久的将来开发复杂的重构和生产工具。在那之前，Angular 2 至少提供了与市场上任何其他 JavaScript 框架一样好的工具支持。

## 热重载

热重载（或热加载）是在纯函数式用户界面的世界中变得流行的一种实践，例如在 ClojureScript 中使用的 Om 和 React 中。

在开发单页应用程序时，每次对样式、视图甚至组件进行小的更改后都需要刷新浏览器是非常恼人的。这就是为什么几年前开发了一个叫做**livereload**的工具。Livereload 监视我们应用程序的文件，当它检测到任何文件的变化时，就会发送消息给浏览器以刷新页面。通常，livereload 服务器和客户端之间建立的连接是通过 WebSockets，因为服务器需要发送推送通知。尽管这个工具在某些情况下效果很好，但它有一个很大的缺点：一旦页面刷新，开发者交互期间收集的所有状态都将丢失。

举例来说，想象一种情况，你正在开发一个视图复杂的应用程序。你浏览了几个页面，填写表单，设置输入字段的值，然后突然发现了一个问题。你去你的文本编辑器或者 IDE 修复了这个问题；livereload 服务器检测到了项目根目录的变化，并发送通知给浏览器以刷新页面。现在，你回到了应用程序的初始状态，需要经过所有这些步骤才能达到刷新之前的同样状态。

与 livereloading 相比，在大多数情况下，热重载可以消除状态丢失。让我们简要看一下它是如何工作的。

热重载的典型实现有两个主要模块：客户端和服务器。与 livereloading 中的服务器相比，热重载服务器不仅监视文件系统的变化，还会获取变化文件的内容并发送给浏览器。一旦浏览器接收到服务器发送的消息，它就可以用新的实现替换之前的实现。之后，受到变化影响的视图可以重新渲染以直观地反映变化。由于应用程序不会丢失其状态，我们可以从已经达到的点继续使用变化后的代码单元的新版本。

不幸的是，并不总是可能使用这种策略动态交换所有组件的实现。如果你更新了保存应用程序状态的代码片段，可能需要手动刷新页面。

### Angular 2 中的热重载

在撰写本文时，有一个可以在*Angular 2 快速入门*部分中使用的 angular2-seed 中测试的 Angular 2 热重载器的工作原型。该项目正在积极开发中，因此在路线图上有很多改进。但它已经提供了核心功能，可以显著简化开发体验。

# 使用 angular-cli 引导项目

在 AngularConnect 2015 期间，Angular 团队的 Brad Green 和 Igor Minar 宣布了`angular-cli`——一个 CLI（命令行界面）工具，用于简化启动和管理 Angular 2 应用程序。对于那些使用过 Ruby on Rails 的人来说，CLI 工具背后的想法可能很熟悉。该工具的基本目的是允许快速引导新项目和搭建新指令、组件、管道和服务。

在撰写本文时，该工具仍处于早期开发阶段，因此我们只会演示其基本用法。

## 使用 angular-cli

为了安装 CLI 工具，请在终端中运行以下命令：

```ts
**npm install -g angular-cli**

```

在此之后，全局的`ng`命令将出现在您的`$PATH`中。要创建一个新的 Angular 2 项目，请使用以下命令：

```ts
# May take a while, depending on your Internet connection
ng new angular-cli-project
cd angular-cli project
ng serve
```

上述命令将执行以下操作：

+   创建一个新的 Angular 2 项目并安装其所有 node.js 依赖项。

+   进入您的项目目录。

+   启动开发 Web 服务器，让您在 Web 浏览器中打开刚创建的应用程序。

要进一步阅读，请查看项目的存储库，位于[`github.com/angular/angular-cli`](https://github.com/angular/angular-cli)。

# Angular 2 快速入门

尽管 Angular 2 CLI 将会是令人惊叹的，但在撰写本文时，它仍处于早期开发阶段。它是构建工具不可知的，这意味着它不提供任何构建系统。幸运的是，社区开发了许多起始项目，可以为我们的下一个 Angular 2 项目提供一个很好的起点。

## Angular 2 seed

如果你喜欢 Gulp 和静态类型，可以尝试 angular2-seed 项目。它托管在 GitHub 上的以下 URL：[`github.com/mgechev/angular2-seed`](https://github.com/mgechev/angular2-seed)。

Angular 2 seed 提供以下关键功能：

+   使用 Gulp 构建的高级、即插即用、易于扩展、模块化和静态类型的构建系统。

+   生产和开发构建。

+   使用 Jasmine 和 Karma 进行示例单元测试。

+   使用 Protractor 进行端到端测试。

+   带有 Livereload 的开发服务器。

+   实验性的热重载支持。

+   遵循应用程序和文件组织的最佳实践。

+   与 TypeScript 相关的类型定义的管理器。

该书中分发的代码基于这个种子项目。

对于 angular2-seed，您需要安装 node.js、npm 和 Git，并且需要运行以下命令列表：

```ts
git clone --depth 1 https://github.com/mgechev/angular2-seed.git
cd angular2-seed
npm install
npm start
```

运行这些命令后，您的浏览器将自动打开种子的主页。在任何 TypeScript 文件发生更改时，代码将自动转译为 JavaScript，并且浏览器将被刷新。

生产构建是可配置的，默认情况下，它会生成一个包含应用程序的缩小版本和所有引用库的单个捆绑包。

## Angular 2 Webpack 起始程序

如果您喜欢使用 Webpack 进行声明性和极简主义构建，您可以使用*angular2-webpack-starter*。这是一个由*AngularClass*开发并托管在 GitHub 上的起始项目。您可以在以下 URL 找到它：[`github.com/AngularClass/angular2-webpack-starter`](https://github.com/AngularClass/angular2-webpack-starter)。

该起始程序提供以下功能：

+   Angular 2 文件和应用程序组织的最佳实践。

+   使用 Webpack 构建系统，用于处理 TypeScript。

+   使用 Jasmine 和 Karma 测试 Angular 2 代码。

+   使用 Istanbul 和 Karma 进行覆盖。

+   使用 Protractor 进行端到端的 Angular 2 代码。

+   带有 Typings 的类型管理器。

为了尝试一下，您需要安装 node.js、npm 和 git，并且需要运行以下命令：

```ts
git clone --depth 1 https://github.com/angularclass/angular2-webpack-starter.git
cd angular2-webpack-starter
npm install
./node_modules/.bin/typings install
npm start
```

# 摘要

我们通过介绍开发 Angular 2 的原因开始了这本书，接着是一个概念概述，让我们对框架为应用程序开发提供的构建块有了一个大致的了解。接下来，我们进行了一个 TypeScript 速成课程，为我们准备了第四章，*开始使用 Angular 2 组件和指令*，在这里我们深入研究了 Angular 的指令、组件和变更检测。

在第五章中，我们解释了 Angular 2 中的依赖注入机制，并看到了我们如何可以通过使用它来管理不同组件之间的关系。接下来的章节向我们解释了如何构建表单和管道，并利用 Angular 2 的基于组件的路由。

通过完成当前章节，我们完成了对这个框架的探索。在撰写本文时，Angular 2 核心背后的设计决策和思想已经稳固并最终确定。尽管这个框架仍然是全新的，但在过去几个月里，它的生态系统已经达到了一个水平，使我们能够开发出生产就绪、高性能、SEO 友好的应用，并且在此基础上，利用静态类型和热重载获得良好的开发体验。
