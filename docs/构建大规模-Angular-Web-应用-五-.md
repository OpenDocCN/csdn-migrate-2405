# 构建大规模 Angular Web 应用（五）

> 原文：[`zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43`](https://zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：创建本地天气 web 应用程序

我们将设计并构建一个简单的使用 Angular 和第三方 web API 的本地天气应用程序，使用迭代式开发方法。您将专注于首先提供价值，同时学习如何使用 Angular、TypeScript、Visual Studio Code、响应式编程和 RxJS 的微妙之处和最佳方式。

在本章中，您将学习以下内容：

+   使用 Waffle 作为连接到 GitHub 的看板进行路线规划

+   制作新的 UI 元素来显示当前天气信息，使用组件和接口。

+   使用 Angular 服务和 HttpClient 从 OpenWeatherMap API 检索数据

+   利用可观察流使用 RxJS 转换数据

本书提供的代码示例需要 Angular 5 和 6\. Angular 5 代码与 Angular 6 兼容。 Angular 6 将在 2019 年 10 月之前得到长期支持。最新版本的代码存储库可以在以下找到：

+   LocalCast 天气，位置：[Github.com/duluca/local-weather-app](https://github.com/duluca/local-weather-app)

+   LemonMart，位置：[Github.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)

# 使用 Waffle 规划功能路线图

在开始编码之前，制定一个粗略的行动计划非常重要，这样您和您的同事或客户就知道您计划执行的路线图。无论您是为自己还是为别人构建应用程序，功能的实时备用库将始终作为在休息之后重返项目时的良好提醒，或作为信息辐射器，防止不断请求状态更新。

在敏捷开发中，您可能已经使用过各种票务系统或工具，例如看板或看板。我的最爱工具是 Waffle.io，[`waffle.io/`](https://waffle.io/)，因为它直接集成了您的 GitHub 存储库的问题，并通过标签跟踪问题的状态。这样，您可以继续使用您选择的工具与您的存储库进行交互，并且轻松地发布信息。在接下来的部分中，您将设置一个 Waffle 项目以实现这个目标。

# 设置一个 Waffle 项目

现在我们将设置我们的 Waffle 项目：

1.  转到 Waffle.io [`waffle.io/`](https://waffle.io/)。

1.  点击登录或免费开始。

1.  选择公共和私有存储库，以允许访问您的所有存储库。

1.  点击创建项目。

1.  搜索本地天气应用程序存储库并选择它。

1.  点击继续。

你将获得两个初始布局模板，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/81040eee-bfed-4822-8449-2037e1cbe44e.png)

Waffle.io 默认的看板布局

对于这个简单的项目，您将选择基本。但是，高级布局演示了如何修改 Waffle 的默认设置，通过添加额外的列，如审查，以便测试人员或产品所有者参与过程。您可以进一步定制任何看板以适应您现有的流程。

1.  选择基本布局并点击创建项目。

1.  您将看到为您创建的新看板。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/ae7f8ef6-e282-4468-a474-71e05feab25b.png)

空的 Waffle 看板

默认情况下，Waffle 将作为看板服务。它允许你将一个任务从一个状态移动到另一个状态。然而，默认视图将显示存储库中存在的所有问题。要将 Waffle 用作 Scrum 板，您需要为 GitHub 里程碑分配问题，这些里程碑将代表迭代。然后，您可以使用过滤功能仅显示来自该里程碑的问题，或者说来自当前迭代。

在 Waffle 上，您可以通过点击 ![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/98c10b6b-b94d-4cca-b7aa-8992281c2ce6.jpg) 比例图标给问题附上故事点。列将自动显示总数和卡片顺序，表示优先级，并且将从一个会话保留到另一个会话。此外，您可以切换到度量视图以获取里程碑燃尽图和吞吐量图表和统计信息。

# 为您的 Local Weather 应用程序创建问题

现在，我们将创建问题的积压，您将使用这些问题来跟踪在实现应用程序设计时的进度。在创建问题时，您应该专注于提供一些价值给用户的功能迭代。您必须克服的技术障碍对您的用户或客户来说没有任何意义。

以下是我们计划在我们的第一个发布版本中构建的功能：

+   显示当前位置的当天天气信息

+   显示当前位置的天气预报信息

+   添加城市搜索功能，使用户可以查看其他城市的天气信息

+   添加一个首选项窗格，用于存储用户的默认城市

+   使用 Angular Material 改善应用程序的用户体验

随意在 Waffle 或 GitHub 上创建问题；无论你喜欢哪种方式都可以。在创建第一个迭代的范围时，我对功能有一些其他想法，所以我只是添加了这些问题，但没有指定给某个人或一个里程碑。我还继续为我打算处理的问题添加了故事点。以下是看起来像的看板，因为我将开始处理第一个故事：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/c0baf628-599c-43ba-92f0-fb70250dff89.png)

板的初始状态快照位于 [`waffle.io/duluca/local-weather-app`](https://waffle.io/duluca/local-weather-app)

最终，Waffle 提供了一个易于使用的 GUI，以便非技术人员可以轻松地与 GitHub 问题进行交互。通过允许非技术人员参与 GitHub 上的开发过程，你可以让 GitHub 成为整个项目的单一信息来源的好处得以发挥。关于功能和问题的问题、答案和讨论都将作为 GitHub 问题的一部分进行跟踪，而不会在电子邮件中丢失。你还可以在 GitHub 上存储维基类型的文档，因此通过在 GitHub 上集中所有与项目相关的信息、数据、对话和工件，你正在极大地简化可能涉及多个需要持续维护、成本高昂的系统的交互。对于私有知识库和本地企业安装，GitHub 的费用非常合理。如果你坚持使用开源，就像我们在本章中所做的那样，所有这些工具都是免费的。

作为一个额外的福利，我在我的知识库 [`github.com/duluca/local-weather-app/wiki`](https://github.com/duluca/local-weather-app/wiki) 上创建了一个初级的维基页面。请注意，你不能在 `README.md` 或维基页面上上传图片。为了解决这个限制，你可以创建一个新的问题，上传图片作为评论，然后复制并粘贴它的 URL 来在 `README.md` 或维基页面上嵌入图片。在示例维基中，我使用了这种技术将线框设计嵌入到页面中。

有了一个明确的路线图，你现在准备开始实施你的应用程序。

# 使用组件和接口来构建 UI 元素

你将利用 Angular 组件、接口和服务以一种解耦、内聚和封装的方式来构建当前天气功能。

Angular 应用的默认起始页位于`app.component.html`。因此，首先要编辑`AppComponent`的模板，使用基本的 HTML 布局应用程序的初始起始体验。

我们现在开始开发 Feature 1：显示当前位置的当天天气信息，所以你可以将 Waffle 中的卡片移动到“进行中”列。

我们将添加一个标题作为`h1`标签，接着是我们应用的标语作为`div`，以及为显示当前天气的地方设置的占位符，如下面的代码块演示的那样：

```ts
src/app/app.component.html
<div style="text-align:center">
  <h1>
  LocalCast Weather
  </h1>
  <div>Your city, your forecast, right now!</div>
  <h2>Current Weather</h2>
  <div>current weather</div>
</div>
```

在这一点上，你应该运行`npm start`，然后在浏览器中导航到`http://localhost:5000`，这样你就可以实时观察到你所做的更改。

# 添加一个 Angular 组件

我们需要显示当前的天气信息，它位于`<div>current weather</div>`的位置。为了实现这一点，你需要构建一个负责显示天气数据的组件。

创建单独组件的原因是一个在**模型-视图-ViewModel**（**MVVM**）设计模式中被规范化的架构最佳实践。你可能之前听说了**模型-视图-控制器**（**MVC**）模式。大部分于 2005 年至 2015 年之间编写的基于 web 的代码都是按照 MVC 模式编写的。MVVM 与 MVC 模式在重要方面有所不同。正如我在 2013 年的 DevPro 文章中所解释的：

[MVVM 的高效实现](https://wiki.example.org/mvvm_implementation) 自然强制实现了良好的关注点分离。业务逻辑与呈现逻辑清晰地分开。因此，当一个视图被开发时，它就会保持开发完成，因为修复一个视图功能中的错误不会影响其他视图。另一方面，如果您有效地使用可视化继承并创建可重用的用户控件，修复一个地方的错误可以解决整个应用程序中的问题。

Angular 提供了 MVVM 的有效实现。

ViewModels 精巧地封装了任何呈现逻辑，并充当模型的专门版本，通过分隔逻辑，使视图代码更简单。视图和 ViewModel 之间的关系很直接，允许将 UI 行为以更自然的方式封装在可重用的用户控件中。

您可以在[`bit.ly/MVVMvsMVC`](http://bit.ly/MVVMvsMVC)上阅读更多关于架构细微差别的内容，包含插图。

接下来，您将使用 Angular CLI 的 `ng generate` 命令创建您的第一个 Angular 组件，其中将包括视图和 ViewModel：

1.  在终端中，执行 `npx ng generate component current-weather`

确保您在`local-weather-app`文件夹下执行 `ng` 命令，而不是在`根`项目文件夹下。另外，注意 `npx ng generate component current-weather` 可以重写为 `ng g c current-weather`。今后，本书将使用简写格式，并期望您必要时在前面加上 `npx`。

1.  观察您的 `app` 文件夹中创建的新文件：

```ts
src/app
├── app.component.css
├── app.component.html
├── app.component.spec.ts
├── app.component.ts
├── app.module.ts
├── current-weather
  ├── current-weather.component.css
  ├── current-weather.component.html
  ├── current-weather.component.spec.ts
  └── current-weather.component.ts
```

一个生成的组件由四个部分组成：

+   `current-weather.component.css` 包含任何特定于组件的 CSS，是一个可选的文件

+   `current-weather.component.html` 包含了定义组件外观和绑定渲染的 HTML 模板，可以被视为与任何使用的 CSS 样式结合起来的视图

+   `current-weather.component.spec.ts` 包含了基于 Jasmine 的单元测试，您可以扩展以测试组件的功能

+   `current-weather.component.ts` 中包含了 `@Component` 装饰器，位于类定义的顶部，它是将 CSS、HTML 和 JavaScript 代码绑定在一起的粘合剂。这个类本身可以被视为 ViewModel，从服务中获取数据并执行必要的转换，以公开视图的合理绑定，如下所示：

```ts
src/app/current-weather/current-weather.component.ts
import { Component, OnInit } from '@angular/core'
@Component({
  selector: 'app-current-weather',
  templateUrl: './current-weather.component.html',
  styleUrls: ['./current-weather.component.css'],
})
export class CurrentWeatherComponent implements OnInit {
  constructor() {}

  ngOnInit() {}
}
```

如果你计划编写的组件很简单，可以使用内联样式和内联模板重写它，以简化代码的结构。

1.  用内联模板和样式更新`CurrentWeatherComponent`：

```ts
src/app/current-weather/current-weather.component.ts import { Component, OnInit } from '@angular/core'

@Component({
  selector: 'app-current-weather',
  template: `
  <p>
    current-weather works!
  </p>
  `,
  styles: ['']
})
export class CurrentWeatherComponent implements OnInit {
constructor() {}

ngOnInit() {}
}
```

当你执行生成命令时，除了创建组件外，命令还将新创建的模块添加到`app.module.ts`，避免了繁琐的组件连接任务：

```ts
src/app/app.module.ts ...
import { CurrentWeatherComponent } from './current-weather/current-weather.component'
...
@NgModule({
declarations: [AppComponent, CurrentWeatherComponent],
...
```

Angular 的引导过程，不可否认，有点复杂。这也是 Angular CLI 存在的主要原因。`index.html`包含一个名为`<app-root>`的元素。当 Angular 开始执行时，首先加载`main.ts`，它配置了用于浏览器的框架并加载应用程序模块。然后应用程序模块加载所有依赖项并在上述的`<app-root>`元素内呈现。在第十二章，*创建一个路由优先的业务应用程序*，当我们构建一个业务应用程序时，我们将创建自己的特性模块以利用 Angular 的可扩展性功能。

现在，我们需要在初始`AppComponent`模板上显示我们的新组件，以便最终用户看到：

1.  将`CurrentWeatherComponent`添加到`AppComponent`中，用`<app-current-weather></app-current-weather>`替换`<div>current weather</div>`：

```ts
src/app/app.component.html
<div style="text-align:center">
<h1>
 LocalCast Weather
 </h1>
 <div>Your city, your forecast, right now!</div>
 <h2>Current Weather</h2>
 <app-current-weather></app-current-weather>
</div>
```

1.  如果一切正常工作，你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/73cfd796-6a00-4c6a-b790-4a736c7fa508.png)

本地天气应用程序的初始渲染

注意浏览器窗口标签中的图标和名称。作为 Web 开发的惯例，在`index.html`文件中，使用应用程序的名称和图标更新`<title>`标签和`favicon.ico`文件，以自定义浏览器标签信息。如果您的网站图标没有更新，请向`href`属性附加一个唯一版本号，例如`href="favicon.ico?v=2"`。因此，您的应用程序将开始看起来像一个真正的 Web 应用程序，而不是一个由 CLI 生成的初学者项目。

# 使用接口定义您的模型

现在，您的`View`和`ViewModel`就位了，您需要定义您的`Model`。如果回顾设计，您将看到组件需要显示：

+   城市

+   国家

+   当前日期

+   当前图片

+   当前温度

+   当前天气描述

首先创建一个表示这个数据结构的接口：

1.  在终端执行`npx ng generate interface ICurrentWeather`

1.  观察一个新生成的名为`icurrent-weather.ts`的文件，其中包含一个空接口定义，看起来像这样：

```ts
src/app/icurrent-weather.ts
export interface ICurrentWeather {
}
```

这不是一个理想的设置，因为我们可能会向我们的应用程序添加许多接口，跟踪各种接口可能会变得繁琐。随着时间的推移，当你将这些接口的具体实现作为类添加时，将有意义地将类和它们的接口放在自己的文件中。

为什么不直接将接口命名为`CurrentWeather`？因为稍后我们可能会创建一个类来实现`CurrentWeather`的一些有趣的行为。接口建立了一个契约，确定了任何实现或扩展接口的类或接口上可用属性的列表。始终意识到您正在使用类还是接口是非常重要的。如果您遵循始终以大写字母 `I` 开头命名接口的最佳实践，您将始终意识到您正在传递的对象的类型。因此，接口被命名为`ICurrentWeather`。

1.  将`icurrent-weather.ts`重命名为`interfaces.ts`

1.  将接口名称的大写进行更正为`ICurrentWeather`

1.  同样，按照以下方式实现接口：

```ts
src/app/interfaces.ts
export interface ICurrentWeather {
  city: string
  country: string
  date: Date
  image: string
  temperature: number
  description: string
}
```

这个接口及其最终的具体表示形式作为一个类是 MVVM 中的模型。到目前为止，我已经强调了 Angular 的各个部分如何符合 MVVM 模式；在接下来，我将用它们的实际名称来指代这些部分。

现在，我们可以将接口导入到组件中，并开始在`CurrentWeatherComponent`模板中连接绑定。

1.  导入`ICurrentWeather`

1.  切换回`templateUrl`和``styleUrls``

1.  定义一个名为 `current` 的本地变量，类型为 `ICurrentWeather`

```ts
src/app/current-weather/current-weather.component.ts import { Component, OnInit } from '@angular/core'
import { ICurrentWeather } from '../interfaces'

@Component({
  selector: 'app-current-weather',
  templateUrl: './current-weather.component.html',
  styleUrls: ['./current-weather.component.css'],
})
export class CurrentWeatherComponent implements OnInit {
  current: ICurrentWeather

  constructor() {}

  ngOnInit() {}
}
```

如果您只键入`current: ICurrentWeather`，您可以使用自动修复程序自动插入导入语句。

在构造函数中，您将用虚拟数据临时填充当前属性以测试绑定。

1.  以 JSON 对象的形式实现虚拟数据，并使用`as`运算符声明它遵循`ICurrentWeather`：

```ts
src/app/current-weather/current-weather.component.ts
...
constructor() {
  this.current = {
    city: 'Bethesda',
    country: 'US',
    date: new Date(),
    image: 'assets/img/sunny.svg',
    temperature: 72,
    description: 'sunny',
  } as ICurrentWeather
}
...
```

在`src/assets`文件夹中，创建一个名为`img`的子文件夹，并放置您选择的图像以在虚拟数据中引用。

您可能会忘记您创建的接口中的确切属性。通过*Ctrl* + 鼠标悬停在接口名称上，您可以快速查看它们，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/e15b7ab5-9e57-4aff-a18d-c38830c6e75a.png)*Ctrl* + 鼠标悬停在接口

现在，您可以更新模板，将您的绑定与基本的基于 HTML 的布局进行连接。

1.  实现模板：

```ts
src/app/current-weather/current-weather.component.html <div>
  <div>
    <span>{{current.city}}, {{current.country}}</span>
    <span>{{current.date | date:'fullDate'}}</span>
  </div>
  <div>
    <img [src]='current.image'>
    <span>{{current.temperature | number:'1.0-0'}}℉</span>
  </div>
  <div>
    {{current.description}}
  </div>
</div>
```

要更改 `current.date` 的显示格式，我们使用了上面的 `DatePipe` ，将`'fullDate'`作为格式选项传入。在 Angular 中，可以使用各种内置和自定义`|`操作符来更改数据的外观，而不改变实际的数据。这是一个非常强大、方便和灵活的系统，可以在不编写重复代码的情况下共享用户界面逻辑。在上面的示例中，如果我们想要以更紧凑的形式表示当前日期，我们可以传入`'shortDate'`。有关各种`DatePipe`选项的更多信息，请参阅[`angular.io/api/common/DatePipe`](https://angular.io/api/common/DatePipe)的文档。要格式化`current.temperature`，以便不显示小数值，您可以使用`DecimalPipe`。文档在[`angular.io/api/common/DecimalPipe`](https://angular.io/api/common/DecimalPipe)中。

请注意，您可以使用其各自的 HTML 代码来呈现℃和℉： ![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b5a76f73-bb93-4f1a-a344-5f20edef7312.png) 代表℃， ![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/a4b2101d-64f9-4302-a885-efa078718e12.png) 代表 ℉。

1.  如果一切正常，您的应用应该看起来类似于该截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b0c66fef-99c4-4b07-b2e6-0040f481527b.png)

绑定到虚拟数据的 App

恭喜，您已成功连接了第一个组件。

# 使用 Angular 服务和 HttpClient 获取数据

现在您需要将您的`CurrentWeather`组件连接到`OpenWeatherMap` APIs。在接下来的章节中，我们将重点介绍以下步骤以实现这个目标：

1.  创建一个新的 Angular 服务

1.  导入 `HttpClientModule` 并将其注入服务中

1.  发现`OpenWeatherMap` API

1.  创建符合 API 结构的新接口

1.  编写一个`get`请求

1.  将新服务注入到`CurrentWeather`组件中

1.  在 `CurrentWeather` 组件的`init`函数中调用该服务

1.  最后，使用 RxJS 函数将 API 数据映射到本地的`ICurrentWeather`类型，以便组件可以使用

# 创建一个新的 Angular 服务

任何超出组件边界的代码应存在于服务中；这包括组件间通信，除非存在父子关系，并且任何类型的 API 调用，以及缓存或从 cookie 或浏览器的 localStorage 中检索数据的任何代码。这是一个在长期内保持您的应用可维护性的重要架构模式。我在我的 DevPro MVVM 文章中详细介绍了这个想法，链接在[`bit.ly/MVVMvsMVC`](http://bit.ly/MVVMvsMVC)。

要创建 Angular 服务，请执行以下操作：

1.  在终端中，执行`npx ng g s weather --flat false`

1.  观察新创建的`weather`文件夹：

```ts
src/app
...
└── weather
   ├── weather.service.spec.ts
   └── weather.service.ts
```

生成的服务有两个部分：

+   `weather.service.spec.ts`包含基于 Jasmine 的单元测试，您可以扩展以测试服务功能。

+   `weather.service.ts`中包含了类定义之前的`@Injectable`装饰器，这使得可以将该服务注入到其他组件中，利用 Angular 的提供者系统。这将确保我们的服务将是单例的，意味着无论它在其他地方被实例化多少次，它都只会被实例化一次。

服务已生成，但并未自动提供。要执行此操作，请按照以下步骤进行：

1.  打开`app.module.ts`

1.  在 providers 数组中输入`WeatherService`

1.  使用自动修复程序为您导入类：

```ts
src/app/app.module.ts
...
import { WeatherService } from './weather/weather.service'
...
@NgModule({
  ...
  providers: [WeatherService],
  ...
```

如果您已安装了推荐的扩展 TypeScript Hero，则导入语句将自动为您添加。您无需使用自动修复程序来执行此操作。接下来，我将不再强调需要导入模块的需要。

# 注入依赖项

为了进行 API 调用，您将使用 Angular 中的`HttpClient`模块。官方文件([`angular.io/guide/http`](https://angular.io/guide/http))简洁地解释了这个模块的好处：

“通过 HttpClient，@angular/common/http 为 Angular 应用程序提供了一个简化的用于 HTTP 功能的 API，构建在浏览器暴露的 XMLHttpRequest 接口之上。HttpClient 的额外好处包括支持可测试性，强类型化的请求和响应对象，请求和响应拦截器支持以及基于可观察对象的更好的错误处理。”

让我们开始导入`HttpClientModule`到我们的应用程序中，以便我们可以在`WeatherService`中注入模块中的`HttpClient`：

1.  在`app.module.ts`中添加`HttpClientModule`，如下所示：

```ts
src/app/app.module.ts
...
import { HttpClientModule } from '@angular/common/http'
...
@NgModule({
  ...
  imports: [
    ...
    HttpClientModule,
    ...
```

1.  注入由`HttpClientModule`提供的`HttpClient`到`WeatherService`，如下所示：

```ts
src/app/weather/weather.service.ts
import { HttpClient } from '@angular/common/http'
import { Injectable } from '@angular/core'

@Injectable()
export class WeatherService {
  constructor(private httpClient: HttpClient) {}
}
```

现在，`httpClient`已经准备好在您的服务中使用。

# 探索 OpenWeatherMap API

由于`httpClient`是强类型的，因此我们需要创建一个符合我们将要调用的 API 形状的新接口。为了能够做到这一点，您需要熟悉当前天气数据 API。

1.  通过导航到[`openweathermap.org/current`](http://openweathermap.org/current)阅读文档：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/771e0150-f856-43e5-9da5-0704544cd618.png)

OpenWeatherMap 当前天气数据 API 文档

您将使用名为“按城市名称”的 API，它允许您通过提供城市名称作为参数来获取当前的天气数据。因此，您的网络请求将如下所示：

```ts
api.openweathermap.org/data/2.5/weather?q={city name},{country code}
```

1.  在文档页面上，点击“API 调用示例”的链接，您将看到以下示例响应：

```ts
http://samples.openweathermap.org/data/2.5/weather?q=London,uk&appid=b1b15e88fa797225412429c1c50c122a1
{
  "coord": {
    "lon": -0.13,
    "lat": 51.51
  },
  "weather": [
    {
      "id": 300,
      "main": "Drizzle",
      "description": "light intensity drizzle",
      "icon": "09d"
    }
  ],
  "base": "stations",
  "main": {
    "temp": 280.32,
    "pressure": 1012,
    "humidity": 81,
    "temp_min": 279.15,
    "temp_max": 281.15
  },
  "visibility": 10000,
  "wind": {
    "speed": 4.1,
    "deg": 80
  },
  "clouds": {
    "all": 90
  },
  "dt": 1485789600,
  "sys": {
    "type": 1,
    "id": 5091,
    "message": 0.0103,
    "country": "GB",
    "sunrise": 1485762037,
    "sunset": 1485794875
  },
  "id": 2643743,
  "name": "London",
  "cod": 200
}
```

鉴于您已经创建的现有`ICurrentWeather`接口，此响应包含的信息比您所需的要多。因此，您将编写一个新的接口，符合此响应的形状，但只指定您将要使用的数据片段。这个接口将只存在于`WeatherService`中，我们不会导出它，因为应用程序的其他部分不需要知道这种类型。

1.  在`weather.service.ts`中的`import`语句和`@Injectable`语句之间创建一个名为`ICurrentWeatherData`的新接口

1.  新接口应该像这样：

```ts
src/app/weather/weather.service.ts
interface ICurrentWeatherData {
  weather: [{
    description: string,
    icon: string
  }],
  main: {
    temp: number
  },
  sys: {
    country: string
  },
  dt: number,
  name: string
}
```

通过`ICurrentWeatherData`接口，我们通过向接口添加具有不同结构的子对象来定义新的匿名类型。这些对象中的每一个都可以被单独提取出来并定义为它们自己的命名接口。特别要注意的是，`weather`将是一个具有`description`和`icon`属性的匿名类型数组。

# 存储环境变量

很容易被忽视的是，之前章节示例的 URL 包含一个必需的`appid`参数。你必须在你的 Angular 应用中存储这个键。你可以将它存储在天气服务中，但实际上，应用程序需要能够在从开发到测试、分段和生产环境的移动过程中针对不同的资源集。Angular 提供了两个环境：一个为`prod`，另一个为默认。

在继续之前，你需要注册一个免费的`OpenWeatherMap`账户并获取自己的`appid`。你可以阅读[`openweathermap.org/appid `](http://openweathermap.org/appid)上`appid`的文档以获取更详细的信息。

1.  复制你的`appid`，它将有一长串字符和数字

1.  将你的`appid`存储在`environment.ts`中

1.  为后续使用配置`baseUrl`：

```ts
src/environments/environment.ts
export const environment = {
  production: false,
  appId: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  baseUrl: 'http://',
}
```

在代码中，我们使用驼峰写法`appId`以保持我们的编码风格一致。由于 URL 参数是大小写不敏感的，`appId`和`appid`都可以使用。

# 实现一个 HTTP GET 操作

现在，我们可以在天气服务中实现 GET 调用：

1.  在`WeatherService`类中添加一个名为`getCurrentWeather`的新函数

1.  导入`environment`对象

1.  实现`httpClient.get`函数

1.  返回 HTTP 调用的结果：

```ts
src/app/weather/weather.service.ts
import { environment } from '../../environments/environment'
...
export class WeatherService {
  constructor(private httpClient: HttpClient) { }

  getCurrentWeather(city: string, country: string) {
    return this.httpClient.get<ICurrentWeatherData>(
        `${environment.baseUrl}api.openweathermap.org/data/2.5/weather?` +
          `q=${city},${country}&appid=${environment.appId}`
    )
  }
}
```

请注意使用 ES2015 的字符串插值功能。不必像`environment.baseUrl + 'api.openweathermap.org/data/2.5/weather?q=' + city + ',' + country + '&appid=' + environment.appId`那样将变量追加到一起来构建字符串，你可以使用反引号语法包裹``你的字符串``。在反引号内，你可以有换行，还可以直接使用`${dollarbracket}`语法将变量嵌入到字符串的流中。但是，在代码中引入换行时，它将被解释为字面换行—`\n`。为了在代码中分割字符串，你可以添加一个反斜杠`\`，但接下来的代码行不能有缩进。如前面的代码示例所示，将多个模板连接起来会更容易些。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

# 当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

1.  当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

1.  当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

```ts
src/app/current-weather/current-weather.component.ts
constructor(private weatherService: WeatherService) { }
```

1.  当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

```ts
src/app/current-weather/current-weather.component.ts
ngOnInit() {
  this.weatherService.getCurrentWeather('Bethesda', 'US')
    .subscribe((data) => this.current = data)
}
```

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

当`CurrentWeather`组件加载时，`ngOnInit`将在第一次触发时，这将调用`getCurrentWeather`函数，该函数返回一个包含`ICurrentWeatherData`类型对象的 Observable。Observable 是一种 RxJS 中最基本的事件监听器构建块，代表事件发射器，它将随着时间的推移接收任何数据类型为`ICurrentWeatherData`的数据。Observable 本身是无害的，除非它被监听。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)中阅读更多关于 Observables 的信息。

通过在 Observable 上调用 `.subscribe`，从本质上说，你将侦听器附加到发射器上。在 `subscribe` 方法中实现了一个匿名函数，每当接收到新的数据并发出事件时，该函数都将被执行。匿名函数以数据对象作为参数，并且在本例中的具体实现中，将数据块分配给了名为 current 的本地变量。每当 current 被更新时，你之前实现的模板绑定将拉取新数据并在视图上渲染。即使 `ngOnInit` 只执行一次，对 Observable 的订阅仍然持续。因此，每当有新数据时，当前变量将被更新，并且视图将重新渲染以显示最新数据。

目前错误的根本原因是正在传送的数据属于 `ICurrentWeatherData` 类型，但是，我们的组件只能理解由 `ICurrentWeather` 接口描述的形式的数据。在下一部分，你需要更深入地了解 RxJS，以便最好地完成这项任务。

注意，VS Code 和 CLI 有时会停止工作。如前所述，在编写代码时，`npm start` 命令正在 VS Code 的集成终端中运行。Angular CLI 与 Angular 语言服务插件一起，不断地监视代码更改，将你的 TypeScript 代码转译成 JavaScript，这样你就能在浏览器中实时查看你的更改。最棒的是，当你出现编码错误时，除了在 VS Code 中的红色下划线外，在终端或者浏览器中也会看到一些红色文字，因为转译失败了。在大多数情况下，在纠正错误后，红色下划线会消失，Angular CLI 会自动重新转译你的代码，一切都会正常工作。然而，在某些情况下，你会发现 VS Code 未能在 IDE 中捕捉到输入更改，所以你将得不到自动补全帮助或者 CLI 工具会卡在消息“webpack：编译失败”上。

你有两种主要策略来从这种情况中恢复：

1.  点击终端，然后按下 *Ctrl* + *C* 停止运行 CLI 任务，并通过执行 `npm start` 重新启动

1.  如果 **#1** 不起作用，用 *Alt* + *F4*（Windows）或 ⌘ + *Q*（macOS）退出 VS Code，然后重新启动它

鉴于 Angular 和 VS Code 每月的发布周期，我相信工具只会不断改进。

# 使用 RxJS 转换数据

RxJS 代表着响应式扩展，这是一个模块化的库，能够实现响应式编程，它本身是一种异步编程范式，并允许通过转换、过滤和控制函数来操纵数据流。你可以将响应式编程看作是事件驱动编程的一种进化。

# 理解响应式编程

在事件驱动编程中，您将定义一个事件处理程序并将其附加到事件源。更具体地说，如果您有一个保存按钮，该按钮公开`onClick`事件，您将实现一个`confirmSave`函数，当触发时，会显示一个弹出窗口询问用户“您确定吗？”。查看以下图示可可视化此过程。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/1958996b-696a-4b00-971d-12e7f8537bf2.png)

事件驱动实现

简而言之，您将有一个事件在每次用户操作时触发。如果用户多次点击保存按钮，此模式将乐意呈现与点击次数相同的弹出窗口，这并没有太多意义。

发布-订阅（pub/sub）模式是一种不同类型的事件驱动编程。在这种情况下，我们可以编写多个处理程序来同时对给定事件的结果进行操作。假设您的应用刚刚收到了一些更新的数据。发布者将遍历其订阅者列表，并将更新的数据传递给每个订阅者。参考以下图表，更新的数据事件如何触发`updateCache`函数，该函数可以使用新数据更新您的本地缓存，`fetchDetails`函数可以从服务器检索有关数据的更多详细信息，并且`showToastMessage`函数可以通知用户应用程序刚刚收到了新数据。所有这些事件都可以异步发生;但是，`fetchDetails`和`showToastMessage`函数将收到比他们实际需要的更多数据，尝试以不同方式组合这些事件以修改应用程序行为可能会变得非常复杂。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3526531c-0a8d-4901-887b-2128cf2c4451.png)

发布-订阅模式实现

在响应式编程中，一切都被视为流。一个流将包含随时间发生的事件，这些事件可以包含一些数据或没有数据。下图可视化了一个场景，您的应用正在监听用户的鼠标点击。不受控的用户点击流是毫无意义的。通过将`throttle`函数应用于它，您可以对此流施加一些控制，以便每 250 **毫秒**（**ms**）仅获得更新。如果订阅此新事件，则每 250 毫秒，您将收到一系列点击事件。您可以尝试从每次点击事件中提取一些数据，但在这种情况下，您只对发生的点击事件数量感兴趣。我们可以使用`map`函数将原始事件数据转化为点击次数。

在下游,我们可能只对带有两个或多个点击的事件感兴趣,所以我们可以使用 `filter` 函数只对本质上是双击事件的事件采取行动。每当我们的过滤器事件触发时,这意味着用户打算双击,你可以根据这个信息弹出一个警告。流的真正力量在于,你可以选择在它通过各种控制、转换和过滤函数时的任何时候采取行动。你可以选择使用 `*ngFor` 和 Angular 的 `async` 管道在 HTML 列表上显示点击数据,这样用户就可以监视每 250 毫秒捕获的点击数据类型。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/c16581a0-78ed-4c3c-87a6-903d7bca41d0.png)

一个响应式数据流实现

# 实现响应式转换

为了避免将来从服务中返回意外类型的数据的错误,你需要更新 `getCurrentWeather` 函数,将返回类型定义为 `Observable<ICurrentWeather>`,并导入 `Observable` 类型,如下所示:

```ts
src/app/weather/weather.service.ts
import { Observable } from 'rxjs'
import { ICurrentWeather } from '../interfaces'
...

export class WeatherService {
  ...
  getCurrentWeather(city: string, country: string): Observable<ICurrentWeather> {
  }
  ...
}
```

现在,VS Code 会告诉你,类型 `Observable<ICurrentWeatherData>` 不可分配给类型 `Observable<ICurrentWeather>`:

1.  编写一个名为 `transformToICurrentWeather` 的转换函数,可以将 `ICurrentWeatherData` 转换为 `ICurrentWeather`

1.  此外,编写一个名为 `convertKelvinToFahrenheit` 的助手函数,将 API 提供的开尔文温度转换为华氏度:

```ts
src/app/weather/weather.service.ts export class WeatherService {...
  private transformToICurrentWeather(data: ICurrentWeatherData): ICurrentWeather {
    return {
      city: data.name,
      country: data.sys.country,
      date: data.dt * 1000,
      image: `http://openweathermap.org/img/w/${data.weather[0].icon}.png`,
      temperature: this.convertKelvinToFahrenheit(data.main.temp),
      description: data.weather[0].description
    }
  }

  private convertKelvinToFahrenheit(kelvin: number): number {
    return kelvin * 9 / 5 - 459.67
  }
}
```

请注意,你需要在此阶段将图标属性转换为图像 URL。在服务中执行此操作有助于保持封装,在视图模板中绑定图标值到 URL 会违反**关注点分离** (**SoC**) 原则。如果你希望创建真正模块化、可重用和可维护的组件,你必须保持警惕并严格执行 SoC。有关天气图标的文档以及如何形成 URL 的详细信息,包括所有可用的图标,可以在 [`openweathermap.org/weather-conditions`](http://openweathermap.org/weather-conditions) 找到。

另一方面,可以论证说,开尔文到华氏温度的转换实际上是一个视图关注点,但我们在服务中实现了它。这个论点是有道理的,特别是考虑到我们计划有一个功能可以在摄氏度和华氏度之间切换。反对的论点是,目前我们只需要以华氏度显示,这是天气服务的一部分,能够转换单位。这个论点也很有道理。最终的实现将是编写一个自定义的 Angular Pipe,并在模板中应用它。一个管道也可以很容易地与计划的切换按钮绑定。但是,现在我们只需要以华氏度显示,我会倾向于*不*过度设计一个解决方案。

1.  将 `ICurrentWeather.date` 更新为 `number` 类型

在编写转换函数时，你会注意到 API 返回的日期是一个数字。这个数字代表自 UNIX 纪元（时间戳）以来的秒数，即 1970 年 1 月 1 日 00:00:00 UTC。然而，`ICurrentWeather`期望一个`Date`对象。通过将时间戳传递给`Date`对象的构造函数`new Date(data.dt)`来转换时间戳非常简单。这没有问题，但也是没必要的，因为 Angular 的`DatePipe`可以直接使用时间戳。在追求简单和最大程度利用我们使用的框架功能的名义上，我们将更新`ICurrentWeather`以使用`number`。如果你正在转换大量数据，这种方法还有性能和内存方面的好处，但这个问题在这里并不适用。这里有一个注意事项—JavaScript 的时间戳是以毫秒为单位的，但服务器的值是以秒为单位的，因此在转换过程中仍然需要简单的乘法运算。

1.  在其他导入语句的下面导入 RxJS 的`map`操作符：

```ts
src/app/weather/weather.service.ts
import { map } from 'rxjs/operators'
```

手动导入 `map` 操作符可能看起来很奇怪。RxJS 是一个功能强大的框架，具有广泛的 API 表面。单独的 Observable 就有超过 200 个附加方法。默认包含所有这些方法会在开发时创建太多的功能选择问题，同时也会对最终交付的大小、应用程序性能和内存使用产生负面影响。因此，你必须单独添加要使用的每个操作符。

1.  在`httpClient.get`方法返回的数据流上应用`map`函数通过一个`pipe`

1.  将`data`对象传递给`transformToICurrentWeather`函数：

```ts
src/app/weather/weather.service.ts
...
return this.httpClient
  .get<ICurrentWeatherData>(
    `http://api.openweathermap.org/data/2.5/weather?q=${city},${country}&appid=${environment.appId}`
  ).pipe(
    map(data => 
      this.transformToICurrentWeather(data)
    )
  )
...
```

现在，当数据进入时，可以在数据流中对其进行转换，确保`OpenWeatherMap`的当前天气 API 数据具有正确的格式，这样可以被`CurrentWeather`组件消费。

1.  确保你的应用程序成功编译

1.  在浏览器中检查结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/9d3b92ed-4580-464f-ba40-4eb4f8b2121d.png)

显示来自 OpenWeatherMap 的实时数据

最后，你应该看到你的应用程序能够从`OpenWeatherMap`中获取实时数据，并正确地将服务器数据转换为你期望的格式。

你已经完成了 Feature 1 的开发：显示当前位置的当天天气信息。提交你的代码并将卡片移到 Waffle 的“已完成”列。

1.  最后，我们可以将这个任务移到完成列：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/fa81e672-d175-49db-a89c-67b6acb67a98.png)

Waffle.io 看板状态

# 总结

恭喜，在这一章中，你创建了你的第一个具有灵活架构的 Angular 应用程序，同时避免了过度设计。这是可能的，因为我们首先建立了一个路线图，并将其编码在一个可见于你的同行和同事的看板中。我们专注于实施我们放在进行中的第一个功能，没有偏离计划。

您现在可以使用 Angular CLI 和优化的 VS Code 开发环境来帮助您减少编码量。您可以利用 TypeScript 匿名类型和可观察流来准确地将复杂的 API 数据重塑为简单的格式，而无需创建一次性接口。

通过主动声明函数的输入和返回类型，并使用通用函数来避免编码错误。您使用了日期和十进制管道来确保数据按预期格式化，同时将与格式相关的问题大部分留在模板中，因为这种逻辑属于模板的范围。

最后，您使用接口在组件和服务之间进行通信，而不会将外部数据结构泄露给内部组件。通过结合应用 Angular、RxJS 和 TypeScript 允许我们执行的所有这些技术，您已确保了关注点的正确分离和封装。因此，`CurrentWeather`组件现在是一个真正可重用和可组合的组件；这不是一件容易的事情。

如果你不发布它，它就永远不会发生。在下一章中，我们将通过解决应用程序错误和使用 Docker 对 Angular 应用程序进行容器化，为其生产发布做准备，以便可以在 web 上发布。


# 第十章：准备 Angular 应用程序进行生产发布

如果你没有上线它，那就好像它从来没有发生过。在前一章中，你创建了一个可以检索当前天气数据的本地天气应用程序。你已经创造了一定的价值；然而，如果你不将你的应用程序上线，最终你将得不到任何价值。交付某物很困难，将其投入生产甚至更加困难。你希望遵循一个能够产生可靠、高质量和灵活发布的策略。

我们在第九章中创建的应用程序，*创建本地天气 Web 应用程序*，比较脆弱。我们需要能够单独交付前端应用程序，而不必与后端应用程序一起处理，这是保持灵活性的重要解耦，以便能够推送独立的应用程序和服务器更新。此外，解耦将确保当应用程序堆栈中的各种工具和技术不可避免地不受支持或不受欢迎时，您将能够替换前端或后端，而无需全面重写系统。

在这一章中，你将学习以下内容：

+   防范空数据

+   使用 Docker 容器化应用程序

+   使用 Zeit Now 将应用程序上线到 Web 上

所需软件列举如下：

+   Docker 社区版版本 17.12

+   Zeit Now 账户

# 在 Angular 中进行空值保护

在 JavaScript 中，`undefined` 和 `null` 值是必须主动处理的持久问题。在 Angular 中，有多种方法可以防范 `null` 值：

1.  属性初始化

1.  安全导航操作符 `?.`

1.  使用 `*ngIf` 进行空值保护

# 属性初始化

在诸如 Java 等静态类型语言中，正确的变量初始化/实例化是无误操作的关键。因此，让我们在 `CurrentWeatherComponent` 中尝试通过使用默认值来初始化当前值：

```ts
src/app/current-weather/current-weather.component.ts
constructor(private weatherService: WeatherService) {
  this.current = {
    city: '',
    country: '',
    date: 0,
    image: '',
    temperature: 0,
    description: '',
  }
}
```

这些更改的结果将将控制台错误从 12 个减少到 3 个，此时您将只看到 API 调用相关的错误。但是，应用程序本身不会处于可展示状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/1f84089f-b267-456c-880f-f229a904a8e2.png)

属性初始化的结果

要使此视图对用户呈现，我们必须对模板上的每个属性编写默认值的代码。因此，通过初始化解决了空保护问题，我们创建了一个默认值处理问题。对于开发人员来说，初始化和默认值处理都是 *O(n)* 规模的任务。在最好的情况下，这种策略将令人厌烦，而在最坏的情况下，效果极差且容易出错，最低要求每个属性的工作量达到 *O(2n)*。

# 安全导航操作符

Angular 实现了安全导航操作 `?.` 以防止意外遍历未定义的对象。因此，我们不需要撰写初始化代码并处理模板数值，而是只需更新模板：

```ts
src/app/current-weather/current-weather.component.html
<div>
  <div>
    <span>{{current?.city}}, {{current?.country}}</span>
    <span>{{current?.date | date:'fullDate'}}</span>
  </div>
  <div>
    <img [src]='current?.image'>
    <span>{{current?.temperature}}℉</span>
  </div>
  <div>
    {{current?.description}}
  </div>
</div>
```

这一次，我们不必设置默认值，让 Angular 处理显示未定义的绑定。你会注意到，就像初始化修复一样，错误从 12 个减少到 3 个。应用本身的状态也稍微好了一些。不再显示混乱的数据；但现在还不是一个可以展示的状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/cf719932-a5c2-4a64-ba10-861ad126010e.png)

安全导航操作符的结果

你可能能想象出在更复杂的情况下安全导航操作符可以派上用场。然而，当规模化部署时，这种类型的编码仍然需要至少*O(n)*级别的工作量来实现。

# 使用*ngIf 进行 null 值保护。

理想策略是使用`*ngIf`，这是一个结构性指令，意味着 Angular 会在假语句之后停止遍历 DOM 树元素。

在`CurrentWeather`组件中，我们可以在尝试渲染模板之前轻松地检查`current`变量是否为 null 或 undefined：

1.  更新顶层的`div`元素，用`*ngIf`来检查`current`是否为对象，如下所示：

```ts
src/app/current-weather/current-weather.component.html <div *ngIf="current">
  ...
</div>
```

现在观察控制台日志，没有错误报告。你必须确保你的 Angular 应用程序不会报告任何控制台错误。如果您仍然在控制台日志中看到错误，请确保已经正确恢复了`OpenWeather`网址到其正确的状态，或者关闭并重新启动`npm start`进程。我强烈建议你在继续之前解决任何控制台错误。一旦您解决了所有错误，请确保再次提交您的代码。

1.  提交你的代码。

# 使用 Docker 容器化应用程序

Docker [docker.io](http://docker.io) 是一个用于开发、部署和运行应用程序的*开放平台*。Docker 结合了*轻量级*的容器虚拟化平台和用于管理和部署应用程序的工作流程和工具。**虚拟机**（**VMs**）和 Docker 容器之间最明显的区别在于，VMs 通常占用数十 GB 的空间并且需要 GB 级别的内存，而容器仅需要 MB 级别的磁盘和内存空间。此外，Docker 平台将主机**操作系统**（**OS**）级别的配置设置抽象掉，所以成功运行应用程序所需的每个配置设置都被编码在易读的 Dockerfile 格式中，如下所示：

```ts
Dockerfile
FROM duluca/minimal-node-web-server:8.11.1
WORKDIR /usr/src/app
COPY dist public
```

前面的文件描述了一个继承自名为`duluca/minimal-node-web-server`的容器的新容器，将工作目录更改为`/usr/src/app`，然后将开发环境中`dist`文件夹的内容复制到容器的`public`文件夹中。在这种情况下，父镜像配置了一个 Express.js 服务器，充当 Web 服务器以提供`public`文件夹中的内容。

参考下图，以可视化表示正在发生的事情：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/e85a11d3-ea47-4e80-804d-ae9267b23407.jpg)

Docker 镜像的上下文

在基础层是我们的宿主操作系统，比如 Windows 或 macOS，运行 Docker 运行时，这将在下一节中安装。Docker 运行时能够运行自包含的 Docker 镜像，这是由上述的`Dockerfile`定义的。`duluca/minimal-node-web-server`基于轻量级的 Linux 操作系统 Alpine。Alpine 是 Linux 的一个完全简化版本，没有任何图形界面、驱动程序，甚至大部分你可能期望从 Linux 系统中获得的 CLI 工具。因此，这个操作系统的大小只有约 5MB。基础包然后安装了 Node.js，这本身的大小约为 10MB，以及我的自定义基于 Node.js 的 Express.js Web 服务器，最终会产生一个小巧的约 15MB 的镜像。Express 服务器被配置为提供`/usr/src/app`文件夹的内容。在前面的`Dockerfile`中，我们只需将我们开发环境中`/dist`文件夹的内容复制并放入`/usr/src/app`文件夹中。我们将稍后构建和执行这个镜像，这将运行我们的 Express Web 服务器，其中包含了我们`dist`文件夹的输出。

Docker 的美妙之处在于，你可以访问[`hub.docker.com`](https://hub.docker.com)，搜索`duluca/minimal-node-web-server`，阅读它的`Dockerfile`，并追溯其起源一直到构成 web 服务器基础的原始基础镜像。我鼓励你以这种方式审核你使用的每个 Docker 镜像，以了解它究竟为你的需求带来了什么。你可能会发现它要么过度复杂，要么具有你之前不知道的功能，可以让你的生活变得更加容易。请注意，父镜像需要特定版本的`duluca/minimal-node-web-server`，在`8.11.1`处。这是完全有意的，作为读者，你应该选择你发现的 Docker 镜像的最新可用版本。然而，如果你不指定版本号，你将总是得到镜像的最新版本。随着镜像的发布更多版本，你可能拉取将来会破坏你的应用程序的某个版本。因此，始终为你依赖的镜像指定版本号。

其中一个例子就是内置了 HTTPS 重定向支持的`duluca/minimal-node-web-server`。你可能会花费无数小时尝试设置一个 Nginx 代理来完成同样的事情，而你只需要在你的 Dockerfile 中添加以下行即可：

```ts
ENV ENFORCE_HTTPS=xProto
```

就像 npm 包一样，Docker 可以带来极大的便利和价值，但你必须小心，了解你正在使用的工具。

在第十六章中，*AWS 上的高可用云基础设施*，我们提到了基于 Nginx 的低占用资源的 docker 镜像的使用。如果你熟悉配置`nginx`，你可以以`duluca/minimal-nginx-web-server`作为你的基础镜像。

# 安装 Docker

为了能够构建和运行容器，你必须首先在你的计算机上安装 Docker 执行环境。

Docker 在 Windows 上的支持可能会有挑战。您必须拥有支持虚拟化扩展的 CPU 的 PC，这在笔记本电脑上并非一定能保证。您还必须拥有启用了 Hyper-V 的 Pro 版 Windows。另一方面，Windows Server 2016 对 Docker 有原生支持，这是微软对业界采用 Docker 和容器化所展现的空前支持。

1.  通过执行以下命令安装 Docker：

对于 Windows：

```ts
PS> choco install docker docker-for-windows -y

```

对于 macOS：

```ts
$ brew install docker
```

1.  执行 `docker -v` 来验证安装。

# 设置 Docker 脚本

现在，让我们配置一些 Docker 脚本，您可以用来自动构建、测试和发布您的容器。我开发了一套名为**npm Scripts for Docker** 的脚本，适用于 Windows 10 和 macOS。您可以在 [bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker) 获取这些脚本的最新版本：

1.  在 [`hub.docker.com/`](https://hub.docker.com/) 上注册一个 Docker Hub 帐户

1.  为您的应用程序创建一个公共（免费）仓库

不幸的是，在出版时，Zeit 不支持私有 Docker Hub 仓库，因此您的唯一选择是公开发布您的容器。如果您的图像必须保持私有，我建议您按照《第十六章》《AWS 上的高可用云基础设施》中描述的方式设置 AWS ECS 环境。您可以通过访问 Zeit Now 的文档 [zeit.co/docs/deployment-types/docker](https://zeit.co/docs/deployment-types/docker) 了解问题的情况。

1.  更新 `package.json` 以添加一个新的配置属性，具有以下配置属性：

```ts
package.json
  ...
  "config": {
    "imageRepo": "[namespace]/[repository]",
    "imageName": "custom_app_name",
    "imagePort": "0000"
  },
 ...
```

命名空间将是您的 DockerHub 用户名。您在创建过程中将定义您的仓库名称。例如，一个示例图像仓库变量应如下所示 `duluca/localcast-weather`。图像名称用于轻松识别您的容器，同时使用类似于 `docker ps` 的 Docker 命令。我将自己的命名为 `localcast-weather`。端口将定义从容器内部公开您的应用程序应使用的端口。因为我们在开发中使用 `5000`，请选择一个不同的端口，比如 `8080`。

1.  通过复制粘贴从 [bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker) 中获取的脚本，向 `package.json` 中添加 Docker 脚本。以下是脚本的注释版本，解释了每个函数：

注意，使用 npm 脚本时，`pre` 和 `post` 关键词用于在给定脚本的执行之前或之后，分别执行辅助脚本。脚本故意被分解为更小的部分，以使其更易于阅读和维护：

```ts
package.json
...
  "scripts": {
    ...
    "predocker:build": "npm run build",
    "docker:build": "cross-conf-env docker image build . -t $npm_package_config_imageRepo:$npm_package_version",
    "postdocker:build": "npm run docker:tag",
    ...
```

运行 `npm run docker:build` 将在 `pre` 中构建您的 Angular 应用程序，然后使用 `docker image build` 命令构建 Docker 镜像，并在 `post` 中为镜像打上版本号：

```ts
package.json
    ...
    "docker:tag": " cross-conf-env docker image tag $npm_package_config_imageRepo:$npm_package_version $npm_package_config_imageRepo:latest",
    ...
```

`npm run docker:tag`将使用`package.json`中的`version`属性的版本号和`latest`标签对已构建的 Docker 镜像进行标记：

```ts
package.json
    ...
    "docker:run": "run-s -c docker:clean docker:runHelper",
    "docker:runHelper": "cross-conf-env docker run -e NODE_ENV=local --name $npm_package_config_imageName -d -p $npm_package_config_imagePort:3000 $npm_package_config_imageRepo",
    ...
```

`npm run docker:run`将删除先前版本的镜像，并使用`docker run`命令运行已构建的镜像。请注意，`imagePort`属性将作为 Docker 镜像的外部端口，映射到 Node.js 服务器监听的镜像的内部端口`3000`：

```ts
package.json
    ...
    "predocker:publish": "echo Attention! Ensure `docker login` is correct.",
    "docker:publish": "cross-conf-env docker image push $npm_package_config_imageRepo:$npm_package_version",
    "postdocker:publish": "cross-conf-env docker image push $npm_package_config_imageRepo:latest",
    ...
```

`npm run docker:publish`将发布构建的镜像到配置的存储库，这种情况下是 Docker Hub，使用`docker image push`命令。首先发布带版本号的镜像，然后发布标记为`latest`的镜像。

```ts
package.json
    ...
    "docker:clean": "cross-conf-env docker rm -f $npm_package_config_imageName",
    ...
```

`npm run docker:clean`将从您的系统中删除先前构建的镜像版本，使用`docker rm -f`命令：

```ts
package.json
    ...
    "docker:taillogs": "cross-conf-env docker logs -f $npm_package_config_imageName",
    ...
```

`npm run docker:taillogs`会使用`docker log -f`命令显示运行中 Docker 实例的内部控制台日志，这是调试 Docker 实例时非常有用的工具：

```ts
package.json
    ...
    "docker:open:win": "echo Trying to launch on Windows && timeout 2 && start http://localhost:%npm_package_config_imagePort%",
    "docker:open:mac": "echo Trying to launch on MacOS && sleep 2 && URL=http://localhost:$npm_package_config_imagePort && open $URL",
    ...
```

`npm run docker:open:win`或`npm run docker:open:mac`将等待 2 秒，然后使用`imagePort`属性以正确的 URL 启动浏览器访问您的应用程序：

```ts
package.json
    ...
    "predocker:debug": "run-s docker:build docker:run",
    "docker:debug": "run-s -cs docker:open:win docker:open:mac docker:taillogs"
  },
...
```

`npm run docker:debug`将构建您的镜像，并在`pre`中运行它的一个实例，打开浏览器，然后开始显示容器的内部日志。

1.  安装两个开发依赖项，以确保脚本的跨平台功能：

```ts
$ npm i -D cross-conf-env npm-run-all
```

1.  在构建镜像之前，自定义预构建脚本以执行单元测试和 e2e 测试：

```ts
package.json
"predocker:build": "npm run build -- --prod --output-path dist && npm test -- --watch=false && npm run e2e",
```

请注意，`npm run build --prod`提供了`--prod`参数，实现了两件事情：

1. 开发时间的 2.5 MB 负载被优化到~73kb 或更少

2. 在运行时使用`src/environments/environment.prod.ts`中定义的配置项

1.  更新`src/environments/environment.prod.ts`以使用来自`OpenWeather`的自己的`appId`：

```ts
export const environment = {
  production: true,
  appId: '01ffxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  baseUrl: 'https://',
}
```

我们正在修改`npm test`的执行方式，以便测试只运行一次，工具停止执行。提供`--watch=false`选项以实现这种行为，与默认的开发友好的持续执行行为相反。此外，提供了`npm run build --output-path dist`，以确保`index.html`发布在文件夹的根目录。

1.  创建一个名为`Dockerfile`的新文件，没有任何文件扩展名

1.  实现如下`Dockerfile`：

```ts
Dockerfile
FROM duluca/minimal-node-web-server:8.11.1
WORKDIR /usr/src/app
COPY dist public
```

确保检查`dist`文件夹的内容。确保`index.html`位于`dist`的根目录。否则，请确保您的`Dockerfile`将包含具有`index.html`的文件夹复制到其根目录。

1.  执行`npm run predocker:build`以确保您的应用程序更改已成功

1.  执行`npm run docker:build`以确保您的镜像成功构建

虽然您可以单独运行提供的任何脚本，但实际上只需要记住其中两个：

+   **npm run docker:debug**会测试，构建，标记，运行，在新的浏览器窗口中为测试启动你的容器化应用程序

+   **npm run docker:publish**将会把你刚才构建并测试的镜像发布到在线 Docker 仓库

1.  在你的终端中执行`docker:debug`:

```ts
$ npm run docker:debug
```

你会注意到脚本在终端窗口显示错误。这些不一定是失败的指标。脚本还不够完善，因此它们同时尝试 Windows 和 macOS 兼容的脚本，并且在第一次构建时，清理命令会失败，因为没有需要清理的东西。等你看到这段话的时候，我可能已经发布了更好的脚本；如果没有，你可以随时提交合并请求。

成功的`docker:debug`运行会在焦点浏览器窗口中显示你的应用程序，并在终端中显示服务器日志，如下所示：

```ts
Current Environment: local.
Server listening on port 3000 inside the container
Attenion: To access server, use http://localhost:EXTERNAL_PORT
EXTERNAL_PORT is specified with 'docker run -p EXTERNAL_PORT:3000'. See 'package.json->imagePort' for th
e default port.
GET / 304 12.402 ms - -
GET /styles.d41d8cd98f00b204e980.bundle.css 304 1.280 ms - -
GET /inline.202587da3544bd761c81.bundle.js 304 11.117 ms - -
GET /polyfills.67d068662b88f84493d2.bundle.js 304 9.269 ms - -
GET /vendor.c0dc0caeb147ad273979.bundle.js 304 2.588 ms - -
GET /main.9e7f6c5fdb72bb69bb94.bundle.js 304 3.712 ms - -
```

你应该经常运行`docker ps`来检查你的镜像是否在运行，上次更新时间，或者它是否与现有镜像发生端口冲突。

1.  在你的终端中执行 `docker:publish` :

```ts
$ npm run docker:publish
```

你应该在终端窗口中看到类似这样的成功运行信息：

```ts
The push refers to a repository [docker.io/duluca/localcast-weather]
60f66aaaaa50: Pushed
...
latest: digest: sha256:b680970d76769cf12cc48f37391d8a542fe226b66d9a6f8a7ac81ad77be4f58b size: 2827
```

随着时间的推移，你本地的 Docker 缓存可能会增长到相当大的规模，在我笔记本上大约是两年时间内增长了大约 40 GB。你可以使用 `docker image prune` 和 `docker container prune` 命令来减小缓存的大小。更详细的信息，请参考[`docs.docker.com/config/pruning`](https://docs.docker.com/config/pruning)的文档。

接下来让我们看一种更简单的与 Docker 进行交互的方式。

# VS Code 中的 Docker 扩展

与 Docker 镜像和容器进行交互的另一种方式是通过 VS Code。如果你按照第九章*，创建本地天气 Web 应用程序*中建议的安装了`PeterJausovec.vscode-docker` Docker 扩展，你会在 VS Code 的资源管理器窗格中看到一个名为 DOCKER 的可展开标题，如下截图所示所指出的部分:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/40d5e5e1-2f87-4b8e-af8a-fccc3466b3c1.png)

VS Code 中的 Docker 扩展

让我们来看看该扩展提供的一些功能:

1.  **Images**包含系统上存在的所有容器快照的列表

1.  在 Docker 镜像上右键单击会弹出上下文菜单，以运行各种操作，比如 run，push 和 tag

1.  **Containers**列出了系统上所有存在的可执行 Docker 容器，你可以启动、停止或连接到它们

1.  **Registries**显示你配置的连接到的注册表，比如 DockerHub 或 AWS Elastic Container Registry

虽然该扩展使与 Docker 进行交互更容易，但**用于 Docker 的 npm 脚本**可以自动化许多与构建、标记和测试镜像相关的琐事。它们是跨平台的，而且在持续集成环境中同样有效。

通过 CLI 与 npm 脚本进行交互可能会让你感到困惑。接下来让我们看一下 VS Code 的 npm 脚本支持。

# VS Code 中的 NPM 脚本

VS Code 提供了对 npm 脚本的支持。 为了启用 npm 脚本资源管理器，打开 VS Code 设置，并确保存在 `"npm.enableScriptExplorer": true` 属性。 一旦你这样做，你将在资源管理器窗格中看到一个可扩展的名称为 NPM SCRIPTS 的标题，如下箭头所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/86f456ab-00f5-4eed-aff6-74117f03454c.png)

VS Code 中的 NPM 脚本

您可以单击任何脚本来启动包含脚本的 `package.json` 文件中的行，或者右键单击并选择运行以执行脚本。

# 部署容器化应用

如果从编码角度交付产品很困难，那么从基础设施角度来看，做到正确更是极其困难。 在后面的章节中，我将讨论如何为您的应用程序提供世界一流的 AWS **弹性容器服务**（**ECS**）基础设施，但如果您需要快速展示一个想法，这是没有帮助的。 这就是 Zeit Now 的作用。

# Zeit Now

Zeit Now，[`zeit.co/now`](https://zeit.co/now)，是一个多云服务，可以直接从 CLI 实现应用程序的实时全球部署。 Now 适用于正确实现 `package.json` 或 `Dockerfile` 的应用程序。 即使我们两者都做了，我们仍然更喜欢部署我们的 Docker image，因为在幕后会应用更多的魔法来使 `package.json` 的部署工作，而您的 Docker image 可以部署到任何地方，包括 AWS ECS。

# 配置 Now CLI 工具

现在，让我们配置 Zeit Now 在您的存储库上运行：

1.  通过执行`npm i -g now`安装 Zeit Now

1.  通过执行 `now -v` 确保正确安装

1.  在 `local-weather-app` 下创建一个名为 `now` 的新文件夹

1.  在新的 `now` 文件夹下创建一个新的 `Dockerfile`

1.  实现从您刚刚发布的镜像中提取文件：

```ts
now/Dockerfile
FROM duluca/localcast-weather:6.0.1
```

1.  最后，在您的终端中执行 `now` 命令并按照说明完成配置：

```ts
$ now
> No existing credentials found. Please log in:
> We sent an email to xxxxxxxx@gmail.com. Please follow the steps provided
 inside it and make sure the security code matches XXX XXXXX.
√ Email confirmed
√ Fetched your personal details
> Ready! Authentication token and personal details saved in "~\.now"
```

# 部署

在 Zeit Now 上部署非常容易：

1.  将工作目录更改为 `now` 并执行命令： 

```ts
$ now --docker --public
```

1.  在终端窗口中，该工具将报告其进度和您可以访问您现在发布的应用程序的 URL：

```ts
> Deploying C:\dev\local-weather-app\web-app\now under duluca
> Ready! https://xxxxxxxxxxxxx.now.sh [3s]
> Initializing...
> Building
> ▲ docker build
Sending build context to Docker daemon 2.048 kBkB
> Step 1 : FROM duluca/localcast-weather
> latest: Pulling from duluca/localcast-weather
...
> Deployment complete!
```

1.  导航到第二行列出的 URL 并验证您的应用程序的发布。

请注意，如果您在配置过程中出现错误，您的浏览器可能会显示一个错误，指示此页面正在尝试加载不安全的脚本，请允许并重新加载以查看您的应用程序。

您可以探索 Zeit Now 的付费功能，这些功能允许为您的应用程序提供高级功能，例如自动缩放。

恭喜，您的应用程序已经在互联网上启动了！

# 总结

在本章中，你学会了如何通过防范空数据来最好地避免 Angular 控制台错误。你已经配置好系统以便与 Docker 协同工作，并成功地将你的 Web 应用程序与专用的 Web 服务器容器化。你还为 Docker 配置了项目并利用了 npm 脚本，这些脚本可以被任何团队成员利用。最后，你成功地将 Web 应用程序交付到了云端。

现在你知道如何构建一个可靠、弹性、并且容器化的生产就绪 Angular 应用程序，以允许灵活的部署策略。在下一章中，我们将改善应用程序的功能集，并使用 Angular Material 使其看起来更加出色。


# 第十一章：使用 Angular Material 增强 Angular 应用

在第十章*，为生产发布准备 Angular 应用*中，我们提到需要提供高质量的应用程序。目前，这个应用程序看起来和感觉都很糟糕，仿佛只适用于上个世纪 90 年代末创建的网站。用户或客户对你的产品或工作的第一印象非常重要，所以我们必须创建一个外观出色、并且在移动和桌面浏览器中提供出色用户体验的应用程序。

作为全栈开发人员，很难专注于你的应用程序的完善。当应用程序的功能集迅速增长时，情况会变得更糟。在匆忙中使用 CSS hack 和内联样式，从而改善你的应用程序，这样做将会使你不再写出优质模块化的代码支持视图，而是沦为一名伟大的代码写手。

Angular Material 是与 Angular 紧密协作开发的惊人库。如果你学会如何有效地利用 Angular Material，你创建的功能将会从一开始就看起来和操作起来非常棒，无论你是在开发小型还是大型应用程序。Angular Material 会使你成为一名更加高效的网页开发人员，因为它附带了各种用户控件，你可以利用它们，而且你不必担心浏览器兼容性。作为额外的奖励，编写自定义 CSS 将变得十分罕见。

在本章中，你将学到以下内容：

+   如何配置 Angular Material

+   使用 Angular Material 升级 UX

# 将 Material 组件添加到你的应用中

现在我们已经安装了各种依赖项，我们可以开始修改我们的 Angular 应用，以添加 Material 组件。我们将添加一个工具栏、Material 设计卡片元素，并涵盖基本布局技术，以及辅助功能和排版方面的问题。

# Angular Material 的生成器原理图

随着 Angular 6 和引入原理图的推出，像 Material 这样的库可以提供自己的代码生成器。目前，Angular Material 随附三个基本生成器，用于创建带有侧边导航、仪表板布局或数据表的 Angular 组件。你可以在[`material.angular.io/guide/schematics`](https://material.angular.io/guide/schematics)了解更多关于生成器原理图的信息。

比如，你可以通过执行以下操作创建一个侧边导航布局：

```ts
$ ng generate @angular/material:material-nav --name=side-nav 

CREATE src/app/side-nav/side-nav.component.css (110 bytes)
CREATE src/app/side-nav/side-nav.component.html (945 bytes)
CREATE src/app/side-nav/side-nav.component.spec.ts (619 bytes)
CREATE src/app/side-nav/side-nav.component.ts (489 bytes)
UPDATE src/app/app.module.ts (882 bytes)
```

此命令会更新`app.module.ts`，直接在该文件中导入 Material 模块，打破了我之前提出的`material.module.ts`的模式。此外，一个新的`SideNavComponent`被添加到应用程序作为一个单独的组件，但如同在第十四章中的*侧边导航*部分中所提到的，*设计验证和授权*，这样的导航体验需要在你的应用程序的非常根本部分实现。

简而言之，Angular Material Schematics 承诺使向 Angular 应用程序添加各种 Material 模块和组件变得更加轻松；然而，就提供的功能而言，这些模式并不适合创建本书追求的灵活、可扩展和良好架构的代码库。

目前，我建议将这些模式用于快速原型设计或实验目的。

现在，让我们开始手动向 LocalCast Weather 添加一些组件。

# 使用 Material 工具栏修改着陆页

在我们开始对`app.component.ts`进行进一步更改之前，让我们将组件切换为使用内联模板和内联样式，这样我们就不必在相对简单的组件上来回切换文件了。

1.  更新 `app.component.ts` 以使用内联模板

1.  删除 `app.component.html` 和 `app.component.css`

```ts
src/app/app.component.ts import { Component } from '@angular/core'

@Component({
  selector: 'app-root',
  template: `
    <div style="text-align:center">
      <h1>
      LocalCast Weather
      </h1>
      <div>Your city, your forecast, right now!</div>
      <h2>Current Weather</h2>
      <app-current-weather></app-current-weather>
    </div>
  `
})
export class AppComponent {}
```

让我们通过实现全局工具栏来改进我们的应用程序：

1.  观察`app.component.ts`中的`h1`标签：

```ts
src/app/app.component.ts
<h1>
  LocalCast Weather
</h1>
```

1.  使用 `mat-toolbar` 更新`h1`标签：

```ts
src/app/app.component.ts    
<mat-toolbar>
  <span>LocalCast Weather</span>
</mat-toolbar>
```

1.  观察结果；您应该会看到一个工具栏，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/d828cd15-3717-4b09-8402-8a13e428257f.png)

LocalCast 天气工具栏

1.  用更引人注目的颜色更新`mat-toolbar`：

```ts
src/app/app.component.ts    
<mat-toolbar color="primary">
```

为了更加原生的感觉，工具栏紧贴浏览器边缘非常重要。无论是在大屏幕还是小屏幕格式上都能很好地发挥作用。此外，当您将可点击的元素（例如汉堡菜单或帮助按钮）放在工具栏的最左侧或最右侧时，您将避免用户点击空白处的潜在可能性。这就是为什么 Material 按钮的点击区域实际上比视觉上表示的要大。这在打造无需挫折的用户体验方面有很大的不同：

```ts
src/styles.css
body {
  margin: 0;
}
```

这对这个应用程序不适用，然而，如果您正在构建一个密集的应用程序，您会注意到您的内容将延伸到应用程序的边缘，这不是一个理想的结果。考虑将内容区域包装在一个 div 中，并使用 css 应用适当的边距，如图所示：

```ts
src/styles.css
.content-margin {
  margin-left: 8px;
  margin-right: 8px;
}
```

在下一个截图中，您可以看到应用了主要颜色的边到边工具栏：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/4e2075cc-752b-48b4-bccb-c1870d9d1ff1.png)

用改进后的工具栏的 LocalCast 天气

# 用 Material Card 表示天气

Material card 是一个很好的容器，用于表示当前的天气信息。卡片元素周围有一个投影，将内容与周围的环境区分开来：

1.  在 `material.module` 中导入`MatCardModule`：

```ts
src/app/material.module.ts
import { ..., MatCardModule} from '@angular/material'
...
@NgModule({
  imports: [..., MatCardModule],
  exports: [..., MatCardModule],
})
```

1.  在 `app.component` 中，用 `<mat-card>` 包围`<app-current-weather>`:

```ts
src/app/app.component.ts
  <div style="text-align:center">
    <mat-toolbar color="primary">
      <span>LocalCast Weather</span>
    </mat-toolbar>
    <div>Your city, your forecast, right now!</div>
    <mat-card>
      <h2>Current Weather</h2>
      <app-current-weather></app-current-weather>
    </mat-card>
  </div>
```

1.  观察几乎无法区分的卡片元素，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/7c7d644c-53ee-4076-8ce8-cff3ed4a939b.png)

LocalCast 天气的难以区分的卡片

为了更好地布局屏幕，我们需要切换到 Flex 布局引擎。从组件模板中删除这些 "训练轮"：

1.  从周围的 `<div>` 中删除`style="text-align:center"`：

要在页面中心放置一个元素，我们需要创建一行，对中心元素分配宽度，并在两侧创建两个额外的列，可以弹性伸展以占用空白部分，如下所示：

```ts
src/app/app.component.ts
<div fxLayout="row">
  <div fxFlex></div>
  <div fxFlex="300px">  
    ...
  </div>
  <div fxFlex></div>
</div>
```

1.  用前面的 HTML 包围`<mat-card>`

1.  请注意，卡片元素已正确居中，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/34bc57e0-cd3f-4551-914d-f526896d8bd4.png)

LocalCast Weather 与居中的卡片

通过阅读卡片文档并查看 Material 文档站点上的示例，您将注意到`mat-card`提供了容纳标题和内容的元素。我们将在接下来的部分实现这个。

在[material.angular.io](https://material.angular.io)上，您可以通过点击括号图标查看任何示例的源代码，或者点击箭头图标在 Plunker 上启动一个工作示例。

# 辅助功能

利用这样的 Material 功能可能会感到多余；然而，设计应用程序时，您必须考虑响应性、样式、间距和可访问性问题。Material 团队已经付出了很多努力，以便您的代码在大多数情况下可以正确工作，并为尽可能多的用户群提供高质量的用户体验。这可能包括视障人士或以键盘为主的用户，他们必须依赖专门的软件或键盘功能（如标签）来浏览您的应用。利用 Material 元素为这些用户提供了关键的元数据，以便他们能够浏览您的应用。

Material 声明支持以下屏幕阅读器软件：

+   在 IE / FF / Chrome（Windows）上使用 NVDA 和 JAWS

+   使用 iOS 上的 Safari 和 OSX 上的 Safari / Chrome 的 VoiceOver

+   使用 Chrome 上的 TalkBack

# 卡片标题和内容

现在，让我们实现`mat-card`的标题和内容元素，如下所示：

```ts
src/app/app.component.ts    
<mat-toolbar color="primary">
  <span>LocalCast Weather</span>
</mat-toolbar>
<div>Your city, your forecast, right now!</div>
<div fxLayout="row">
  <div fxFlex></div>
  <mat-card fxFlex="300px">
    <mat-card-header>
      <mat-card-title>Current Weather</mat-card-title>
    </mat-card-header>
    <mat-card-content>
      <app-current-weather></app-current-weather>
    </mat-card-content>
  </mat-card>
  <div fxFlex></div>
</div>
```

使用 Material，少就是更多。您将注意到我们能够移除中心的`div`，并直接在居中卡片上应用`fxFlex`。所有材料元素都原生支持 Flex 布局引擎，这在复杂的 UI 中具有巨大的正面可维护性影响。

当我们应用`mat-card-header`后，您可以看到以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/043fdc09-4523-4514-b191-1819972288e5.png)

带标题和内容的 LocalCast Weather 卡片

请注意，卡片内的字体现在与 Material 的 Roboto 字体匹配。然而，"Current Weather"现在不再那么引人注目。如果您在`mat-card-title`内重新添加`h2`标签，"Current Weather"在视觉上看起来会更大；但是，字体不会与您应用程序的其他部分匹配。要解决此问题，您必须了解 Material 的排版功能。

# Material 排版

Material 的文档恰如其分地表述如下：

排版是一种排列类型以在显示时使文本易读、可读和吸引人的方法。

Material 提供了一种不同水平的排版，具有不同的字体大小、行高和字重特性，您可以将其应用到任何 HTML 元素，而不仅仅是默认提供的组件。

在下表中是您可以使用的 CSS 类，用于应用 Material 的排版，比如`<div class="mat-display-4">Hello, Material world!</div>`：

| **类名** | **用法** |
| --- | --- |
| `display-4`、`display-3`、`display-2` 和 `display-1` | 大而独特的标题，通常位于页面顶部（例如，主标题） |
| `headline ` | 对应`<h1>`标签的部分标题 |
| `title ` | 对应`<h2>`标签的部分标题 |
| `subheading-2` | 对应`<h3>`标签的部分标题 |
| `subheading-1` | 对应`<h4>`标签的部分标题 |
| `body-1` | 基本正文文本 |
| `body-2` | 更加粗体的正文文本 |
| `caption ` | 较小的正文和提示文本 |
| `button` | 按钮和链接 |

您可以在[`material.angular.io/guide/typography`](https://material.angular.io/guide/typography)了解更多关于 Material 排版的信息。

# 应用排版

有多种应用排版的方式。一种方式是利用`mat-typography`类，并使用相应的 HTML 标签如`<h2>`：

```ts
src/app/app.component.ts 
<mat-card-header class="mat-typography">
  <mat-card-title><h2>Current Weather</h2></mat-card-title>
</mat-card-header>
```

另一种方式是直接在元素上应用特定的排版，比如`class="mat-title"`：

```ts
src/app/app.component.ts 
<mat-card-title><div class="mat-title">Current Weather</div></mat-card-title>
```

注意，`class="mat-title"`可以应用于`div`、`span`或带有相同结果的`h2`。

通常来说，实现更具体和本地化的选项通常是更好的选择，也就是第二种实现方式。

# 将标语更新为居中对齐的标题排版

我们可以使用`fxLayoutAlign`将应用程序的标语居中，并赋予其一个柔和的`mat-caption`排版，如下所示：

1.  实现布局更改和标题排版：

```ts
src/app/app.component.ts 
<div fxLayoutAlign="center">
  <div class="mat-caption">Your city, your forecast, right now!</div>
</div>
```

1.  观察结果，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/61aca5fe-b2cc-47e9-b988-0ea5d1d1fe48.png)

本地天气中心标语

# 更新当前天气卡片布局

还有更多工作要做，使 UI 看起来像设计一样，特别是当前天气卡片的内容，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/73911aa2-c33c-4fba-80da-fe4594b53b64.png)

为了设计布局，我们将利用 Angular Flex。

您将编辑`current-weather.component.html`，它使用`<div>`和`<span>`标签来建立各个元素，这些元素可以分别存在于不同行或同一行。随着切换到 Angular Flex，我们需要将所有元素转换为`<div>`，并使用`fxLayout`指定行和列。

# 实现布局脚手架

我们需要首先实现粗略的脚手架。

考虑模板的当前状态：

```ts
 src/app/current-weather/current-weather.component.html
 1 <div *ngIf="current">
 2  <div>
 3    <span>{{current.city}}, {{current.country}}</span>
 4    <span>{{current.date | date:'fullDate'}}</span>
 5  </div>
 6  <div>
 7    <img [src]='current.image'>
 8    <span>{{current.temperature | number:'1.0-0'}}℉</span>
 9  </div>
10  <div>
11    {{current.description}}
12  </div>
13 </div>
```

让我们一步步浏览文件并更新：

1.  在第 3、4 和 8 行更新`<span>`元素为`<div>`

1.  用`<div>`包裹`<img>`元素

1.  在第 2 和 6 行的有多个子元素的`<div>`元素中添加`fxLayout="row"`属性

1.  城市和国家列大约占据了屏幕的 2/3，所以在第 3 行的`<div>`元素中添加`fxFlex="66%"`

1.  在第 4 行的下一个`<div>`元素上添加`fxFlex`以确保它占据其余的水平空间

1.  在新的`<div>`元素（包围`<img>`元素）中添加`fxFlex="66%"`

1.  在第 4 行的下一个`<div>`元素中添加`fxFlex`

模板的最终状态应该如下所示：

```ts
 src/app/current-weather/current-weather.component.html
 1 <div *ngIf="current">
 2   <div fxLayout="row">
 3     <div fxFlex="66%">{{current.city}}, {{current.country}}</div>
 4     <div fxFlex>{{current.date | date:'fullDate'}}</div>
 5   </div>
 6   <div fxLayout="row">
 7     <div fxFlex="66%">
 8       <img [src]='current.image'>
 9     </div>
10     <div fxFlex>{{current.temperature | number:'1.0-0'}}℉</div>
11   </div>
12   <div>
13    {{current.description}}
14  </div>
15 </div>
```

在添加 Angular Flex 属性时，你可以更详细一些；但是，你写的代码越多，未来的改动就会变得更加困难。例如，在第 12 行的`<div>`元素不需要`fxLayout="row"`，因为`<div>`会隐式换行。同样，在第 4 行和第 7 行，右侧的列不需要显式的`fxFlex`属性，因为它将自动被左侧元素压缩。

从网格布局的角度来看，你的元素现在都在正确的*单元格*中，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/4e654723-bc0e-46b4-84ee-58aea4c84fe9.png)

使用布局脚手架的本地天气

# 对齐元素

现在，我们需要对齐和设计每个单独的单元格以匹配设计。日期和温度需要右对齐，描述需要居中：

1.  要右对齐日期和温度，在`current-weather.component.css`中创建一个名为`.right`的新 CSS 类：

```ts
src/app/current-weather/current-weather.component.css
.right {
  text-align: right
}
```

1.  在第 4 行和第 10 行的`<div>`元素中添加`class="right"`

1.  以与本章前面居中应用标语相同的方式居中描述的`<div>`元素

1.  观察元素的正确对齐方式如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/7fe6ea79-5fcb-43bf-bea3-be0aa44eb4b8.png)

本地天气与正确的对齐方式

# 设计元素

最终设计元素的调整通常是前端开发中最费时的部分。我建议首先进行多次尝试，以便用最少的工作量获得足够接近设计的版本，然后让你的客户或团队决定是否值得投入额外的资源来花费更多时间来完善设计：

1.  添加新的 CSS 属性：

```ts
src/app/current-weather/current-weather.component.css
.no-margin {
  margin-bottom: 0
}
```

1.  对于城市名称，在第 3 行，添加`class="mat-title no-margin"`

1.  对于日期，在第 4 行，将`"mat-subheading-2 no-margin"`添加到`class="right"`中

1.  将日期的格式从`'fullDate'`改为`'EEEE MMM d'`以匹配设计

1.  修改`<img>`，在第 8 行添加`style="zoom: 175%"`

1.  对于温度，在第 10 行，附加`"mat-display-3 no-margin"`

1.  对于描述，在第 12 行，添加`class="mat-caption"`

这是模板的最终状态：

```ts
src/app/current-weather/current-weather.component.html
<div *ngIf="current">
  <div fxLayout="row">
    <div fxFlex="66%" class="mat-title no-margin">{{current.city}}, {{current.country}}</div>
    <div fxFlex class="right mat-subheading-2 no-margin">{{current.date | date:'EEEE MMM d'}}</div>
  </div>
  <div fxLayout="row">
    <div fxFlex="66%">
      <img style="zoom: 175%" [src]='current.image'>
    </div>
    <div fxFlex class="right mat-display-3 no-margin">{{current.temperature | number:'1.0-0'}}℉</div>
  </div>
  <div fxLayoutAlign="center" class="mat-caption">
    {{current.description}}
  </div>
</div>
```

1.  观察你的代码输出的样式变化，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/fea27c51-414f-4bf1-89c1-8e413c625610.png)

带有样式的本地天气

# 微调样式

标语可以受益于一些上下边距。这是我们可能会在整个应用程序中使用的常见 CSS，因此让我们将它放在`styles.css`中：

1.  实现`vertical-margin`：

```ts
src/styles.css
.vertical-margin {
  margin-top: 16px;
  margin-bottom: 16px;
}
```

1.  应用`vertical-margin`：

```ts
src/app/app.component.ts
<div class="mat-caption vertical-margin">Your city, your forecast, right now!</div>
```

当前天气具有与城市名称相同的样式；我们需要区分这两者。

1.  在`app.component.ts`中，使用`mat-headline`排版更新当前天气：

```ts
src/app/app.component.ts
<mat-card-title><div class="mat-headline">Current Weather</div></mat-card-title>
```

1.  图像和温度没有居中，因此在围绕第 6 行上下文中包含这些元素的行中添加`fxLayoutAlign="center center"`：

```ts
src/app/current-weather/current-weather.component.html
<div fxLayout="row" fxLayoutAlign="center center">
```

1.  观察您的应用程序的最终设计，应该如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b4a8d03d-3a72-42bd-8e7b-76e3588061a8.png)

LocalCast 天气的最终设计

# 调整以匹配设计

这是一个您可能会花费大量时间的领域。如果我们遵循 80-20 法则，像素完美的微调通常成为最后的 20%，却需要花费 80%的时间来完成。让我们来研究我们的实现和设计之间的差异，以及弥合这一差距需要什么：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/752fe2d4-5f42-4db7-bf34-0f3e84dfd4b4.png)

日期需要进一步定制。数字序数*th*丢失了；为了实现这一点，我们需要引入第三方库，比如 moment，或者实现我们自己的解决方案并将其绑定到模板上的日期旁边：

1.  更新`current.date`以附加序数：

```ts
src/app/current-weather/current-weather.component.html
{{current.date | date:'EEEE MMM d'}}{{getOrdinal(current.date)}}
```

1.  实现一个`getOrdinal`函数：

```ts
src/app/current-weather/current-weather.component.ts export class CurrentWeatherComponent implements OnInit {
...
  getOrdinal(date: number) {
    const n = new Date(date).getDate()
    return n > 0
      ? ['th', 'st', 'nd', 'rd'][(n > 3 &amp;&amp; n < 21) || n % 10 > 3 ? 0 : n % 10]
      : ''
  }
  ...
}
```

请注意，`getOrdinal`的实现归结为一个复杂的单行代码，不太可读，而且很难维护。这样的函数，如果对您的业务逻辑至关重要，应该进行严格的单元测试。

截至目前为止，Angular 6 不支持在日期模板中插入新的换行；理想情况下，我们应该能够将日期格式指定为`'EEEE\nMMM d'`，以确保换行始终一致。

温度的实现需要使用`<span>`元素将数字与单位分隔开，并用`<span class="unit">℉</span>`将其包围起来，其中 unit 是一个 CSS 类，可以使其看起来像上标元素。

1.  实现一个`unit`CSS 类：

```ts
src/app/current-weather/current-weather.component.css
.unit {
  vertical-align: super;
}
```

1.  应用`unit`：

```ts
src/app/current-weather/current-weather.component.html
...   
 7 <div fxFlex="55%">
...
10 <div fxFlex class="right no-margin">
11   <p class="mat-display-3">{{current.temperature | number:'1.0-0'}}
12     <span class="mat-display-1 unit">℉</span>
13   </p>
```

我们需要尝试调整第 7 行上的`fxFlex`值来确定预报图像应该占用多少空间。否则，温度将溢出到下一行，并且您的设置还会受到浏览器窗口大小的影响。例如，`60%`在小浏览器窗口下效果很好，但最大化时会造成溢出。然而，`55%`似乎满足了这两个条件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/90504375-02fa-479b-b7fe-cd6f267d516f.png)

修正后的 LocalCast 天气

一如既往，进一步调整边距和填充以进一步定制设计是可能的。然而，每一次与库的偏离都会对维护性造成影响。除非您确实在建立一个以显示天气数据为中心的业务，否则您应该将进一步的优化推迟到项目的最后，如果时间允许的话。如果经验能够作为指导，您将不会进行这样的优化。

通过两个负的 margin-bottom hack，您可以获得一个与原始设计相当接近的设计，但是我不会在这里包含这些 hack，并留给读者在 GitHub 仓库中发现。这些 hack 有时是必要的恶，但一般来说，它们指向设计和实现现实之间的脱节。在调整部分之前的解决方案是甜蜜点，Angular Material 在那里繁荣：

![图片](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/181ade0b-f684-4c00-975c-83d7f4f31da4.png)

经过调整和 hack 的 LocalCast Weather

# 更新单元测试

为了保持您的单元测试运行，您需要将`MaterialModule`导入到任何使用 Angular Material 的组件的`spec`文件中：

```ts
*.component.spec.ts
...
  beforeEach(
    async(() => {
      TestBed.configureTestingModule({
        ...
        imports: [..., MaterialModule, NoopAnimationsModule],
      }).compileComponents()
    })
  )
```

您还需要更新任何测试，包括 e2e 测试，以查找特定的 HTML 元素。

例如，由于应用程序的标题 LocalCast Weather 不再在一个`h1`标签中，您必须更新`spec`文件以在`span`元素中查找它：

```ts
src/app/app.component.spec.ts
expect(compiled.querySelector('span').textContent).toContain('LocalCast Weather')
```

类似地，在 e2e 测试中，您需要更新您的页面对象函数以从正确的位置检索文本：

```ts
e2e/app.po.ts
getParagraphText() {
  return element(by.css('app-root mat-toolbar span')).getText()
}
```

# 更新 Angular Material

您可以使用`ng update`来快速无痛升级体验，应该如下所示：

```ts
$ npx ng update @angular/material
 Updating package.json with dependency @angular/cdk @ "6.0.0" (was "5.2.2")...
 Updating package.json with dependency @angular/material @ "6.0.0" (was "5.2.2")...
UPDATE package.json (5563 bytes)
```

此外，我发现了由 Angular 团队在[`github.com/angular/material-update-tool`](https://github.com/angular/material-update-tool)发布的`material-update-tool`。在当前形式下，该工具被宣传为一个特定的 Angular Material 5.x 到 6.0 的更新工具，因此它可能会成为未来`ng update`的一部分，就像`rxjs-tslint`工具一样。您可以按照下面的命令来运行该工具：

```ts
$ npx angular-material-updater -p .\src\tsconfig.app.json

√ Successfully migrated the project source files. Please check above output for issues that couldn't be automatically fixed.
```

如果幸运的话，一切顺利，可以随意跳过本节剩下的内容。本节的其余部分我将介绍我在开发本示例过程中遇到的一个涉及发布候选版本和 beta 版本的特定情景，这突显了手动更新的需求。首先，我们将意识到当前版本，然后发现最新可用版本，并最后升级和测试升级，就像我们手动更新 Angular 时那样。

# 更新 Angular Material

现在我们知道要升级到哪个版本，让我们继续进行升级：

1.  执行以下命令，将 Material 及其相关组件更新到目标版本：

```ts
$ npm install @angular/material@⁵.0.0 @angular/cdk@⁵.0.0 @angular/animations@⁵.0.0 @angular/flex-layout@².0.0-rc.1
```

1.  验证您的`package.json`，确保版本与预期版本匹配

1.  处理任何 NPM 警告

在这种特定情况下，我们从`@angular/flex-layout`包收到了无法满足的对等依赖警告。在 GitHub 上的进一步调查([`github.com/angular/flex-layout/issues/508`](https://github.com/angular/flex-layout/issues/508))显示，这是一个已知问题，通常可以预期从 Beta 或 RC 包中出现。这意味着可以忽略这些警告是安全的。

# 总结

在本章中，你学会了将特定的 Angular Material 组件应用到你的应用程序中。你意识到了过度优化 UI 设计的陷阱。我们还讨论了如何保持 Angular Material 的最新状态。

在下一章中，我们将更新天气应用程序，以响应用户输入并使用响应式表单来保持我们的组件解耦，同时还可以使用`BehaviorSubject`在它们之间进行数据交换。在下一章之后，我们将完成天气应用程序，并把重点转向构建更大型的业务线应用。


# 第十二章：创建一个以路由为首选的 LOB 应用

Line-of-Business（**LOB**）应用程序是软件开发世界的支柱。根据维基百科的定义，LOB 是一个通用术语，指的是服务于特定客户交易或业务需求的产品或一组相关产品。LOB 应用程序提供了展示各种功能和功能的良好机会，而无需涉及大型企业应用程序通常需要的扭曲或专业化场景。在某种意义上，它们是 80-20 的学习经验。但是，我必须指出关于 LOB 应用程序的一个奇怪之处——如果您最终创建了一个半有用的 LOB 应用程序，其需求将不受控制地增长，您将很快成为自己成功的受害者。这就是为什么您应该把每个新项目的开始视为一个机会，一个编码的开拓，以更好地创建更灵活的架构。

在本章和其余章节中，我们将使用可扩展的架构和工程最佳实践建立一个功能丰富的新应用程序，以满足具有可扩展架构的 LOB 应用程序的需求。我们将遵循以路由为首选的设计模式，依靠可重用组件创建一个名为 LemonMart 的杂货店 LOB。

在本章中，您将学会以下内容：

+   有效地使用 CLI 来创建重要的 Angular 组件和 CLI 脚手架

+   学习如何构建以路由为首选的应用程序

+   品牌、定制和素材图标

+   使用 Augury 调试复杂应用程序

+   启用延迟加载

+   创建一个步行骨架

本书提供的代码示例需要 Angular 版本 5 和 6。Angular 5 代码与 Angular 6 运行时兼容。Angular 6 将在 2019 年 10 月之前得到长期支持。代码存储库的最新版本可在以下网址找到：

+   在 [Github.com/duluca/local-weather-app](https://github.com/duluca/local-weather-app) 上的 LocalCast 天气

+   在 [Github.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart) 上的 LemonMart

# Angular 速查表

在我们开始创建 LOB 应用程序之前，我为您提供了一个速查表，让您熟悉常见的 Angular 语法和 CLI 命令，因为在今后，这些语法和命令将被使用，而不需要明确解释它们的目的。花些时间审查和熟悉新的 Angular 语法、主要组件、CLI 脚手架和常见管道。如果您的背景是 AngularJS，您可能特别需要这个列表，因为您需要放弃一些旧的语法。

# 绑定

绑定，或数据绑定，指的是代码中的变量和 HTML 模板或其他组件中显示或输入的值之间的自动单向或双向连接：

| **类型** | **语法 ** | **数据方向** |
| --- | --- | --- |

| 插值属性

属性

类

样式 | `{{expression}}``[target]="expression"``bind-target="expression"` | 从数据源单向传输

用于查看目标 |

| 事件 | `(target)="statement"` `on-target="statement"` | 从视图目标到单向

用于数据源 |

| 双向绑定 | `[(target)]="expression"` `bindon-target="expression"` | 双向绑定 |
| --- | --- | --- |

来源：[`angular.io/guide/template-syntax#binding-syntax-an-overview`](https://angular.io/guide/template-syntax#binding-syntax-an-overview)

# 内置指令

指令封装编码行为，可应用为 HTML 元素或其他组件的属性：

| **名称** | **语法** | **目的** |
| --- | --- | --- |
| 结构指令 | `*ngIf``*ngFor``*ngSwitch` | 控制 HTML 的结构布局，以及根据需要在 DOM 中添加或移除元素 |
| 属性指令 | `[class]``[style]``[(model)]` | 监听并修改其他 HTML 元素、属性、属性和组件的行为，如 CSS 类、HTML 样式和 HTML 表单元素 |

结构指令来源：[`angular.io/guide/structural-directives`](https://angular.io/guide/structural-directives)

属性指令来源：[`angular.io/guide/template-syntax#built-in-attribute-directives`](https://angular.io/guide/template-syntax#built-in-attribute-directives)

# 常见的管道

管道修改了在 HTML 模板中显示数据绑定值的方式。  

| **名称** | **目的** | **用法** |
| --- | --- | --- |
| 日期 | 根据语言环境规则，格式化日期 | `{{date_value &#124; date[:format]}}` |
| 文本转换 | 将文本转换为大写、小写或标题格式 | `{{value &#124; uppercase}}``{{value &#124; lowercase}}``{{value &#124; titlecase }}` |
| 十进制 | 根据语言环境规则，格式化数字 | `{{number &#124; number[:digitInfo]}}` |
| 百分比 | 根据语言环境规则，将数字格式化为百分比形式 | `{{number &#124; percent[:digitInfo]}}` |
| 货币 | 根据语言环境规则，格式化数字为带有货币代码和符号的货币形式 | `{{number &#124; currency[:currencyCode [:symbolDisplay[:digitInfo]]]}}` |

管道来源：[`angular.io/guide/pipes`](https://angular.io/guide/pipes)

# 起始命令、主要组件和 CLI 脚手架

起始命令帮助生成新项目或添加依赖项。Angular CLI 命令可通过自动生成易用的样板脚手架代码来快速创建主要组件。有关完整命令列表，请访问[`github.com/angular/angular-cli/wiki`](https://github.com/angular/angular-cli/wiki)：

| **名称** | **目的** | **CLI 命令** |
| --- | --- | --- |
| 新建 | 创建一个新的 Angular 应用，并已配置好初始化的 git 仓库、package.json，并已配置好路由。从父级文件夹运行。 | `npx @angular/cli new project-name --routing` |
| 更新 | 更新 Angular、RxJS 和 Angular Material 依赖项。根据需要重写代码以保持兼容性。 | `npx ng update` |
| 添加材料 | 安装和配置 Angular Material 依赖项。 | `npx ng add @angular/material` |
| 模块 | 创建一个新的`@NgModule`类。使用`--routing`为子模块添加路由。可选择使用`--module`将新模块导入到父模块中。 | `ng g module new-module` |
| 组件 | 创建一个新的`@Component`类。使用`--module`指定父模块。可选择使用`--flat`跳过目录创建，`-t`用于内联模板，`-s`用于内联样式。 | `ng g component new-component` |
| 指令 | 创建一个新的`@Directive`类。可选择使用`--module`为给定子模块定义指令的作用域。 | `ng g directive new-directive` |
| 管道 | 创建一个新的`@Pipe`类。可选择使用`--module`为给定子模块定义管道的作用域。 | `ng g pipe new-pipe` |
| 服务 | 创建一个新的`@Injectable`类。使用`--module`为给定子模块提供服务。服务不会自动导入到模块中。可选择使用`--flat` false 将服务创建在一个目录下。 | `ng g service new-service` |
| 守卫 | 创建一个新的`@Injectable`类，实现了路由生命周期钩子`CanActivate`。使用`--module`为给定的子模块提供守卫。守卫不会自动导入到一个模块中。 | `ng g guard new-guard` |
| 类 | 创建一个基础的类。 | `ng g class new-class` |
| 接口 | 创建一个基本的接口。 | `ng g interface new-interface` |
| 枚举 | 创建一个基础的枚举。 | `ng g enum new-enum` |

为了正确地在自定义模块下生成之前列出的一些组件，比如`my-module`，你可以在你想要生成的名字之前加上模块名，比如`ng g c my-module/my-new-component`。Angular CLI 将正确配置并将新组件放置在`my-module`文件夹下。

# 配置 Angular CLI 自动补全

在使用 Angular CLI 时，可以获得自动补全的体验。在你的`*nix`环境中执行相应的命令：

+   对于 bash shell：

```ts
$ ng completion --bash >> ~/.bashrc
$ source ~/.bashrc
```

+   对于 zsh shell：

```ts
$ ng completion --zsh >> ~/.zshrc
$ source ~/.zshrc
```

+   对于使用 git bash shell 的 Windows 用户：

```ts
$ ng completion --bash >> ~/.bash_profile
$ source ~/.bash_profile
```

# 以路由为中心的架构

Angular 路由器，包含在`@angular/router`包中，是构建**单页面应用程序**（**SPAs**）的核心且关键的部分，它的行为表现就像是可以使用浏览器控件或缩放控件轻松导航的普通网站。

Angular Router 具有高级功能，例如延迟加载，路由出口，辅助路由，智能活动链接跟踪，以及可以被表示为一个`href`的能力，这使得可以利用无状态数据驱动组件使用 RxJS `SubjectBehavior`来实现高度灵活的以路由为中心的应用架构。

大型团队可以针对单一代码库进行工作，每个团队负责一个模块的开发，而不会互相影响，同时可以实现简单的持续集成。Google 有着数十亿行代码，选择针对单一代码库工作是有着非常好的理由的。事后的集成是非常昂贵的。

小团队可以动态重新排列其 UI 布局，以快速对变化做出响应，而无需重新构建其代码。很容易低估由于布局或导航的后期变更而浪费的时间量。对于大团队来说，这些变化更容易吸收，但对于小团队来说是一次代价高昂的努力。

通过延迟加载，所有开发人员都可以受益于亚秒级的第一意义性绘制，因为在构建时，向浏览器传递的核心用户体验的文件大小被保持在最低限度。模块的大小影响下载和加载速度，因为浏览器需要执行的操作越多，用户看到应用程序的第一个屏幕就需要的时间就越长。通过定义延迟加载的模块，每个模块可以作为单独的文件打包，可以单独下载和加载，并根据需要使用。智能活动链接跟踪会产生卓越的开发人员和用户体验，使得实现突出显示功能来指示用户当前活动的选项卡或应用程序部分非常容易。辅助路由最大化了组件的重用，并帮助轻松实现复杂的状态转换。通过辅助路由，您可以仅使用单个外部模板呈现多个主视图和详细视图。您还可以控制路由如何在浏览器的 URL 栏中显示，并使用`routerLink`在模板中和`Router.navigate`在代码中组成路由，从而驱动复杂的场景。

为了实现路由器优先的实现，您需要这样做：

1.  早期定义用户角色

1.  设计时考虑延迟加载

1.  实施一个步行骨架导航体验

1.  围绕主要数据组件进行设计

1.  强制执行解耦的组件架构

1.  区分用户控件和组件

1.  最大化代码复用

用户角色通常表示用户的工作职能，比如经理或数据输入专员。在技术术语中，它们可以被视为特定用户类别被允许执行的一组操作。定义用户角色有助于识别可以配置为延迟加载的子模块。毕竟，数据输入专员永远不会看到大多数经理可以看到的屏幕，那么为什么要向这些用户提供这些资源并减慢他们的体验呢？延迟加载对于创建可扩展的应用程序架构至关重要，不仅从应用程序的角度来看，还从高质量和高效的开发角度来看。配置延迟加载可能会有些棘手，这就是为什么早期确定一个步行骨架导航体验非常重要的原因。

确定用户将使用的主要数据组件，例如发票或人员对象，将帮助您避免过度设计您的应用程序。围绕主要数据组件进行设计将及早通知 API 设计，并帮助定义您将使用的`BehaviorSubject`数据锚定来实现无状态、数据驱动的设计，以确保解耦的组件架构。

最后，识别自包含的用户控件，它们封装了您希望为您的应用程序创建的独特行为。用户控件可能会作为具有数据绑定属性和紧密耦合的控制器逻辑和模板的指令或组件进行创建。另一方面，组件将利用路由生命周期事件来解析参数并对数据执行 CRUD 操作。早期识别这些组件的重用将导致创建更灵活的组件，可以在路由器协调下在多个上下文中重用，最大程度地提高代码重用率。

# 创建 LemonMart

LemonMart 将是一个具有超过 90 个代码文件的中型业务应用程序。我们将通过从一开始就创建一个配置了路由和 Angular Material 的新 Angular 应用程序来开始我们的旅程。

# 创建一个以路由为主的应用

采用路由优先的方法时，我们希望在应用程序早期就启用路由：

1.  你可以通过执行此命令创建已经配置了路由的新应用：

确保没有全局安装 `@angular/cli`，否则可能会遇到错误：

```ts
$ npx @angular/cli new lemon-mart --routing
```

1.  为我们创建了一个新的 `AppRoutingModule` 文件：

```ts
src/app/app-routing.modules.ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

const routes: Routes = [];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

我们将在路由数组中定义路由。请注意，路由数组被传递以配置为应用程序的根路由，默认的根路由是 `/`。

在配置你的 `RouterModule` 时，可以传入额外的选项来自定义路由的默认行为，例如当你尝试加载已经显示的路由时，而不是不采取任何行动，你可以强制重新加载组件。要启用这种行为，请这样创建你的路由 `RouterModule.forRoot(routes, { onSameUrlNavigation: 'reload' })`。 

1.  最后，注册 `AppRoutingModule` 到 `AppModule`，如下所示：

```ts
src/app/app.module.ts ...
import { AppRoutingModule } from './app-routing.module';

@NgModule({
  ...
  imports: [
    AppRoutingModule 
    ...
  ],
  ...
```

# 配置 Angular.json 和 Package.json

在继续之前，你应该完成以下步骤：

1.  修改 `angular.json` 和 `tslint.json` 以强制执行你的设置和编码规范

1.  安装 `npm i -D prettier`

1.  在 `package.json` 中添加 `prettier` 设置

1.  将开发服务器端口配置为非`4200`，例如`5000`

1.  添加 `standardize` 脚本并更新 `start` 和 `build` 脚本

1.  在 `package.json` 中为 Docker 添加 npm 脚本

1.  建立开发规范并在项目中记录，使用 `npm i -D dev-norms` 然后执行 `npx dev-norms create`

1.  如果你使用 VS Code，需要设置 `extensions.json` 和 `settings.json` 文件

你可以配置 TypeScript Hero 扩展来自动整理和修剪导入语句，只需在 `settings.json` 中添加 `"typescriptHero.imports.organizeOnSave": true`。如果与设置 `"files.autoSave": "onFocusChange"` 结合使用，你可能会发现该工具在你努力输入时会积极地清理未使用的导入项。确保该设置适合你并且不会与任何其他工具或 VS Code 自己的导入组织功能发生冲突。

1.  执行 `npm run standardize`

参考[第十章]()，*准备 Angular 应用进行生产发布*，获取更多配置详细信息。

你可以在[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)获取适用于 Docker 的 npm 脚本，以及在[bit.ly/npmScriptsForAWS](http://bit.ly/npmScriptsForAWS)获取适用于 AWS 的 npm 脚本。

# 配置 Material 和样式

我们还需要设置 Angular Material 并配置要使用的主题，如第十一章*使用 Angular Material 增强 Angular 应用*：

1.  安装 Angular Material：

```ts
$ npx ng add @angular/material
$ npm i @angular/flex-layout hammerjs 
$ npx ng g m material --flat -m app
```

1.  导入和导出`MatButtonModule`，`MatToolbarModule`，和`MatIconModule`

1.  配置默认主题并注册其他 Angular 依赖项

1.  将通用 css 添加到`styles.css`中，如下所示，

```ts
src/styles.css

body {
  margin: 0;
}

.margin-top {
  margin-top: 16px;
}

.horizontal-padding {
  margin-left: 16px;
  margin-right: 16px;
}

.flex-spacer {
  flex: 1 1 auto;
}
```

参考[第十一章]()，*使用 Angular Material 增强 Angular 应用*，获取更多配置详细信息。

# 设计 LemonMart

构建一个从数据库到前端的基本路线图非常重要，同时要避免过度工程化。这个初始设计阶段对项目的长期健康和成功至关重要，在这个阶段任何现有的团队隔离必须被打破，并且整个团队必须对整体技术愿景有很好的理解。这比说起来要容易得多，关于这个话题已经有大量的书籍写成。

在工程中，没有一个问题有唯一正确答案，所以重要的是要记住没有人能拥有所有答案，也没有一个清晰的愿景。技术和非技术领导者们创造一个安全的空间，鼓励开放讨论和实验，作为文化的一部分是非常重要的。对于整个团队来说，对这种不确定性的谦卑和同理心和任何单独团队成员的技术能力一样重要。每个团队成员都必须习惯于把自己的自负留在门外，因为我们共同的目标将是在开发周期期间根据不断变化的要求发展和演变应用。如果你成功了，你会发现你创建的软件中的每个部分都可以轻松被任何人替代。

# 识别用户角色

我们设计的第一步是考虑你为什么要使用这个应用。

我们构想了 LemonMart 的四种用户状态或角色：

+   经过身份验证的用户，任何经过身份验证的用户都可以访问他们的个人资料

+   出纳，他们的唯一角色是为客户结账

+   职员，他们的唯一角色是执行与库存相关的功能

+   经理，可以执行出纳和职员所能执行的所有操作，但也可以访问管理功能

有了这个想法，我们可以开始设计我们应用的高层结构。

# 用站点地图识别高级模块

开发你的应用的高级站点地图，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b4beb082-f0f8-44ca-a697-89567f380298.png)

用户的登陆页面

我使用 MockFlow.com 的 SiteMap 工具创建了站点地图

显示在[`sitemap.mockflow.com`](https://sitemap.mockflow.com)上。

第一次检查时，三个高级模块显现出延迟加载的候选项：

1.  销售点（POS）

1.  库存

1.  管理员

收银员只能访问 POS 模块和组件。店员只能访问库存模块，该模块将包括额外的屏幕，用于库存录入，产品和类别管理组件。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b50bc6a5-20a7-4e3a-9944-db949ec9ef40.png)

库存页面

最后，管理员将能够使用管理员模块访问所有三个模块，包括用户管理和收据查找组件。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/49c79ce6-4bb5-4fba-904b-73f0bc978f3f.png)

管理员页面

启用所有三个模块的延迟加载有很大的好处，因为收银员和店员永远不会使用属于其他用户角色的组件，所以没有理由将这些字节发送到他们的设备上。这意味着当管理员模块获得更先进的报告功能或应用程序添加新角色时，POS 模块将不受应用程序带宽和内存增长的影响。这意味着减少了支持电话，并保持了长时间使用相同硬件的一致性性能。

# 生成经过路由启用的模块

现在我们已经定义了我们的高级组件——管理员，库存和 POS，我们可以将它们定义为模块。这些模块将与您迄今创建的模块不同，因为它们涉及路由和 Angular Material。我们可以将用户配置文件创建为应用程序模块上的一个组件；不过请注意，用户配置文件只能供已经经过身份验证的用户使用，因此定义一个仅供一般经过身份验证的用户使用的第四个模块是有意义的。这样，您将确保您的应用程序的第一个有效载荷尽可能保持最小。此外，我们将创建一个主页组件，以包含应用程序的着陆体验，这样我们就可以将实现细节保持在`app.component`之外：

1.  生成`manager`，`inventory`，`pos`和`user` 模块，指定它们的目标模块和路由功能：

```ts
$ npx ng g m manager -m app --routing
$ npx ng g m inventory -m app --routing
$ npx ng g m pos -m app --routing
$ npx ng g m user -m app --routing
```

如果您已经配置`npx`来自动识别`ng`作为命令，您可以节省更多按键，这样您将不必在每次命令后附加`npx`。不要全局安装`@angular/cli`。请注意缩写命令结构，其中`ng generate module manager`变成了`ng g m manager`，同样，`--module`变成了`-m`。

1.  验证您的 CLI 是否没有错误。

请注意，在 Windows 上使用`npx`可能会遇到错误，如路径必须是字符串。接收到未定义的错误。这个错误似乎对命令的成功操作没有任何影响，这就是为什么始终检查 CLI 工具生成的内容是至关重要的。

1.  验证已创建的文件夹和文件：

```ts
/src/app
│   app-routing.module.ts
│   app.component.css
│   app.component.html
│   app.component.spec.ts
│   app.component.ts
│   app.module.ts
│   material.module.ts
├───inventory
│        inventory-routing.module.ts
│        inventory.module.ts
├───manager
│        manager-routing.module.ts
│        manager.module.ts
├───pos
│        pos-routing.module.ts
│        pos.module.ts
└───user
        user-routing.module.ts
        user.module.ts
```

1.  检查`ManagerModule`如何连接。

子模块实现了类似于 `app.module` 的 `@NgModule`。最大的区别在于，子模块不实现 `bootstrap` 属性，而这个属性对于根模块是必需的，以初始化你的 Angular 应用程序：

```ts
src/app/manager/manager.module.ts
import { NgModule } from '@angular/core'
import { CommonModule } from '@angular/common'

import { ManagerRoutingModule } from './manager-routing.module'

@NgModule({
  imports: [CommonModule, ManagerRoutingModule],
  declarations: [],
```

```ts
})
export class ManagerModule {}
```

由于我们指定了 `-m` 选项，该模块已经被导入到 `app.module` 中：

```ts
src/app/app.module.ts
...
import { ManagerModule } from './manager/manager.module'
...
@NgModule({
  ...
  imports: [
    ...
    ManagerModule 
  ],
...
```

另外，因为我们还指定了 `--routing` 选项，一个路由模块已经被创建并导入到 `ManagerModule` 中：

```ts
src/app/manager/manager-routing.module.ts
import { NgModule } from '@angular/core'
import { Routes, RouterModule } from '@angular/router'

const routes: Routes = []

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class ManagerRoutingModule {}
```

请注意，`RouterModule` 正在使用 `forChild` 进行配置，而不是像 `AppRouting` 模块的情况下使用 `forRoot`。这样，路由器就能理解不同模块上下文中定义的路由之间的正确关系，并且能够在这个示例中正确地在所有子路由之前添加 `/manager`。

CLI 不遵循你的 `tslint.json` 设置。如果你已经正确配置了你的 VS Code 环境，并使用 prettier，那么当你在每个文件上工作时，或者在全局运行 prettier 命令时，你的代码样式偏好将被应用。

# 设计主页路由

请将以下模拟作为 LemonMart 的着陆体验考虑：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3f5d646c-4efd-4ecb-930c-3f099ff6e0fd.png)

LemonMart 着陆体验

与 `LocalCastWeather` 应用程序不同，我们不希望所有这些标记都出现在 `App` 组件中。`App` 组件是整个应用程序的根元素；因此，它应该只包含在整个应用程序中始终出现的元素。在以下带注释的实例中，标记为 1 的工具栏将在整个应用程序中持续存在。

标记为 2 的区域将容纳主页组件，它本身将包含一个登陆用户控件，标记为 3：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/fb7ef832-d649-4970-be2d-d88f0e0f1a51.png)

LemonMart 布局结构

将默认或着陆组件作为 Angular 中的单独元素是最佳实践。这有助于减少必须在每个页面加载和执行的代码量，同时在利用路由器时也会产生更灵活的体系结构：

使用内联模板和样式生成 `home` 组件：

```ts
$ npx ng g c home -m app --inline-template --inline-style
```

现在，你已经准备好配置路由器。

# 设置默认路由

让我们开始为 LemonMart 设置一个简单的路由：

1.  配置你的 `home` 路由：

```ts
src/app/app-routing.module.ts 
...
const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
]
...
```

我们首先为 `'home'` 定义一个路径，并通过设置组件属性告知路由器渲染 `HomeComponent`。然后，我们将应用程序的默认路径 `''` 重定向到 `'/home'`。通过设置 `pathMatch` 属性，我们始终确保这个非常特定的主页路由实例将作为着陆体验呈现。

1.  创建一个带有内联模板的 `pageNotFound` 组件

1.  配置 `PageNotFoundComponent` 的通配符路由：

```ts
src/app/app-routing.module.ts 
...
const routes: Routes = [
  ...
  { path: '**', component: PageNotFoundComponent }
]
...
```

这样，任何没有匹配的路由都将被重定向到 `PageNotFoundComponent`。

# RouterLink

当用户登陆到 `PageNotFoundComponent` 时，我们希望他们通过 `RouterLink` 方向重定向到 `HomeComponent`：

1.  实施内联模板以使用`routerLink`链接回主页：

```ts
src/app/page-not-found/page-not-found.component.ts
...
template: `
    <p>
      This page doesn't exist. Go back to <a routerLink="/home">home</a>.
    </p>
  `,
...
```

也可以通过`<a href>`标签实现此导航；但是，在更动态和复杂的导航场景中，您将失去诸如自动活动链接跟踪或动态链接生成等功能。

Angular 引导流程将确保`AppComponent`在您的`index.html`中的`<app-root>`元素内。但是，我们必须手动定义我们希望`HomeComponent`渲染的位置，以完成路由器配置。

# 路由器出口

`AppComponent`被视为`app-routing.module`中定义的根路由的根元素，这使我们能够在这个根元素中定义出口，以使用`<router-outlet>`元素动态加载我们希望的任何内容：

1.  配置`AppComponent`以使用内联模板和样式

1.  为您的应用程序添加工具栏

1.  将您的应用程序名称添加为按钮链接，以便在点击时将用户带到主页

1.  添加 `<router-outlet>` 以渲染内容：

```ts
src/app/app.component.ts
...
template: `
    <mat-toolbar color="primary">
      <a mat-button routerLink="/home"><h1>LemonMart</h1></a>
    </mat-toolbar>
    <router-outlet></router-outlet>
  `,
```

现在，主页的内容将在`<router-outlet>`内渲染。

# 品牌、自定义和 Material 图标

为构建一个吸引人且直观的工具栏，我们必须向应用程序引入一些图标和品牌，以便用户可以轻松地通过熟悉的图标在应用程序中进行导航。

# 品牌

在品牌方面，您应确保您的 Web 应用程序应具有自定义调色板，并与桌面和移动浏览器功能集成，以展示您的应用程序名称和图标。

# 调色板

使用 Material Color 工具选择一个调色板，如第十一章，*使用 Angular Material 增强 Angular 应用程序* 中所述。这是我为 LemonMart 选择的调色板：

```ts
https://material.io/color/#!/?view.left=0&view.right=0&primary.color=2E7D32&secondary.color=C6FF00
```

# 实现浏览器清单和图标

您需要确保浏览器在浏览器标签中显示正确的标题文本和图标。此外，应创建一个清单文件，为各种移动操作系统实现特定图标，这样，如果用户将您的网站置为书签，就会显示一个理想的图标，类似于手机上的其他应用图标。这将确保用户在手机设备的主屏幕上收藏或将您的 Web 应用程序置为书签时可以获得一个原生外观的应用程序图标：

1.  创建或从设计师或网站（如[`www.flaticon.com`](https://www.flaticon.com)）获取您网站的标志的 SVG 版本

1.  在这种情况下，我将使用特定的柠檬图片：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/7728c712-6fd0-4162-ab73-fb7a2d267725.jpg)

LemonMart 的标志性标识

在使用互联网上找到的图像时，请注意适用的版权。在这种情况下，我已经购买了许可证以发布这个柠檬标志，但是您可以在以下 URL 获得您自己的副本，前提是您向图像的作者提供所需的归属声明：[`www.flaticon.com/free-icon/lemon_605070`](https://www.flaticon.com/free-icon/lemon_605070)。

1.  使用[`realfavicongenerator.net`](https://realfavicongenerator.net)等工具生成`favicon.ico`和清单文件

1.  根据你的喜好调整 iOS、Android、Windows Phone、macOS 和 Safari 的设置

1.  确保你设置版本号，网站图标在缓存方面可能让人头疼；一个随机的版本号将确保用户总是得到最新的版本

1.  下载并解压生成的`favicons.zip`文件到你的`src`文件夹中

1.  编辑`angular.json`文件以在你的应用程序中包括新资源：

```ts
angular.json   
"apps": [
  {
    ...
      "assets": [
        "src/assets",
        "src/favicon.ico",
        "src/android-chrome-192x192.png",
        "src/favicon-16x16.png",
        "src/mstile-310x150.png",
        "src/android-chrome-512x512.png",
        "src/favicon-32x32.png",
        "src/mstile-310x310.png",
        "src/apple-touch-icon.png",
        "src/manifest.json",
        "src/mstile-70x70.png",
        "src/browserconfig.xml",
        "src/mstile-144x144.png",
        "src/safari-pinned-tab.svg",
        "src/mstile-150x150.png"
      ]
```

1.  将生成的代码插入到你的`index.html`的`<head>`部分中：

```ts
src/index.html
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=rMlKOnvxlK">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png?v=rMlKOnvxlK">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png?v=rMlKOnvxlK">
<link rel="manifest" href="/manifest.json?v=rMlKOnvxlK">
<link rel="mask-icon" href="/safari-pinned-tab.svg?v=rMlKOnvxlK" color="#b3ad2d">
<link rel="shortcut icon" href="/favicon.ico?v=rMlKOnvxlK">
<meta name="theme-color" content="#ffffff">
```

1.  确保你的新网站图标正确显示

为了进一步发展你的品牌，考虑配置一个自定义的 Material 主题并利用[`material.io/color`](https://material.io/color/)

# 自定义图标

现在，让我们在你的 Angular 应用程序中添加自定义的品牌。你需要用来创建网站图标的 svg 图标：

1.  将图片放在`src/app/assets/img/icons`下，命名为`lemon.svg`

1.  将`HttpClientModule`导入`AppComponent`，以便通过 HTTP 请求`.svg`文件

1.  更新`AppComponent`以注册新的 svg 文件为图标：

```ts
src/app/app.component.ts import { DomSanitizer } from '@angular/platform-browser'
...
export class AppComponent {
  constructor(iconRegistry: MatIconRegistry, sanitizer: DomSanitizer) {
    iconRegistry.addSvgIcon(
      'lemon',
      sanitizer.bypassSecurityTrustResourceUrl('assets/img/icons/lemon.svg')
    )
  }
}
```

1.  将图标添加到工具栏：

```ts
src/app/app.component.ts  
template: `
    <mat-toolbar color="primary">
      <mat-icon svgIcon="lemon"></mat-icon>
      <a mat-button routerLink="/home"><h1>LemonMart</h1></a>
    </mat-toolbar>
    <router-outlet></router-outlet>
  `,
```

现在让我们添加菜单、用户资料和退出的其余图标。

# Material 图标

Angular Material 可以与 Material Design 图标直接使用，可以在你的`index.html`中作为 Web 字体引入你的应用程序。你可以自行托管这个字体；不过，如果选择这条路线，你也无法享受用户在访问其他网站时已经缓存了字体的好处，这就会导致浏览器在下载 42-56 KB 文件时节省速度和延迟。完整的图标列表可以在[`material.io/icons/`](https://material.io/icons/)找到。

现在让我们在工具栏上添加一些图标，并为主页设置一个最小的假登录按钮的模板：

1.  确保 Material 图标的`<link>`标签已经添加到`index.html`中：

```ts
src/index.html
<head>
  ...
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
</head>
```

如何自行托管的说明可以在[`google.github.io/material-design-icons/#getting-icons`](http://google.github.io/material-design-icons/#getting-icons)的自行托管部分找到。

配置完成后，使用 Material 图标很容易。

1.  更新工具栏，使菜单按钮位于标题左侧。

1.  添加一个`fxFlex`，使其余图标右对齐。

1.  添加用户资料和退出图标：

```ts
src/app/app.component.ts    
template: `
    <mat-toolbar color="primary">
      <button mat-icon-button><mat-icon>menu</mat-icon></button>
      <mat-icon svgIcon="lemon"></mat-icon>
      <a mat-button routerLink="/home"><h1>LemonMart</h1></a>
      <span class="flex-spacer"></span>
      <button mat-icon-button><mat-icon>account_circle</mat-icon></button>
      <button mat-icon-button><mat-icon>lock_open</mat-icon></button>
    </mat-toolbar>
    <router-outlet></router-outlet>
  `,
```

1.  为登录添加一个最小的模板：

```ts
src/app/home/home.component.ts 
  styles: [`
    div[fxLayout] {margin-top: 32px;}
  `],
  template: `
    <div fxLayout="column" fxLayoutAlign="center center">
      <span class="mat-display-2">Hello, Lemonite!</span>
      <button mat-raised-button color="primary">Login</button>
    </div>
  `
```

你的应用程序应该看起来与这个截图类似：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/da684805-2472-4ba0-b4f9-86e3595124b1.png)

最小登录的 LemonMart

还有一些工作要做，就是在用户的认证状态下实现和显示/隐藏菜单、资料和退出图标。我们将在 Chapter 14 *设计认证和授权* 中介绍这个功能。现在你已经为你的应用程序设置了基本路由，需要学会如何调试你的 Angular 应用程序，然后再进行设置懒加载模块和子组件。

# Angular Augury

Augury 是用于调试和分析 Angular 应用的 Chrome Dev Tools 扩展。这是一个专门为帮助开发人员直观地浏览组件树、检查路由器状态，并通过对开发人员编写的 TypeScript 代码和生成的 JavaScript 代码进行源映射来启用断点调试的工具。您可以从[augury.angular.io](http://augury.angular.io)下载 Augury。安装完成后，当您打开 Chrome Dev Tools 查看您的 Angular 应用时，您会注意到一个新的 Augury 选项卡，如下图所示：

![图 3](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/77a0c9d5-5c32-476d-b2e3-78dbc2c1ab49.png)

Chrome Dev Tools Augury

Augury 在理解您的 Angular 应用在运行时的行为方面提供了有用且关键的信息：

1.  当前的 Angular 版本列在此处，例如，版本为 5.1.2

1.  组件树

1.  路由器树显示了应用程序中已配置的所有路由

1.  NgModules 显示了应用程序的`AppModule`和子模块

# 组件树

“组件树”选项卡显示了所有应用程序组件的关系以及它们如何相互交互：

1.  选择特定的组件，例如`HomeComponent`，如下所示：

![图 2](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/52ec135a-aa7e-4736-b2d2-d5cbb7b028b7.png)

Augury 组件树

右侧的“属性”标签页将显示一个名为“查看源代码”的链接，您可以使用它来调试您的组件。在下面更深的位置，您将能够观察到组件的属性状态，例如显示的登录布尔值，以及您注入到组件中的服务及其状态。

您可以通过双击值来更改任何属性的值。例如，如果您想将`displayLogin`的值更改为`false`，只需双击包含真值的蓝色框，并键入 false 即可。您将能够观察到您的更改对您的 Angular 应用的影响。

为了观察`HomeComponent`的运行时组件层次结构，您可以观察注入器图。

1.  点击“注入器图”选项卡，如下所示：

![图 1](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/56a2334d-f80e-447f-8cce-06693543920e.png)

Augury 注入器图

此视图展示了您选择的组件是如何渲染出来的。在这种情况下，我们可以观察到`HomeComponent`是在`AppComponent`内部渲染的。这种可视化对于追踪陌生代码库中特定组件的实现或存在深层组件树的情况非常有帮助。

# 断点调试

让我再次重申一下，`console.log`语句绝对不应该提交到你的代码库。一般来说，它们只会浪费你的时间，因为这需要编辑代码，之后还得清理你的代码。此外，Augury 已经提供了组件的状态，所以在简单的情况下，你应该能够利用它来观察或转换状态。

有些特定用例，`console.log`语句可能会很有用。这些大多是操作在并行运行且依赖及时用户交互的异步工作流。在这些情况下，控制台日志可以帮助您更好地理解事件流和各个组件之间的交互。

Augury 还不够复杂，无法解析异步数据或通过函数返回的数据。还有其他常见情况，您可能想观察属性状态在设置时的变化，甚至能够在运行时改变它们的值，以强制代码执行`if`-`else`或`switch`语句的分支逻辑。对于这些情况，您应该使用断点调试。

假设`HomeComponent`上存在一些基本逻辑，根据从`AuthService`获取的`isAuthenticated`值设置`displayLogin`布尔值，如下所示：

```ts
src/app/home/home.component.ts
...
import { AuthService } from '../auth.service'
...
export class HomeComponent implements OnInit {
  displayLogin = true
  constructor(private authService: AuthService) {}

  ngOnInit() {
    this.displayLogin = !this.authService.isAuthenticated()
  }
}
```

现在观察`displayLogin`的值和`isAuthenticated`函数在设置时的状态，然后观察`displayLogin`值的变化：

1.  点击`HomeComponent`上的查看源链接

1.  在`ngOnInit`函数内的第一行上放一个断点

1.  刷新页面

1.  Chrome Dev 工具将切换到源选项卡，您将看到断点命中并在此处以蓝色突出显示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/8e106845-3195-4a27-b870-7846a6d37e01.png)

Chrome Dev 工具断点调试

1.  悬停在`this.displayLogin`上，观察其值已设置为`true`

1.  如果悬停在`this.authService.isAuthenticated()`上，您将无法观察其值

在断点命中时，您可以在控制台中访问当前范围的状态，这意味着您可以执行函数并观察其值。

1.  在控制台中执行`isAuthenticated()`

```ts
> !this.authService.isAuthenticated()
true
```

您会观察到它返回`true`，这就是`this.displayLogin`的值。您仍然可以在控制台中强制`displayLogin`的值。

1.  将`displayLogin`设置为`false`

```ts
> this.displayLogin = false
false
```

如果观察`displayLogin`的值，无论是悬停在上面还是从控制台检索，您会看到值被设置为`false`。

利用断点调试基础知识，您可以在一点也不改变源代码的情况下调试复杂的场景。

# 路由树

路由树选项卡将显示路由器的当前状态。这可以是一个非常有用的工具，可以直观地展示路由和组件之间的关系，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/122bac61-a7ce-438c-b1a1-36abd2c4044e.png)

Augury 路由树

上述路由树展示了一个深套的路由结构，带有主细节视图。您可以通过点击圆形节点来看到呈现给定组件所需的绝对路径和参数。

正如您所看到的，对于`PersonDetailsComponent`，确定渲染这个主细节视图的一系列参数可能会变得复杂。

# NgModules

NgModules 选项卡显示`AppModule`和当前加载到内存中的任何其他子模块：

1.  启动应用的`/home`路由

1.  观察 NgModules 标签，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/1f7e47e0-937e-41a1-9dd2-1f115597640b.png)

Augury NgModules

您会注意到仅加载了`AppModule`。然而，由于我们的应用程序采用了延迟加载的架构，我们的其他模块尚未被加载。

1.  导航到`ManagerModule`中的一个页面

1.  然后，导航到`UserModule`中的一个页面

1.  最后，导航回`/home`路由

1.  观察 NgModules 标签，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/eb0747c8-e2c8-4467-a657-3e6db3ac2781.png)

带有三个模块的 Augury NgModules

1.  现在，您会观察到已加载进内存的三个模块。

NgModules 是一个重要的工具，可以可视化设计和架构的影响。

# 具有延迟加载的子模块

懒加载允许由 webpack 提供支持的 Angular 构建流程将我们的 Web 应用程序分隔成不同的 JavaScript 文件，称为块。通过将应用程序的各部分分开为单独的子模块，我们允许这些模块及其依赖项捆绑到单独的块中，从而将初始 JavaScript 捆绑大小保持在最小限度。随着应用程序的增长，首次有意义的呈现时间保持不变，而不是随时间持续增加。懒加载对实现可扩展的应用程序架构至关重要。

现在我们将介绍如何设置带有组件和路由的子模块。我们还将使用 Augury 来观察我们不同路由配置的效果。

# 配置子模块的组件和路由

管理员模块需要一个着陆页面，如此示意图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/37bfa672-ea69-4f47-bf18-0d3fb718dfab.png)

管理员仪表板

让我们先创建`ManagerModule`的主屏幕：

1.  创建`ManagerHome`组件：

```ts
$ npx ng g c manager/managerHome -m manager -s -t
```

为了在`manager`文件夹下创建新组件，我们必须在组件名称前加上`manager/`前缀。另外，我们指定该组件应该被`ManagerModule`导入和声明。由于这是另一个着陆页，可能不够复杂需要额外的 HTML 和 CSS 文件。您可以使用`--inline-style`（别名`-s`）和/或`--inline-template`（别名`-t`）来避免创建额外的文件。

1.  确认您的文件夹结构如下所示：

```ts
 /src
 ├───app
 │ │
 │ ├───manager
 │ │ │ manager-routing.module.ts
 │ │ │ manager.module.ts
 │ │ │
 │ │ └───manager-home
 │ │ manager-home.component.spec.ts
 │ │ manager-home.component.ts
```

1.  使用`manager-routing.module`配置`ManagerHome`组件的路由，类似于我们如何使用`app-route.module`配置`Home`组件：

```ts
src/app/manager/manager-routing.module.ts
import { ManagerHomeComponent } from './manager-home/manager-home.component'
import { ManagerComponent } from './manager.component'

const routes: Routes = [
  {
    path: '',
    component: ManagerComponent,
    children: [
      { path: '', redirectTo: '/manager/home', pathMatch: 'full' },
      { path: 'home', component: ManagerHomeComponent },
    ],
  },
]
```

您会注意到`http://localhost:5000/manager`实际上并不解析为一个组件，因为我们的 Angular 应用程序不知道`ManagerModule`的存在。让我们首先尝试蛮力、饥饿加载的方法，导入`manager.module`并在我们的应用程序中注册管理器路由。

# 预加载

此部分纯粹是为了演示我们迄今学到的导入和注册路由的概念，并不会产生可扩展的解决方案，无论是急切加载还是懒加载组件：

1.  将`manager.module`导入到`app.module`中：

```ts
 src/app/app.module.ts
 import { ManagerModule } from './manager/manager.module'
   ...
   imports: [
   ...
     ManagerModule,
   ]
```

你会发现`http://localhost:5000/manager`仍然不能渲染其主页组件。

1.  使用 Augury 调试路由器状态，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/7ff737cd-253a-4696-8099-e8954525ec07.png)

带有预加载的路由器树

1.  看起来`/manager`路径在正确地注册并指向正确的组件`ManagerHomeComponent`。这里的问题是，在`app-routing.module`中配置的`rootRouter`没有意识到`/manager`路径，所以`**`路径占据优先地位，导致呈现`PageNotFoundComponent`。

1.  作为最后的练习，在`app-routing.module`中实现`'manager'`路径，并像平常一样将`ManagerHomeComponent`指定给它：

```ts
src/app/app-routing.module.ts
import { ManagerHomeComponent } from './manager/manager-home/manager-home.component'  
...
const routes: Routes = [
  ...
  { path: 'manager', component: ManagerHomeComponent },
  { path: '**', component: PageNotFoundComponent },
]
```

现在你会注意到`http://localhost:5000/manager`正确地渲染，显示`manager-home works!`；然而，如果通过 Augury 调试路由器状态，你会注意到`/manager`被注册了两次。

这个解决方案不太可扩展，因为它要求所有开发者维护一个单一的主文件来导入和配置每个模块。这会导致合并冲突和沮丧，希望团队成员不会多次注册相同的路由。

可以设计一种解决方案将模块分成多个文件。你可以在`manager.module`中实现 Route 数组并将其导出，而不是使用标准的`*-routing.module`。考虑以下示例：

```ts
example/manager/manager.module
export const managerModuleRoutes: Routes = [
  { path: '', component: ManagerHomeComponent }
]
```

然后这些文件需要逐个被导入到`app-routing.module`中，并且使用`children`属性进行配置：

```ts
example/app-routing.module
import { managerModuleRoutes } from './manager/manager.module'
...
{ path: 'manager', children: managerModuleRoutes },
```

这个解决方案能够运行，是一个正确的解决方案，就像 Augury Router 树所展示的那样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/076e3b5e-6610-49bf-9327-82e885ce29ce.png)

带有子路由的路由器树

没有重复注册，因为我们删除了`manager-routing.module`。此外，我们不必在`manager.module`之外导入`ManagerHomeComponent`，从而得到一个更好的可扩展解决方案。然而，随着应用的增长，我们仍然必须在`app.module`中注册模块，并且子模块仍然与父`app.module`以可能不可预测的方式耦合。此外，这段代码无法被分块，因为使用 import 导入的任何代码都被视为硬依赖。

# 懒加载

现在你理解了模块的预加载是如何工作的，你将能更好地理解我们即将编写的代码，否则这些代码可能会看起来像黑魔法一样，并且神秘（也就是被误解的）代码总是导致混乱的架构。

我们现在将前面的预加载解决方案演变为懒加载的方式。为了从不同的模块加载路由，我们知道不能简单地导入它们，否则它们将被急切加载。答案就在于在`app-routing.module.ts`中配置路由时使用`loadChildren`属性，并提供字符串告知路由器如何加载子模块：

1.  确保你打算懒加载的任何模块都*不*被导入到``app.module``中

1.  移除`ManagerModule`中添加的任何路由

1.  确保将`ManagerRoutingModule`导入到`ManagerModule`中

1.  实现或更新带有`loadChildren`属性的管理路径：

```ts
src/app/app-routing.module.ts
import {
  ...
  const routes: Routes = [
    ...
    { path: 'manager', loadChildren: './manager/manager.module#ManagerModule' },
    { path: '**', component: PageNotFoundComponent },
  ]
  ...
```

通过一个巧妙的技巧实现了惰性加载，避免使用`import`语句。定义了一个由两部分组成的字符串文字，其中第一部分定义了模块文件的位置，如`app/manager/manager.module`，第二部分定义了模块的类名。这样的字符串可以在构建过程和运行时进行解释，以动态创建块，加载正确的模块并实例化正确的类。`ManagerModule`然后就像它自己的 Angular 应用程序一样，管理着它的所有子依赖项和路由。

1.  更新`manager-routing.module`路由，考虑到 manager 现在是它们的根路由：

```ts
src/app/manager/manager-routing.module.ts
const routes: Routes = [
  { path: '', redirectTo: '/manager/home', pathMatch: 'full' },
  { path: 'home', component: ManagerHomeComponent },
]
```

现在我们可以将`ManagerHomeComponent`的路由更新为更有意义的`'home'`路径。这个路径不会与`app-routing.module`中的路径冲突，因为在这个上下文中，`'home'`解析为`'manager/home'`，同样地，当路径为空时，URL 将看起来像`http://localhost:5000/manager`。

1.  通过观察 Augury 确认惰性加载是否正常运行，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/31d5b987-9e37-42c7-a579-988f2dad9381.png)

通过惰性加载的路由树

`ManagerHomeComponent`的根节点现在被命名为`manager [Lazy]`。

# 完成步行骨架

使用我们在本章早些时候为 LemonMart 创建的站点地图，我们需要完成应用的步行骨架导航体验。为了创建这种体验，我们需要创建一些按钮来链接所有模块和组件。我们将逐个模块进行：

+   在开始之前，更新`home.component`上的登录按钮，将其链接到`Manager`模块：

```ts
src/app/home/home.component.ts
 ...
 <button mat-raised-button color="primary" routerLink="/manager">Login as Manager</button>
 ...
```

# 管理员模块

由于我们已经为`ManagerModule`启用了惰性加载，让我们继续完成它的其余导航元素。

在当前设置中，`ManagerHomeComponent`在`app.component`中定义的`<router-outlet>`中呈现，因此当用户从`HomeComponent`导航到`ManagerHomeComponent`时，`app.component`中实现的工具栏保持不变。如果我们实现一个类似的工具栏，使其在`ManagerModule`中保持不变，我们可以为跨模块导航子页面创建一个一致的用户体验。

为实现这一点，我们需要在`app.component`和`home/home.component`之间复制父子关系，其中父级实现了工具栏和一个`<router-outlet>`，以便子元素可以在那里呈现。

1.  首先创建基本的`manager`组件：

```ts
$ npx ng g c manager/manager -m manager --flat -s -t
```

`--flat`选项跳过目录创建，直接将组件放在`manager`文件夹下，就像`app.component`直接放在`app`文件夹下一样。

1.  创建一个带有`activeLink`跟踪的导航工具栏：

```ts
src/app/manager/manager.component.ts
styles: [`
   div[fxLayout] {margin-top: 32px;}
   `, `
  .active-link {
    font-weight: bold;
    border-bottom: 2px solid #005005;
  }`
],
template: `
  <mat-toolbar color="accent">
    <a mat-button routerLink="/manager/home" routerLinkActive="active-link">Manager's Dashboard</a>
    <a mat-button routerLink="/manager/users" routerLinkActive="active-link">User Management</a>
    <a mat-button routerLink="/manager/receipts" routerLinkActive="active-link">Receipt Lookup</a>
  </mat-toolbar>
  <router-outlet></router-outlet>
`
```

必须注意，子模块不会自动访问父模块创建的服务或组件。这是为了保持解耦的架构的重要默认行为。然而，也有一些情况下希望分享一些代码。在这种情况下，`mat-toolbar` 需要重新导入。由于 `MatToolbarModule` 已经在 `src/app/material.module.ts` 中加载，我们只需要在 `manager.module.ts` 中导入这个模块，这样做不会带来性能或内存的损耗。

1.  `ManagerComponent` 应该被引入到 `ManagerModule` 中：

```ts
src/app/manager/manager.module.ts
import { MaterialModule } from '../material.module'
import { ManagerComponent } from './manager.component'
...
imports: [... MaterialModule, ManagerComponent],
```

1.  为子页面创建组件：

```ts
$ npx ng g c manager/userManagement -m manager
$ npx ng g c manager/receiptLookup -m manager
```

1.  创建父/子路由。我们知道我们需要以下路由才能导航到我们的子页面，如下：

```ts
example
{ path: '', redirectTo: '/manager/home', pathMatch: 'full' },
{ path: 'home', component: ManagerHomeComponent },
{ path: 'users', component: UserManagementComponent },
{ path: 'receipts', component: ReceiptLookupComponent },
```

为了定位到在 `manager.component` 中定义的 `<router-outlet>`，我们需要先创建父路由，然后为子页面指定路由：

```ts
src/app/manager/manager-routing.module.ts
...
const routes: Routes = [
  {
    path: '', component: ManagerComponent, children: [
      { path: '', redirectTo: '/manager/home', pathMatch: 'full' },
      { path: 'home', component: ManagerHomeComponent },
```

```ts
      { path: 'users', component: UserManagementComponent },
      { path: 'receipts', component: ReceiptLookupComponent },
    ]
  },
]
```

现在你应该能够浏览整个应用了。当你点击登录为管理者的按钮时，你将被带到这里显示的页面。可点击的目标被高亮显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/da476e0e-d0b1-400e-ab4a-bf00c34246fc.png)

带有可点击目标高亮显示的 Manager's Dashboard

如果你点击 LemonMart，你将被带到主页。如果你点击 Manager's Dashboard，User Management 或 Receipt Lookup，你将被导航到相应的子页面，同时工具栏上的活动链接将是粗体和下划线。

# 用户模块

登录后，用户将能够通过侧边导航菜单访问他们的个人资料，并查看他们可以在 LemonMart 应用程序中访问的操作列表。在第十四章，*设计认证和授权*，当我们实现认证和授权时，我们将从服务器接收到用户的角色。根据用户的角色，我们将能够自动导航或限制用户可以看到的选项。我们将在这个模块中实现这些组件，以便它们只有在用户登录后才被加载。为了完成骨架层，我们将忽略与认证相关的问题：

1.  创建必要的组件：

```ts
$ npx ng g c user/profile -m user
$ npx ng g c user/logout -m user -t -s
$ npx ng g c user/navigationMenu -m user -t -s
```

1.  实现路由：

从在 `app-routing` 中实现延迟加载开始：

```ts
src/app/app-routing.module.ts
... 
 { path: 'user', loadChildren: 'app/user/user.module#UserModule' },
```

确保 `PageNotFoundComponent` 路由总是在 `app-routing.module` 中的最后一个路由。

现在在 `user-routing` 中实现子路由：

```ts
src/app/user/user-routing.module.ts
...
const routes: Routes = [
  { path: 'profile', component: ProfileComponent },
  { path: 'logout', component: LogoutComponent },
]
```

我们正在为 `NavigationMenuComponent` 实现路由，因为它将直接被用作 HTML 元素。另外，由于 `userModule` 没有一个登陆页面，没有默认路径定义。

1.  连接用户和注销图标：

```ts
src/app/app.component.ts ...
<mat-toolbar>
  ...
  <button mat-mini-fab routerLink="/user/profile" matTooltip="Profile" aria-label="User Profile"><mat-icon>account_circle</mat-icon></button>
  <button mat-mini-fab routerLink="/user/logout" matTooltip="Logout" aria-label="Logout"><mat-icon>lock_open</mat-icon></button>
</mat-toolbar>
```

图标按钮可能难以理解，因此添加工具提示对它们是个好主意。为了使工具提示正常工作，切换到`mat-mini-fab`指令并确保在`material.module`中导入`MatTooltipModule`，此外，确保为只有图标的按钮添加`aria-label`，这样依赖于屏幕阅读器的残障用户仍然能够浏览您的 Web 应用。

1.  确保应用程序正常工作。

您会注意到两个按钮离得太近，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/cb91cc12-4942-4b77-91f3-2140190899b0.png)

带图标的工具栏

1.  您可以通过在`<mat-toolbar>`中添加`fxLayoutGap="8px"`来解决图标布局问题；但是现在柠檬标识离应用名称太远了，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/c3cefbb7-5579-4074-8cb8-1040b0458795.png)

带填充图标的工具栏

1.  通过合并图标和按钮来解决标识布局问题：

```ts
src/app/app.component.ts ...<mat-toolbar>  ...
  <a mat-icon-button routerLink="/home"><mat-icon svgIcon="lemon"></mat-icon><span class="mat-h2">LemonMart</span></a>
  ...
</mat-toolbar>
```

如下截图所示，分组修复了布局问题：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/13163991-6945-422d-a9bc-3859d916a9a6.png)

带有分组和填充元素的工具栏

从用户体验的角度来看这更加理想；现在用户可以通过点击柠檬回到主页。

# POS 和库存模块

我们的基本架构假定经理的角色。为了能够访问我们即将创建的所有组件，我们需要使经理能够访问 POS 和库存模块。

使用两个新按钮更新`ManagerComponent`：

```ts
src/app/manager/manager.component.ts
<mat-toolbar color="accent" fxLayoutGap="8px">
  ...
  <span class="flex-spacer"></span>
  <button mat-mini-fab routerLink="/inventory" matTooltip="Inventory" aria-label="Inventory"><mat-icon>list</mat-icon></button>
  <button mat-mini-fab routerLink="/pos" matTooltip="POS" aria-label="POS"><mat-icon>shopping_cart</mat-icon></button>
</mat-toolbar>
```

请注意，这些路由链接将导航我们离开`ManagerModule`，因此工具栏消失是正常的。

现在，由您来实现最后的两个模块。

# POS 模块

POS 模块与用户模块非常相似，除了`PosComponent`将成为默认路由。这将是一个复杂的组件，带有一些子组件，因此确保它是通过目录创建的：

1.  创建`PosComponent`

1.  注册`PosComponent`作为默认路由

1.  配置`PosModule`的懒加载

1.  确保应用程序正常工作

# 库存模块

库存模块与`ManagerModule`非常相似，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/accdce61-5a0f-4140-ba5a-0ecd8e79d133.png)

库存仪表板模拟

1.  创建基本的`Inventory`组件

1.  注册`MaterialModule`

1.  创建库存仪表板、库存录入、产品和类别组件

1.  在`inventory-routing.module`中配置父子路由

1.  配置`InventoryModule`的懒加载

1.  确保应用程序正常工作，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/520d2c6b-4597-4ccf-a386-8e444457afa9.png)

LemonMart 库存仪表板

现在应用程序的基本架构已经完成，检查路由树以确保懒加载已正确配置，并且模块不会被意外急加载是非常重要的。

# 检查路由树

转到应用程序的基本路由，并使用 Augury 检查路由树，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/30f96a6d-a4c2-42fc-8235-c5a800e074db.png)

路由树与急加载错误

一切，除了最初需要的组件，应该带有[Lazy]属性。 如果由于某种原因，路由未带有[Lazy]标记，那么它们可能被错误地导入到`app.module`或其他某个组件中。

在上述截图中，您可能会注意到`ProfileComponent`和`LogoutComponent`是急加载的，而`user`模块正确地标记为[Lazy]。 即使通过工具和代码基础进行多次视觉检查，也可能让您一直寻找问题所在。 但是，如果全局搜索`UserModule`，您将很快发现它正在被导入到`app.module`中。

为了保险起见，请确保删除`app.module`中的任何模块导入语句，您的文件应该像下面这样：

```ts
src/app/app.module.ts
import { FlexLayoutModule } from '@angular/flex-layout'
import { BrowserModule } from '@angular/platform-browser'
import { NgModule } from '@angular/core'

import { AppRoutingModule } from './app-routing.module'
import { AppComponent } from './app.component'
import { BrowserAnimationsModule } from '@angular/platform-browser/animations'
import { MaterialModule } from './material.module'
import { HomeComponent } from './home/home.component'
import { PageNotFoundComponent } from './page-not-found/page-not-found.component'
import { HttpClientModule } from '@angular/common/http'

@NgModule({
  declarations: [AppComponent, HomeComponent, PageNotFoundComponent],
  imports: [
    BrowserModule,
    AppRoutingModule,
    BrowserAnimationsModule,
    MaterialModule,
    HttpClientModule,
    FlexLayoutModule,
  ],
  providers: [],
  bootstrap: [AppComponent],
})
export class AppModule {}

```

下一张截图展示了更正后的路由树：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/87fb2c48-5d43-48d6-bf92-c48c0346a9e0.png)

带有延迟加载的路由树

在继续前进之前，请确保`npm test`和`npm run e2e`执行时没有错误。

# 通用测试模块

现在我们有大量的模块要处理，为每个规范文件单独配置导入和提供者变得乏味。 为此，我建议创建一个通用的测试模块，其中包含可以在整个项目中重用的通用配置。

首先创建一个新的`.ts`文件。

1.  创建`common/common.testing.ts`

1.  使用常见的测试提供程序、伪造品和模块填充，如下所示：

我提供了`ObservableMedia`、`MatIconRegistry`、`DomSanitizer`的伪造实现，以及`commonTestingProviders`和`commonTestingModules`的数组。

```ts
src/app/common/common.testing.ts
import { HttpClientTestingModule } from '@angular/common/http/testing'
import { MediaChange } from '@angular/flex-layout'
import { FormsModule, ReactiveFormsModule } from '@angular/forms'
import { SafeResourceUrl, SafeValue } from '@angular/platform-browser'
import { NoopAnimationsModule } from '@angular/platform-browser/animations'
// tslint:disable-next-line:max-line-length
import { SecurityContext } from '@angular/platform-browser/src/security/dom_sanitization_service'
import { RouterTestingModule } from '@angular/router/testing'
import { Observable, Subscription, of } from 'rxjs'
import { MaterialModule } from '../material.module'

const FAKE_SVGS = {
  lemon: '<svg><path id="lemon" name="lemon"></path></svg>',
}

export class ObservableMediaFake {
  isActive(query: string): boolean {
    return false
  }

  asObservable(): Observable<MediaChange> {
    return of({} as MediaChange)
  }

  subscribe(
    next?: (value: MediaChange) => void,
    error?: (error: any) => void,
    complete?: () => void
  ): Subscription {
    return new Subscription()
  }
}

export class MatIconRegistryFake {
  _document = document
  addSvgIcon(iconName: string, url: SafeResourceUrl): this {
    // this.addSvgIcon('lemon', 'lemon.svg')
    return this
  }

  getNamedSvgIcon(name: string, namespace: string = ''): Observable<SVGElement> {
    return of(this._svgElementFromString(FAKE_SVGS.lemon))
  }

  private _svgElementFromString(str: string): SVGElement {
    if (this._document || typeof document !== 'undefined') {
      const div = (this._document || document).createElement('DIV')
      div.innerHTML = str
      const svg = div.querySelector('svg') as SVGElement
      if (!svg) {
        throw Error('<svg> tag not found')
      }
      return svg
    }
  }
}

export class DomSanitizerFake {
  bypassSecurityTrustResourceUrl(url: string): SafeResourceUrl {
    return {} as SafeResourceUrl
  }
  sanitize(context: SecurityContext, value: SafeValue | string | null): string | null {
    return value ? value.toString() : null
  }
}

export const commonTestingProviders: any[] = [
  // intentionally left blank
]

export const commonTestingModules: any[] = [
  FormsModule,
  ReactiveFormsModule,
  MaterialModule,
  NoopAnimationsModule,
  HttpClientTestingModule,
  RouterTestingModule,
]

```

现在让我们看看如何使用共享配置文件的示例：

```ts
src/app/app.component.spec.ts import { commonTestingModules,
 commonTestingProviders,
 MatIconRegistryFake,
 DomSanitizerFake,
 ObservableMediaFake,
} from './common/common.testing'
import { ObservableMedia } from '@angular/flex-layout'
import { MatIconRegistry } from '@angular/material'
import { DomSanitizer } from '@angular/platform-browser'

...
TestBed.configureTestingModule({
      imports: commonTestingModules,
      providers: commonTestingProviders.concat([
        { provide: ObservableMedia, useClass: ObservableMediaFake },
        { provide: MatIconRegistry, useClass: MatIconRegistryFake },
        { provide: DomSanitizer, useClass: DomSanitizerFake },
      ]),
      declarations: [AppComponent],
...
```

大多数其他模块只需导入`commonTestingModules`即可。

在所有测试通过之前，请不要继续前进！

# 总结

在本章中，您学会了如何有效地使用 Angular CLI 创建主要的 Angular 组件和脚手架。 您创建了应用程序的品牌，利用自定义和内置 Material 图标。 您学会了如何使用 Augury 调试复杂的 Angular 应用程序。 最后，您开始构建基于路由的应用程序，及早定义用户角色，设计时考虑懒加载，并及早确定行为骨架导航体验。

总结一下，为了完成基于路由的实现，您需要执行以下操作：

1.  早期定义用户角色

1.  设计时考虑懒加载

1.  实现行为骨架导航体验

1.  围绕主要数据组件进行设计

1.  强制执行解耦的组件架构

1.  区分用户控件和组件

1.  最大化代码重用

在本章中，您执行了步骤 1-3；在接下来的三章中，您将执行步骤 4-7。在第十三章中，*持续集成和 API 设计*，我们将讨论围绕主要数据组件进行设计，并实现持续集成以确保高质量的交付。在第十四章中，*设计身份验证和授权*，我们将深入探讨安全考虑因素，并设计有条件的导航体验。在第十五章中，*Angular 应用设计和配方*，我们将通过坚持解耦组件架构，巧妙选择创建用户控件与组件，并利用各种 TypeScript、RxJS 和 Angular 编码技术来最大程度地重用代码，将所有内容紧密结合在一起。
