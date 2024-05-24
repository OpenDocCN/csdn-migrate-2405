# Angular6 面向企业级的 Web 开发（三）

> 原文：[`zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992`](https://zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：响应式表单和组件交互

到目前为止，您一直在努力组合构成 Angular 应用程序的基本元素，比如模块、组件、管道、服务、RxJS、单元测试、环境变量，甚至更进一步地学习如何使用 Docker 交付您的 Web 应用程序，并使用 Angular Material 使其看起来更加精致。

为了构建真正动态的应用程序，我们需要构建能够实现丰富用户交互并利用现代网络功能的功能，比如`LocalStorage`和`GeoLocation`。您还需要熟练掌握新的 Angular 语法，以有效地利用绑定、条件布局和重复元素。

您需要能够使用 Angular 表单来创建带有验证消息的输入字段，使用搜索即时输入功能创建引人入胜的搜索体验，为用户提供自定义其偏好的方式，并能够在本地和服务器上持久保存这些信息。您的应用程序可能会有多个共享数据的组件。

随着您的应用程序不断发展，并且有更多的人参与其中或者与同事交流您的想法，仅仅用手绘草图就变得越来越困难。这意味着我们需要一个更专业的模拟，最好是一个交互式的模拟，以最好地展示应用程序的计划用户体验。

在本章中，您将做以下事情：

1.  了解这些：

+   双向绑定

+   模板驱动表单

1.  熟练掌握组件之间的交互

1.  能够创建这些：

+   交互式原型

+   使用 Angular 响应式表单进行输入字段和验证

# 交互式原型

外观确实很重要。无论您是在开发团队工作还是作为自由职业者，您的同事、老板或客户总是会更认真地对待一个精心准备的演示。在第二章中，*创建本地天气 Web 应用程序*，我提到了成为全栈开发人员的时间和信息管理挑战。我们必须选择一个可以在最少的工作量下取得最佳结果的工具。这通常意味着选择付费工具，但 UI/UX 设计工具很少是免费或便宜的。

原型工具将帮助您创建一个更好、更专业的应用程序模拟。无论您选择哪种工具，都应该支持您选择使用的 UI 框架，在这种情况下是 Material。

如果一张图片价值千言万语，那么你的应用的交互式原型价值千行代码。应用的交互式模型将帮助你在编写一行代码之前审查想法，并节省大量的代码编写。

# MockFlow WireFramePro

我选择了 MockFlow WireFramePro，[`mockflow.com`](https://mockflow.com)，作为一个易于使用、功能强大且在线支持 Material design UI 元素的工具，它允许你创建多个页面，然后将它们链接在一起，以创建一个工作应用程序的幻觉。

最重要的是，在发布时，MockFlow 允许永远免费使用一个完整功能集和功能。这将给你一个机会真正审查工具的有用性，而不受人为限制或者试用期的影响，试用期总是比你预期的要快得多。

Balsamiq 是更知名的线框工具。然而，[`balsamiq.com`](https://balsamiq.com)没有提供免费使用，但如果你正在寻找一个没有月费的工具，我强烈推荐 Balsamiq 的桌面应用 Mockups，它只需要一次购买费用。

# 构建模型

我们首先添加一个新任务来创建一个交互式原型，在任务结束时，我会将所有工件附加到这个任务上，这样它们就存储在 GitHub 上，所有团队成员都可以访问，也可以从 Wiki 页面链接进行持久性文档化。让我们将这个新任务拉到进行中的列，并查看来自 Waffle.io 的看板板的状态：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/049df723-d8b0-41be-b5d0-4118eba0e49a.png)

WireframePro 作为一个拖放设计界面非常直观，所以我不会详细介绍工具的工作原理，但我会强调一些技巧：

1.  创建你的项目

1.  选择一个组件包，可以是手绘 UI 或者 Material design

1.  将每个屏幕作为一个新页面添加，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/80ba1e1d-9144-4b72-9d9a-8b6794bd804a.png)MockFlow.com WireFrame Pro

我建议坚持手绘 UI 的外观和感觉，因为它能够为你的观众设定正确的期望。如果你在与客户的第一次会议上展示了一个非常高质量的模型，你的第一个演示将是一个低调的陈述。你最多只能满足期望，最坏的情况下，会让你的观众感到失望。

# 主屏幕

这是主屏幕的新模型：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/fbab9fda-4d66-43a7-81c9-0d0d0735e807.png)LocalCast Weather Wireframe

您会注意到一些不同之处，比如应用工具栏与浏览器栏的混合以及重复元素的故意模糊。我做出这些选择是为了减少我需要在每个屏幕上花费的设计时间。我只是使用水平和垂直线对象来创建网格。

# 搜索结果

搜索屏幕同样故意保持模糊，以避免必须维护任何详细信息。令人惊讶的是，您的观众更有可能关注您的测试数据，而不是关注设计元素。

通过含糊不清，我们故意让观众的注意力集中在重要的事情上。以下是搜索屏幕的模拟：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e40d3db6-04ae-45dc-b22c-da7ecc88ed57.png)LocalCast 天气搜索线框图

# 设置窗格

设置窗格是一个单独的屏幕，其中包含从主屏幕复制并应用了 85%不透明度的元素，以创建类似模型的体验。设置窗格本身只是一个带有黑色边框和纯白背景的矩形。

看一下以下的模拟：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/2cfeee5a-082d-4288-89d9-29c04de3bdf2.png)LocalCast 天气设置线框图

# 添加交互性

能够点击模拟并了解导航工作流程的感觉是一个无法或缺的工具，可以获得早期用户反馈。这将为您和您的客户节省大量的沮丧、时间和金钱。

要将元素链接在一起，请按照以下步骤操作：

1.  选择主屏幕上的可点击元素，如*齿轮*图标

1.  在链接子标题下，点击选择页面

1.  在弹出窗口中，选择设置

1.  点击创建链接，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e8d1d737-cf40-4edc-a9ef-e782fd021d1b.png)WireFrame Pro - 添加链接

现在，当您点击*齿轮*图标时，工具将显示设置页面，这将在同一页面上创建侧边栏实际显示的效果。要返回主屏幕，您可以将齿轮图标和侧边栏外部的部分链接回该页面，以便用户可以来回导航。

# 导出功能原型

一旦您的原型完成，您可以将其导出为各种格式：

1.  选择导出线框图按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/bdb1f463-01af-4ea6-b162-1fb6d0bbe731.png)WireFrame Pro - 导出线框图

1.  现在选择您的文件格式，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/3303b71e-2d1a-4c69-99b1-9708eb0d0356.png)WireFrame Pro - 文件格式

我更喜欢 HTML 格式，因为它更灵活；然而，您的工作流程和需求会有所不同。

1.  如果您选择了 HTML，您将获得一个 ZIP 捆绑包的所有资产。

1.  解压捆绑包并使用浏览器导航到它；您应该会得到您线框的交互版本，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/55daea75-657d-411f-b4bc-a14cad741628.png)WireFrame Pro - 交互式线框交互元素在以下截图中以黄色突出显示。您可以使用屏幕左下角的“显示链接”选项启用或禁用此行为。

您甚至可以使用`minimal-nginx-server`或`minimal-node-server`对原型 HTML 项目进行容器化，并使用相同的技术在 Zeit Now 上进行托管，这与第三章中讨论的准备 Angular 应用程序进行生产发布的技术完全相同。

现在将所有资产添加到 GitHub 问题的评论中，包括 ZIP 捆绑包，我们准备继续下一个任务。让我们将“添加城市搜索卡…”移动到“进行中”，如我们看板中所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/b3214869-cf27-471d-bee2-3f0b18d82e85.png)Waffle.io 看板

# 使用用户输入进行搜索

现在，我们将在应用程序的主屏幕上实现搜索栏。用户故事中指出显示当前位置的天气预报信息，这可能意味着具有地理位置功能。然而，正如您可能注意到的，地理位置被列为一个单独的任务。挑战在于，使用原生平台功能如地理位置，您永远无法保证获得实际的位置信息。这可能是由于移动设备的信号丢失问题，或者用户可能拒绝分享他们的位置信息。

首先，我们必须提供良好的基线用户体验，并实现增值功能，如地理位置功能。我们将实现搜索即时输入功能，同时向用户提供反馈，如果服务无法检索到预期的数据。

最初，实现类型搜索机制可能是直观的；然而，`OpenWeatherMap`API 并没有提供这样的端点。相反，它们提供昂贵且在兆字节范围内的大量数据下载。

我们需要实现自己的应用服务器来公开这样一个端点，以便我们的应用可以有效地查询，同时使用最少量的数据。

OpenWeatherMap 的免费端点确实带来了一个有趣的挑战，其中两位数的国家代码可能会伴随城市名称或邮政编码以获得最准确的结果。这是一个很好的机会，可以为用户实现反馈机制，如果对于给定的查询返回了多个结果。

我们希望应用程序的每次迭代都是一个潜在的可发布的增量，并且避免在任何给定时间做太多事情。

我们将执行以下操作：

1.  添加 Angular 表单控件

1.  使用 Angular Material Input，如在[`material.angular.io/components/input`](https://material.angular.io/components/input)中记录的那样。

1.  将搜索栏创建为其自己的组件

1.  扩展现有的端点以接受邮政编码，并使国家代码在`weather.service`中变为可选项

1.  节流请求

# 添加 Angular 响应式表单

您可能会想为什么我们要添加 Angular 表单，因为我们只添加了一个单个输入字段，而不是具有多个输入的表单。作为一个一般的经验法则，任何时候您添加任何输入字段，它都应该包装在`<form>`标签中。`Forms`模块包含`FormControl`，它使您能够编写支持输入字段背后的后备代码，以响应用户输入，并根据需要提供适当的数据、验证或响应消息。

Angular 中有两种类型的表单：

+   **模板驱动：** 这些表单类似于您可能熟悉的 AngularJS 中的表单，其中表单逻辑主要在 HTML 模板中。我个人不喜欢这种方法，因为很难测试这些行为，而且庞大的 HTML 模板很快就难以维护。

+   **响应式：** 响应式表单的行为由控制器中编写的 TypeScript 代码驱动。这意味着您的验证逻辑可以进行单元测试，并且更好的是可以在整个应用程序中重复使用。在[`angular.io/guide/reactive-forms`](https://angular.io/guide/reactive-forms)中了解更多关于响应式表单的信息。

让我们首先将`ReactiveFormsModule`导入到我们的应用程序中：

```ts
src/app/app.module.ts
...
import { FormsModule, ReactiveFormsModule } from '@angular/forms'
...
@NgModule({
  ...
  imports: [
    ...
    FormsModule,
    ReactiveFormsModule,
    ...
```

响应式表单是使 Angular Material 团队能够编写更丰富的工具的核心技术，例如可以根据将来的 TypeScript 接口自动生成输入表单的工具。

# 添加和验证组件

我们将使用 Material 表单和输入模块创建一个`citySearch`组件：

1.  将`MatFormFieldModule`和`MatInputModule`添加到`material.module`中，以便在应用程序中可用：

```ts
src/app/material.module.ts
import {
  ...
  MatFormFieldModule,
  MatInputModule,
} from '@angular/material'
...
@NgModule({
  imports: [
    ...
    MatFormFieldModule,
    MatInputModule,
  ],
  exports: [
    ...
    MatFormFieldModule,
    MatInputModule,
  ],
})
```

我们正在添加`MatFormFieldModule`，因为每个输入字段都应该包装在`<mat-form-field>`标签中，以充分利用 Angular Material 的功能。在高层次上，`<form>`封装了键盘、屏幕阅读器和浏览器扩展用户的许多默认行为；`<mat-form-field>`实现了简单的双向数据绑定，这种技术应该适度使用，并且还允许优雅的标签、验证和错误消息显示。

1.  创建新的`citySearch`组件：

```ts
$ npx ng g c citySearch --module=app.module
```

由于我们添加了`material.module.ts`文件，`ng`无法猜测应将城市搜索功能模块添加到哪里，导致出现错误，例如*More than one module matches*。因此，我们需要使用`--module`选项提供要将`citySearch`添加到的模块。使用`--skip-import`选项跳过将组件导入到任何模块中。

1.  创建一个基本模板：

```ts
src/app/city-search/city-search.component.html
<form>
  <mat-form-field>
    <mat-icon matPrefix>search</mat-icon>
    <input matInput placeholder="Enter city or zip" aria-label="City or Zip" [formControl]="search">
  </mat-form-field>
</form>
```

1.  导入并实例化`FormControl`的实例：

```ts
src/app/city-search/city-search.component.ts
import { FormControl } from '@angular/forms'
...
export class CitySearchComponent implements OnInit {
  search = new FormControl()
  ...
```

响应式表单有三个级别的控件：

+   `FormControl`是与输入字段具有一对一关系的最基本元素

+   `FormArray`表示重复的输入字段，表示对象的集合

+   `FormGroup`用于将单独的`FormControl`或`FormArray`对象注册为您向表单添加更多输入字段时

最后，`FormBuilder`对象用于更轻松地编排和维护`FormGroup`的操作，这将在第十章中进行介绍，*Angular 应用设计和示例*。

1.  在包含`app-current-weather`的外部行的标题之间，在`app.component`中添加`app-city-search`：

```ts
src/app/app.component.ts
...
  </div>    
  <div fxLayoutAlign="center">
    <app-city-search></app-city-search>
  </div>
  <div fxLayout="row">
...
```

1.  通过在浏览器中查看应用程序来测试组件的集成，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f608032f-7d6a-4379-9c1a-0ae47d4c7a54.png)带有搜索字段的 LocalWeather 应用

如果没有错误，现在我们可以开始添加`FormControl`元素并将它们连接到搜索端点。

# 向天气服务添加搜索

到目前为止，我们一直在通过名称和国家代码传递参数来获取城市的天气。通过允许用户输入邮政编码，我们必须使我们的服务更灵活，以接受两种类型的输入。

OpenWeatherMap 的 API 接受 URI 参数，因此我们可以使用 TypeScript 联合类型重构现有的`getCurrentWeather`函数，并使用类型守卫，我们可以提供不同的参数，同时保持类型检查：

1.  重构`weather.service`中的`getCurrentWeather`函数以处理邮政编码和城市输入：

```ts
app/src/weather/weather.service.ts  
  getCurrentWeather(
    search: string | number,
    country?: string
  ): Observable<ICurrentWeather> {
    let uriParams = ''
    if (typeof search === 'string') {
      uriParams = `q=${search}`
    } else {
      uriParams = `zip=${search}`
    }

    if (country) {
      uriParams = `${uriParams},${country}`
    }

    return this.getCurrentWeatherHelper(uriParams)
  }
```

我们将城市参数重命名为`search`，因为它可以是城市名称或邮政编码。然后，我们允许其类型为`string`或`number`，并根据运行时的类型，我们将使用`q`或`zip`。如果存在，我们还将`country`设置为可选，并仅在查询中追加它。

`getCurrentWeather`现在嵌入了业务逻辑，因此是单元测试的良好目标。遵循单一职责原则，从 SOLID 原则中，我们将 HTTP 调用重构为自己的函数，称为`getCurrentWeatherHelper`。

1.  将 HTTP 调用重构为`getCurrentWeatherHelper`。

在下一个示例中，请注意使用反引号字符`` ` ``而不是单引号字符`'`，它利用了允许在JavaScript中嵌入表达式的模板文字功能：

```ts
src/app/weather/weather.service.ts  
  private getCurrentWeatherHelper(uriParams: string): Observable<ICurrentWeather> {
    return this.httpClient
      .get<ICurrentWeatherData>(
        `${environment.baseUrl}api.openweathermap.org/data/2.5/weather?` +
          `${uriParams}&appid=${environment.appId}`
      )
      .pipe(map(data => this.transformToICurrentWeather(data)))
  }
```

作为积极的副作用，`getCurrentWeatherHelper` 遵循了开闭原则，因为我们可以通过提供不同的`uriParams` 来改变函数的行为，所以它对扩展是开放的，并且对修改是封闭的，因为它不需要经常被修改。

为了证明后一点，让我们实现一个新的函数，根据纬度和经度获取当前天气。

1.  实现`getCurrentWeatherByCoords`：

```ts
src/app/weather/weather.service.ts    
getCurrentWeatherByCoords(coords: Coordinates): Observable<ICurrentWeather> {
  const uriParams = `lat=${coords.latitude}&lon=${coords.longitude}`
  return this.getCurrentWeatherHelper(uriParams)
}
```

如你所见，`getCurrentWeatherHelper` 可以在不做任何修改的情况下容易地进行扩展。

1.  确保您更新`IWeatherService`和之前所做的更改保持一致。

作为遵循 SOLID 设计原则的结果，我们更容易地对流控制逻辑进行鲁棒的单元测试，最终编写出更具韧性、更便宜维护的代码。

# 实现搜索：

现在，让我们将新的服务方法与输入字段连接起来：

1.  更新`citySearch`以注入`weatherService`并订阅输入更改:

```ts
src/app/city-search/city-search.component.ts
...
export class CitySearchComponent implements OnInit {
  search = new FormControl()  
  constructor(private weatherService: WeatherService) {}
  ...
  ngOnInit() {
    this.search.valueChanges
      .subscribe(...)
  } 
```

在此时，我们将所有输入都视为`string`。用户输入可以是城市、邮政编码，或用逗号分隔的城市和国家代码，或邮政编码和国家代码。而城市或邮政编码是必需的，国家代码是可选的。我们可以使用`String.split`函数来解析任何可能的逗号分隔输入，然后使用`String.trim`去除字符串的开头和结尾的任何空格。然后，我们通过遍历它们并使用`Array.map`来确保我们去除字符串的所有部分。

然后，我们使用三元运算符`?:`来处理可选参数，只有在存在值时才传递一个值，否则将其保留为未定义。

1.  实现搜索处理程序：

```ts
src/app/city-search/city-search.component.ts
this.search.valueChanges
  .subscribe((searchValue: string) => {
    if (searchValue) {
      const userInput = searchValue.split(',').map(s => s.trim())
      this.weatherService.getCurrentWeather(
        userInput[0],
        userInput.length > 1 ? userInput[1] : undefined
      ).subscribe(data => (console.log(data)))
    }
  })
```

1.  为用户添加有关可选国家功能的提示：

```ts
src/app/city-search/city-search.component.html
...    
  <mat-form-field>
    ...
    <mat-hint>Specify country code like 'Paris, US'</mat-hint>
  </mat-form-field>
...
```

在这一点上，订阅处理程序将调用服务器并将输出记录到控制台。

观察在 Chrome Dev Tools 中如何工作。注意`search`函数运行的频率以及我们未处理服务错误的情况。

# 使用节流/防抖限制用户输入：

如此，我们在每次按键输入时都向服务器发送请求。这不是期望的行为，因为它会导致糟糕的用户体验，耗尽电池寿命，造成浪费的网络请求，并在客户端和服务器端都引起性能问题。用户可能会打错字；他们可能会改变主意，然后很少有输入的前几个字符会产生有用的结果。

我们仍然可以监听每个按键输入，但不必对每个按键输入做出反应。通过利用节流/防抖，我们可以限制生成的事件数量到一个预定的时间间隔，并依然保持输入时搜索的功能。

请注意，`throttle`和`debounce`不是功能等效的，它们的行为会因框架而异。除了节流，我们希望捕获用户输入的最后一次输入。在`lodash`框架中，throttle 函数可以实现此需求，而在`RxJS`中，debounce 可以实现。请注意，此差异可能在将来的框架更新中得到修复。

可以很容易地使用`RxJS/debounceTime`将节流注入到可观察流中。

使用`pipe`实现`debounceTime`：

```ts
src/app/city-search/city-search.component.ts
import { debounceTime } from 'rxjs/operators'

    this.search.valueChanges
      .pipe(debounceTime(1000))
      .subscribe(...)
```

`debounceTime`最多每秒运行一次搜索，但在用户停止输入后也会运行最后一次搜索。相比之下，`RxJS/throttleTime`每秒只会运行一次搜索，并不一定捕获用户输入的最后几个字符。

RxJS 还具有`throttle`和`debounce`函数，您可以使用它们来实现自定义逻辑以限制不一定是基于时间的输入。

由于这是一个时间和事件驱动的功能，不可行进行断点调试。您可以在 Chrome Dev Tools | Network 选项卡中监视网络调用，但要获得有关搜索处理程序实际被调用的次数的更实时感觉，请添加一个`console.log`语句。

在代码中使用活动的`console.log`语句并不是一个好的实践。正如第三章*为生产发布准备 Angular 应用*中介绍的，`console.log`是一种低级的调试方法。这些语句使得很难阅读实际代码，这本身就具有很高的可维护性成本。所以，无论它们是被注释掉还是不是，都不要在代码中使用`console.log`语句。

# 实现输入验证和错误消息

`FormControl`是高度可定制的。它允许您设置默认初始值，添加验证器，或在模糊、更改和提交事件上监听更改，如下所示：

```ts
example
new FormControl('Bethesda', { updateOn: 'submit' })
```

我们不会用一个值来初始化`FormControl`，但我们需要实现一个验证器来禁止一个字符的输入：

1.  从`@angular/forms`导入`Validators`：

```ts
src/app/city-search/city-search.component.ts
import { FormControl, Validators } from '@angular/forms'
```

1.  修改`FormControl`以添加最小长度验证器：

```ts
src/app/city-search/city-search.component.ts
search = new FormControl('', [Validators.minLength(2)])
```

1.  修改模板以显示验证错误消息：

```ts
src/app/city-search/city-search.component.html
...  
<form style="margin-bottom: 32px">  
  <mat-form-field>
    ...
    <mat-error *ngIf="search.invalid">
      Type more than one character to search
    </mat-error>
  </mat-form-field>
</form>
...
```

请注意增加一些额外的间距以为长度较长的错误消息腾出空间。

如果您处理不同类型的错误，模板中的`hasError`语法可能会变得重复。您可能希望实现一个更可扩展的解决方案，可以通过代码进行自定义，如下所示：

```ts
example
<mat-error *ngIf="search.invalid">{{getErrorMessage()}}</mat-error>

getErrorMessage() {
   return this.search.hasError('minLength') ? 'Type more than one character to search' : '';
}
```

1.  修改`search`函数以不使用无效输入执行搜索：

```ts
src/app/city-search/city-search.component.ts
this.search.valueChanges.pipe(debounceTime(1000)).subscribe((searchValue: string) => {
      if (!this.search.invalid) {
        ...
```

不仅仅是简单检查`searchValue`是否已定义且不是空字符串，我们可以通过调用`this.search.invalid`来利用验证引擎进行更健壮的检查。

# 通过双向绑定实现模板驱动的表单

与响应式表单相对应的是模板驱动的表单。如果您熟悉 AngularJS 中的`ng-model`，您会发现新的`ngModel`指令是其 API 兼容的替代品。

在幕后，`ngModel`实现了一个自动将自身附加到`FormGroup`的`FormControl`。`ngModel`可以在`<form>`级别或单个`<input>`级别使用。您可以在[angular.io/api/forms/NgModel](https://angular.io/api/forms/NgModel)上了解更多关于`ngModel`的信息。

在本地天气应用中，我在`app.component.ts`中包含了一个名为`app-city-search-tpldriven`的组件的注释。您可以取消`app.component`中的注释以进行实验。让我们看看替代模板实现是什么样的：

```ts
src/app/city-search-tpldriven/city-search-tpldriven.component.html
  ...
    <input matInput placeholder="Enter city or zip" aria-label="City or Zip" 
      [(ngModel)]="model.search" (ngModelChange)="doSearch($event)"
      minlength="2" name="search" #search="ngModel">
  ...
    <mat-error *ngIf="search.invalid">
      Type more than one character to search
    </mat-error>
  ...

```

注意`ngModel`与`[()]`的“香蕉箱”双向绑定语法的使用。

组件中的差异实现如下：

```ts
src/app/city-search-tpldriven/city-search-tpldriven.component.ts
import { NgModel, Validators} from '@angular/forms'
...
export class CitySearchTpldrivenComponent implements OnInit {
   model = {
    search: '',
  }
  ...
  doSearch(searchValue) {
    const userInput = searchValue.split(',').map(s => s.trim())
    this.weatherService
      .getCurrentWeather(userInput[0], userInput.length > 1 ? userInput[1] : undefined)
      .subscribe(data => console.log(data))
  }
```

正如你所看到的，大部分逻辑是在模板中实现的，程序员需要保持对模板中的内容和控制器的活跃心智模型，并在两个文件之间来回切换，以对事件处理程序和验证逻辑进行更改。

此外，我们丢失了输入限制以及在输入无效状态时阻止服务调用的能力。当然，仍然可以实现这些功能，但它们需要繁琐的解决方案，而且并不完全适合新的 Angular 语法和概念。

# 启用组件交互

为了更新当前天气信息，我们需要`city-search`组件与`current-weather`组件进行交互。在 Angular 中，有四种主要的技术来实现组件之间的交互：

+   全局事件

+   父组件监听从子组件冒泡上来的信息

+   在模块内部工作的同级、父级或子级的组件，它们基于类似的数据流

+   父组件向子组件传递信息

# 全局事件

这是从编程早期开始就一直被利用的技术。在 JavaScript 中，你可能通过全局函数委托或 jQuery 的事件系统来实现这一点。在 AngularJS 中，你可能创建了一个服务并在其中存储值。

在 Angular 中，你仍然可以创建一个根级别的服务，在其中存储值，使用 Angular 的`EventEmitter`类（实际上是为指令而设计的），或使用`rxjs/Subscription`来为自己创建一个复杂的消息总线。

作为模式，全局事件容易被滥用，而不是帮助维护一个解耦的应用架构，随着时间的推移，它会导致全局状态。全局状态甚至是在控制器级别的本地状态，函数读取和写入任何给定类的变量，都是编写可维护和可单元测试软件的头号敌人。

最终，如果你将所有应用程序数据存储或者路由所有事件都在一个服务中以启用组件交互，那么你只是在发明一个更好的捕鼠夹。这是一种应该尽量避免的反模式。在后面的章节中，您将发现本质上我们仍然会使用服务来实现组件间的交互；然而，我想指出的是在灵活的架构和全局或集中式解耦方法之间存在一个细微的界限，后者无法很好地扩展。

# 使用事件发射器的子父关系

你的子组件应该完全不知道它的父组件。这是创建可重用组件的关键。

我们可以使用 app 组件作为父元素，实现城市搜索组件和当前天气组件之间的通信，让 `app` 模块控制器来协调数据。

让我们看看这个实现会是怎样的：

1.  `city-search` 组件通过 `@Output` 属性公开了一个 `EventEmitter`：

```ts
src/app/city-search/city-search.component.ts
import { Component, Output, EventEmitter } from '@angular/core'

export class CitySearchComponent implements OnInit {
  ...
  @Output() searchEvent = new EventEmitter<string>()

  ...
  this.search.valueChanges.debounceTime(1000).subscribe((searchValue: string) => {
      if (!this.search.invalid) {
        this.searchEvent.emit(this.searchValue)
      }
    })
  ...
}
```

1.  `app` 组件使用该信息，并调用 `weatherService`，设置 `currentWeather` 变量：

```ts
src/app/app.component.ts
template: `
  ...
    <app-city-search (searchEvent)="doSearch($event)"></app-city-search>
  ...
`

export class AppComponent {
  currentWeather: ICurrenWeather
  constructor() { }

  doSearch(searchValue) {
    const userInput = searchValue.split(',').map(s => s.trim())
    this.weatherService
      .getCurrentWeather(userInput[0], userInput.length > 1 ? userInput[1] : undefined)
      .subscribe(data => this.currentWeather = data)
  }
}
```

我们已经成功地向上传递了信息，现在我们必须能够将它传递给 `current-weather` 组件。

# 使用输入绑定的父子关系

按照定义，父组件将意识到它正在使用哪些子组件。由于 `currentWeather` 属性与 `current-weather` 组件上的 `current` 属性绑定，结果传递下来并显示。这是通过创建一个 `@Input` 属性来实现的：

```ts
src/app/current-weather/current-weather.component.ts
import { Component, Input } from '@angular/core'
...
export class CurrentWeatherComponent implements OnInit {
 @Input() current: ICurrentWeather
 ...
}
```

然后你可以更新 `app` 组件，将数据绑定到 `current` 天气上：

```ts
src/app/app.component.ts
template: `
  ...
    <app-current-weather [current]="currentWeather"></app-current-weather>
  ...
`
```

这种方式可能适用于创建耦合度较高的组件或用户控件，且不需要消耗外部数据的情况。一个很好的例子就是向 `current-weather` 组件添加预测信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/2860d596-cf91-4e23-b9c9-7a4a38620b59.png)天气预报线框图

每周的每一天都可以作为一个组件来实现，使用 `*ngFor` 进行重复，并且将这些信息合理地绑定到 `current-weather` 的子组件上是非常合理的：

```ts
example
<app-mini-forecast *ngFor="let dailyForecast of forecastArray     
  [forecast]="dailyForecast">
</app-mini-forecast>
```

通常，如果你在使用数据驱动的组件，父子或者子父通信模式将导致架构不够灵活，使得组件的重用或重新排列变得非常困难。考虑到不断变化的业务需求和设计，这是一个重要的教训需要牢记。

# 使用主题进行兄弟交互

组件互动的主要原因是发送或接收用户提供或从服务器接收的数据更新。在 Angular 中,你的服务公开 `RxJS.Observable` 端点,这些是数据流,你的组件可以订阅它们。`RxJS.Observer` 补充了 `RxJS.Observable` 作为 `Observable` 发出的事件的消费者。`RxJS.Subject` 将这两套功能合并到一个易于使用的对象中。您可以使用主题来描述属于特定数据集的流,比如正在显示的当前天气数据:

```ts
src/app/weather/weather.service.ts
import { Subject } from 'rxjs'
...
export class WeatherService implements IWeatherService {
   currentWeather: Subject<ICurrentWeather>
   ...
}
```

`currentWeather` 仍然是一个数据流,并不仅仅代表一个数据点。你可以通过订阅来订阅 `currentWeather` 数据的变化,或者可以按照以下方式发布对它的更改:

```ts
example
currentWeather.subscribe(data => (this.current = data))
currentWeather.next(newData)
```

`Subject` 的默认行为非常类似于通用的发布-订阅机制,比如 jQuery 事件。但是,在组件以不可预知的方式加载或卸载的异步世界中,使用默认的 `Subject` 并不是很有用。

有三种不同类型的 Subject:

+   `ReplaySubject`: 它将记住和缓存数据流中发生的所有数据点,以便订阅者可以在任何给定时间重放所有事件

+   `BehaviorSubject`: 它只记住最后一个数据点,同时继续监听新的数据点

+   `AsyncSubject`: 这是一次性事件,不希望再次发生

`ReplaySubject` 可能会对您的应用程序造成严重的内存和性能影响,所以应该谨慎使用。在 `current-weather` 的情况下,我们只对显示最新收到的天气数据感兴趣,但通过用户输入或其他事件,我们可以接收新数据,因此我们可以保持 `current-weather` 组件最新。 `BehaviorSubject` 将是满足这些需求的合适机制:

1.  在 `weatherService` 中定义 `BehaviorSubject` 并设置默认值:

```ts
app/src/weather/weather.service.ts
import { BehaviorSubject } from 'rxjs'
...
export class WeatherService implements IWeatherService {
  currentWeather = new BehaviorSubject<ICurrentWeather>({
    city: '--',
    country: '--',
    date: Date.now(),
    image: '',
    temperature: 0,
    description: '',
  })
  ...
}
```

1.  将 `current-weather` 组件更新为订阅新的 `BehaviorSubject`:

```ts
app/src/current-weather/current-weather.component.ts
...  
ngOnInit() {
  this.weatherService.currentWeather.subscribe(data => (this.current = data))
}
...
```

1.  将 `city-search` 组件更新为发布其接收到的数据到 `BehaviorSubject`:

```ts
app/src/city-search/city-search.component.ts
... 
this.weatherService
  .getCurrentWeather(
    userInput[0],
    userInput.length > 1 ? userInput[1] : undefined
  )
  .subscribe(data => this.weatherService.currentWeather.next(data))
...
```

1.  在浏览器中测试您的应用程序；它应该如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/0f9bdb7b-4799-4a07-b01d-0a8d466e63b7.png)土耳其布尔萨的天气信息

当您输入一个新的城市时，组件应该更新为该城市的当前天气信息。

在应用程序首次加载时，默认体验看起来有些问题。至少有两种不同的处理方式。首先是在`app`组件级别隐藏整个组件，如果没有数据显示。为了使其工作，我们将不得不将`weatherService`注入到`app`组件中，最终导致不太灵活的解决方案。另一种方法是能够更好地处理`current-weather`组件中缺少的数据。

为了使应用程序更好，您可以在应用程序启动时实现地理位置功能，以获取用户当前位置的天气。您还可以利用`window.localStorage`来存储上次显示的城市或从`window.geolocation`在初始启动时检索的上次位置。

在继续之前，不要忘记执行`npm test`和`npm run e2e`。读者可以自行修复单元测试和端到端测试。

# 摘要

这一章完成了我们对本地天气应用程序的工作。我们可以将`城市搜索`功能任务移动到`完成`列，如我们看板中所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a35b3b83-60f3-429f-a5e0-d2b5401aa8ba.png)Waffle.io 看板状态

在本章中，您学会了如何创建一个交互式原型，而不需要编写一行代码。然后，您使用`MatInput`、验证器、响应式表单和数据流驱动处理程序创建了一个搜索即时响应的功能。您还了解了不同的策略来实现组件间的交互和数据共享。最后，您了解了双向绑定和基于模板的表单。

LocalCast Weather 是一个简单的应用程序，我们用它来介绍 Angular 的基本概念。正如您所见，Angular 非常适合构建这样的小型和动态应用程序，同时向最终用户提供最少量的框架代码。您应该考虑利用 Angular 甚至用于快速而简单的项目，这在构建更大型的应用程序时也是一个很好的实践。在下一章中，您将使用路由器优先的方法来创建一个更复杂的**业务线**（**LOB**）应用程序，设计和构建可扩展的 Angular 应用程序，其中包括一流的身份验证和授权、用户体验以及涵盖大多数 LOB 应用程序需求的众多技巧。


# 第七章：创建一个路由优先的业务应用

业务应用（LOB）是软件开发世界的基础。根据维基百科的定义，LOB 是一个通用术语，指的是为特定客户交易或业务需求提供产品或一组相关产品。LOB 应用程序提供了展示各种功能和功能的良好机会，而无需涉及大型企业应用程序通常需要的扭曲或专业化场景。在某种意义上，它们是 80-20 的学习经验。然而，我必须指出有关 LOB 应用程序的一个奇怪之处——如果您最终构建了一个半有用的 LOB 应用程序，对它的需求将不受控制地增长，您很快就会成为自己成功的受害者。这就是为什么您应该把每个新项目的开始视为一个机会，一个编码的机会，以便更好地创建更灵活的架构。

在本章和其余章节中，我们将建立一个具有丰富功能的新应用程序，可以满足可扩展架构和工程最佳实践的 LOB 应用程序的需求，这将帮助您在有需求时快速启动并迅速扩展解决方案。我们将遵循路由优先的设计模式，依赖可重用的组件来创建一个名为 LemonMart 的杂货店 LOB。

在本章中，您将学会以下内容：

+   有效使用 CLI 创建主要的 Angular 组件和 CLI 脚手架

+   学习如何构建路由优先应用

+   品牌、自定义和材料图标

+   使用 Augury 调试复杂的应用程序

+   启用延迟加载

+   创建一个基本框架

本书提供的代码示例需要 Angular 版本 5 和 6。Angular 5 代码与 Angular 6 兼容。Angular 6 将在 LTS 中得到支持，直到 2019 年 10 月。代码存储库的最新版本可以在以下网址找到：

+   对于第 2 到 6 章，LocalCast Weather 在 [Github.com/duluca/local-weather-app](https://github.com/duluca/local-weather-app)

+   对于第 7 到 12 章，LemonMart 在 [Github.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)

# Angular 技巧表

在我们深入创建 LOB 应用程序之前，我为您提供了一个速查表，让您熟悉常见的 Angular 语法和 CLI 命令，因为在接下来的过程中，这些语法和命令将被使用，而不会明确解释它们的目的。花些时间来审查和熟悉新的 Angular 语法、主要组件、CLI 脚手架和常见管道。如果您的背景是 AngularJS，您可能会发现这个列表特别有用，因为您需要放弃一些旧的语法。

# 绑定

绑定，或数据绑定，指的是代码中变量与 HTML 模板或其他组件中显示或输入的值之间的自动单向或双向连接：

| **类型** | **语法** | **数据方向** |
| --- | --- | --- |

| 插值属性

属性

类

样式 | `{{expression}}``[target]="expression"``bind-target="expression"` | 从数据源单向

到视图目标 |

事件 | `(目标)="语句"` `on-目标="语句"` | 从视图目标单向

到数据源 |

| 双向 | `[(target)]="expression"` `bindon-target="expression"` | 双向 |
| --- | --- | --- |

来源：[`angular.io/guide/template-syntax#binding-syntax-an-overview`](https://angular.io/guide/template-syntax#binding-syntax-an-overview)

# 内置指令

指令封装了可以作为属性应用到 HTML 元素或其他组件的编码行为：

| **名称** | **语法** | **目的** |
| --- | --- | --- |
| 结构指令 | `*ngIf``*ngFor``*ngSwitch` | 控制 HTML 的结构布局，以及元素是否从 DOM 中添加或移除 |
| 属性指令 | `[class]``[style]``[(model)]` | 监听并修改其他 HTML 元素、属性、属性和组件的行为，如 CSS 类、HTML 样式和 HTML 表单元素 |

结构指令来源：[`angular.io/guide/structural-directives`](https://angular.io/guide/structural-directives)

属性指令来源：[`angular.io/guide/template-syntax#built-in-attribute-directives`](https://angular.io/guide/template-syntax#built-in-attribute-directives)

# 常见管道

管道修改了数据绑定值在 HTML 模板中的显示方式。

| **名称** | **目的** | **用法** |
| --- | --- | --- |
| 日期 | 根据区域设置规则格式化日期 | `{{date_value &#124; date[:format]}}` |
| 文本转换 | 将文本转换为大写、小写或标题大小写 | `{{value &#124; uppercase}}``{{value &#124; lowercase}}``{{value &#124; titlecase }}` |
| 小数 | 根据区域规则，将数字格式化 | `{{number &#124; number[:digitInfo]}}` |
| 百分比 | 根据区域规则，将数字格式化为百分比 | `{{number &#124; percent[:digitInfo]}}` |
| 货币 | 根据区域规则，将数字格式化为带有货币代码和符号的货币 | `{{number &#124; currency[:currencyCode [:symbolDisplay[:digitInfo]]]}}` |

管道来源：[`angular.io/guide/pipes`](https://angular.io/guide/pipes)

# 启动命令，主要组件和 CLI 脚手架

启动命令帮助生成新项目或添加依赖项。Angular CLI 命令帮助创建主要组件，通过自动生成样板脚手架代码来轻松完成。有关完整命令列表，请访问[`github.com/angular/angular-cli/wiki`](https://github.com/angular/angular-cli/wiki)：

| **名称** | **目的** | **CLI 命令** |
| --- | --- | --- |
| 新建 | 创建一个新的 Angular 应用程序，并初始化 git 存储库，配置好 package.json 和路由。从父文件夹运行。 | `npx @angular/cli new project-name --routing` |
| 更新 | 更新 Angular，RxJS 和 Angular Material 依赖项。如有必要，重写代码以保持兼容性。 | `npx ng update` |
| 添加材料 | 安装和配置 Angular Material 依赖项。 | `npx ng add @angular/material` |
| 模块 | 创建一个新的`@NgModule`类。使用`--routing`来为子模块添加路由。可选地，使用`--module`将新模块导入到父模块中。 | `ng g module new-module` |
| 组件 | 创建一个新的`@Component`类。使用`--module`来指定父模块。可选地，使用`--flat`来跳过目录创建，`-t`用于内联模板，和`-s`用于内联样式。 | `ng g component new-component` |
| 指令 | 创建一个新的`@Directive`类。可选地，使用`--module`来为给定子模块范围内的指令。 | `ng g directive new-directive` |
| 管道 | 创建一个新的`@Pipe`类。可选地，使用`--module`来为给定子模块范围内的管道。 | `ng g pipe new-pipe` |
| 服务 | 创建一个新的`@Injectable`类。使用`--module`为给定子模块提供服务。服务不会自动导入到模块中。可选地使用`--flat` false 在目录下创建服务。 | `ng g service new-service` |
| Guard | 创建一个新的`@Injectable`类，实现路由生命周期钩子`CanActivate`。使用`--module`为给定的子模块提供守卫。守卫不会自动导入到模块中。 | `ng g guard new-guard` |
| Class | 创建一个简单的类。 | `ng g class new-class` |
| Interface | 创建一个简单的接口。 | `ng g interface new-interface` |
| Enum | 创建一个简单的枚举。 | `ng g enum new-enum` |

为了正确地为自定义模块下列出的一些组件进行脚手架搭建，比如`my-module`，你可以在你打算生成的名称前面加上模块名称，例如`ng g c my-module/my-new-component`。Angular CLI 将正确地连接并将新组件放置在`my-module`文件夹下。

# 配置 Angular CLI 自动完成

在使用 Angular CLI 时，您将获得自动完成的体验。执行适合您的`*nix`环境的适当命令：

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

# 路由器优先架构

Angular 路由器，打包在`@angular/router`包中，是构建**单页应用程序**（**SPAs**）的中心和关键部分，它的行为和操作方式类似于普通网站，可以使用浏览器控件或缩放或微缩放控件轻松导航。

Angular 路由器具有高级功能，如延迟加载、路由器出口、辅助路由、智能活动链接跟踪，并且可以表达为`href`，这使得使用 RxJS `SubjectBehavior`的无状态数据驱动组件的高度灵活的路由器优先应用程序架构成为可能。

大型团队可以针对单一代码库进行工作，每个团队负责一个模块的开发，而不会互相干扰，同时实现简单的持续集成。谷歌之所以选择针对数十亿行代码进行单一代码库的工作，是有很好的原因的。事后的集成非常昂贵。

小团队可以随时重新调整他们的 UI 布局，以快速响应变化，而无需重新设计他们的代码。很容易低估由于布局或导航的后期更改而浪费的时间。这样的变化对于大型团队来说更容易吸收，但对于小团队来说是一项昂贵的努力。

通过延迟加载，所有开发人员都可以从次秒级的首次有意义的绘制中受益，因为在构建时将传递给浏览器的核心用户体验文件大小保持在最低限度。模块的大小影响下载和加载速度，因为浏览器需要做的越多，用户看到应用程序的第一个屏幕就需要的时间就越长。通过定义延迟加载的模块，每个模块都可以打包为单独的文件，可以根据需要单独下载和加载。智能活动链接跟踪可以提供卓越的开发人员和用户体验，非常容易实现突出显示功能，以指示用户当前活动的选项卡或应用程序部分。辅助路由最大化了组件的重用，并帮助轻松实现复杂的状态转换。通过辅助路由，您可以仅使用单个外部模板呈现多个主视图和详细视图。您还可以控制路由在浏览器的 URL 栏中向用户显示的方式，并使用`routerLink`在模板中和`Router.navigate`在代码中组合路由，驱动复杂的场景。

为了实现一个以路由为先的实现，您需要这样做：

1.  早期定义用户角色

1.  设计时考虑延迟加载

1.  实现一个骨架导航体验

1.  围绕主要数据组件进行设计

1.  执行一个解耦的组件架构

1.  区分用户控件和组件

1.  最大化代码重用

用户角色通常表示用户的工作职能，例如经理或数据录入专员。在技术术语中，它们可以被视为特定类别用户被允许执行的一组操作。定义用户角色有助于识别可以配置为延迟加载的子模块。毕竟，数据录入专员永远不会看到经理可以看到的大多数屏幕，那么为什么要将这些资产传递给这些用户并减慢他们的体验呢？延迟加载在创建可扩展的应用程序架构方面至关重要，不仅从应用程序的角度来看，而且从高质量和高效的开发角度来看。配置延迟加载可能会很棘手，这就是为什么及早确定骨架导航体验非常重要的原因。

识别用户将使用的主要数据组件，例如发票或人员对象，将帮助您避免过度设计您的应用程序。围绕主要数据组件进行设计将在早期确定 API 设计，并帮助定义`BehaviorSubject`数据锚点，以实现无状态、数据驱动的设计，确保解耦的组件架构，详见第六章，*响应式表单和组件交互*。

最后，识别封装了您希望为应用程序创建的独特行为的自包含用户控件。用户控件可能会被创建为具有数据绑定属性和紧密耦合的控制器逻辑和模板的指令或组件。另一方面，组件将利用路由器生命周期事件来解析参数并对数据执行 CRUD 操作。在早期识别这些组件重用将导致创建更灵活的组件，可以在路由器协调下在多个上下文中重用，最大程度地实现代码重用。

# 创建 LemonMart

LemonMart 将是一个中型的业务应用程序，拥有超过 90 个代码文件。我们将从创建一个新的 Angular 应用程序开始，其中包括路由和 Angular Material 的配置。

# 创建一个以路由为先的应用程序

采用以路由为先的方法，我们将希望在应用程序早期启用路由：

1.  您可以通过执行以下命令创建已经配置了路由的新应用程序：

确保未全局安装`@angular/cli`，否则可能会遇到错误：

```ts
$ npx @angular/cli new lemon-mart --routing
```

1.  一个新的`AppRoutingModule`文件已经为我们创建了：

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

我们将在 routes 数组中定义路由。请注意，routes 数组被传入以配置为应用程序的根路由，默认的根路由为`/`。

在配置您的`RouterModule`时，您可以传入其他选项来自定义路由器的默认行为，例如当您尝试加载已经显示的路由时，而不是不采取任何操作，您可以强制重新加载组件。要启用此行为，请创建您的路由器如下：`RouterModule.forRoot(routes, { onSameUrlNavigation: 'reload' })`。

1.  最后，`AppRoutingModule`被注册到`AppModule`中，如下所示：

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

以下是第 2-6 章中涵盖的配置步骤的快速摘要。如果您对某个步骤不熟悉，请参考之前的章节。在继续之前，您应该完成这些步骤：

1.  修改`angular.json`和`tslint.json`以强制执行您的设置和编码标准。

1.  安装`npm i -D prettier`

1.  将`prettier`设置添加到`package.json`

1.  将开发服务器端口配置为除`4200`之外的其他端口，例如`5000`

1.  添加`standardize`脚本并更新`start`和`build`脚本

1.  为 Docker 添加 npm 脚本到`package.json`

1.  建立开发规范并在项目中记录，`npm i -D dev-norms`然后`npx dev-norms create`

1.  如果您使用 VS Code，请设置`extensions.json`和`settings.json`文件

您可以配置 TypeScript Hero 扩展以自动组织和修剪导入语句，只需将`"typescriptHero.imports.organizeOnSave": true`添加到`settings.json`中。如果与设置`"files.autoSave": "onFocusChange"`结合使用，您可能会发现该工具在您尝试输入时会积极清除未使用的导入。确保此设置适用于您，并且不会与任何其他工具或 VS Code 自己的导入组织功能发生冲突。

1.  执行`npm run standardize`

参考第三章，*为生产发布准备 Angular 应用*，以获取更多配置细节。

您可以在[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)获取 Docker 的 npm 脚本，以及在[bit.ly/npmScriptsForAWS](http://bit.ly/npmScriptsForAWS)获取 AWS 的 npm 脚本。

# 配置 Material 和样式

我们还需要设置 Angular Material 并配置要使用的主题，如第五章中所述，*使用 Angular Material 增强 Angular 应用*：

1.  安装 Angular Material：

```ts
$ npx ng add @angular/material
$ npm i @angular/flex-layout hammerjs 
$ npx ng g m material --flat -m app
```

1.  导入和导出`MatButtonModule`，`MatToolbarModule`和`MatIconModule`

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

有关更多配置详细信息，请参阅第五章，*使用 Angular Material 增强 Angular 应用*。

# 设计 LemonMart

在构建从数据库到前端的基本路线图的同时，避免过度工程化非常重要。这个初始设计阶段对项目的长期健康和成功至关重要，团队之间任何现有的隔离必须被打破，并且整体技术愿景必须被团队的所有成员充分理解。这并不是说起来容易做起来难，关于这个话题已经有大量的书籍写成。

在工程领域，没有一个问题有唯一正确的答案，因此重要的是要记住没有一个人可以拥有所有答案，也没有一个人可以有清晰的愿景。技术和非技术领导者之间创造一个安全的空间，提供开放讨论和实验的机会是文化的一部分，这一点非常重要。能够在团队中面对这种不确定性所带来的谦卑和同理心与任何单个团队成员的技术能力一样重要。每个团队成员都必须习惯于把自己的自我放在一边，因为我们的集体目标将是在开发周期内发展和演变应用程序以适应不断变化的需求。如果你能够知道你已经成功了，那么你所创建的软件的各个部分都可以很容易地被任何人替换。

# 确定用户角色

我们设计的第一步是考虑您使用应用程序的原因。

我们为 LemonMart 设想了四种用户状态或角色：

+   认证用户，任何经过认证的用户都可以访问他们的个人资料

+   收银员，其唯一角色是为客户结账。

+   店员，其唯一角色是执行与库存相关的功能

+   经理，可以执行收银员和店员可以执行的所有操作，但也可以访问管理功能

有了这个想法，我们可以开始设计我们应用程序的高级设计。

# 使用站点地图确定高级模块

制作应用程序的高级站点地图，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/87ef861d-200d-4e44-bed9-807ca9b3e2c4.png)用户的登陆页面我使用了 MockFlow.com 的 SiteMap 工具来创建站点地图

显示在[`sitemap.mockflow.com`](https://sitemap.mockflow.com)。

在首次检查时，三个高级模块出现为延迟加载的候选项：

1.  销售点（POS）

1.  库存

1.  经理

收银员只能访问 POS 模块和组件。店员只能访问库存模块，其中包括库存录入、产品和类别管理组件的额外屏幕。

库存页面

最后，管理者将能够通过管理模块访问所有三个模块，包括用户管理和收据查找组件。

管理页面

启用所有三个模块的延迟加载有很大好处，因为收银员和店员永远不会使用属于其他用户角色的组件，所以没有理由将这些字节发送到他们的设备上。这意味着当管理模块获得更多高级报告功能或新角色添加到应用程序时，POS 模块不会受到应用程序增长的带宽和内存影响。这意味着更少的支持电话，并且在同一硬件上保持一致的性能更长的时间。

# 生成启用路由的模块

现在我们已经定义了高级组件作为管理者、库存和 POS，我们可以将它们定义为模块。这些模块将与您迄今为止创建的模块不同，用于路由和 Angular Material。我们可以将用户配置文件创建为应用程序模块上的一个组件；但是，请注意，用户配置文件只会用于已经经过身份验证的用户，因此定义一个专门用于一般经过身份验证用户的第四个模块是有意义的。这样，您将确保您的应用程序的第一个有效载荷保持尽可能小。此外，我们将创建一个主页组件，用于包含我们应用程序的着陆体验，以便我们可以将实现细节从`app.component`中排除出去：

1.  生成`manager`，`inventory`，`pos`和`user`模块，指定它们的目标模块和路由功能：

```ts
$ npx ng g m manager -m app --routing
$ npx ng g m inventory -m app --routing
$ npx ng g m pos -m app --routing
$ npx ng g m user -m app --routing
```

如第一章中所讨论的*设置您的开发环境*，如果您已经配置`npx`自动识别`ng`作为命令，您可以节省更多按键，这样您就不必每次都添加`npx`到您的命令中。不要全局安装`@angular/cli`。请注意缩写命令结构，其中`ng generate module manager`变成`ng g m manager`，同样，`--module`变成了`-m`。

1.  验证您是否没有 CLI 错误。

请注意，在 Windows 上使用`npx`可能会遇到错误，例如路径必须是字符串。收到未定义。这个错误似乎对命令的成功操作没有任何影响，这就是为什么始终要检查 CLI 工具生成的内容是至关重要的。

1.  验证文件夹和文件是否已创建：

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

1.  检查`ManagerModule`的连接方式。

子模块实现了类似于`app.module`的`@NgModule`。最大的区别是子模块不实现`bootstrap`属性，这是你的根模块所需的，用于初始化你的 Angular 应用程序：

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

由于我们指定了`-m`选项，该模块已被导入到`app.module`中：

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

此外，因为我们还指定了`--routing`选项，一个路由模块已经被创建并导入到`ManagerModule`中：

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

请注意，`RouterModule`正在使用`forChild`进行配置，而不是`forRoot`，这是`AppRouting`模块的情况。这样，路由器就能理解在不同模块上下文中定义的路由之间的正确关系，并且可以在这个例子中正确地在所有子路由前面添加`/manager`。

CLI 不尊重你的`tslint.json`设置。如果你已经正确配置了 VS Code 环境并使用 prettier，你的代码样式偏好将在你每个文件上工作时应用，或者在全局运行 prettier 命令时应用。

# 设计 home 路由

考虑以下模拟作为 LemonMart 的登陆体验：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/07e577f7-b81e-4f2a-8fbe-df27bafba4bd.png)LemonMart 登陆体验

与`LocalCastWeather`应用程序不同，我们不希望所有这些标记都在`App`组件中。`App`组件是整个应用程序的根元素；因此，它应该只包含将在整个应用程序中持续出现的元素。在下面的注释模拟中，标记为 1 的工具栏将在整个应用程序中持续存在。

标记为 2 的区域将容纳 home 组件，它本身将包含一个登录用户控件，标记为 3：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/791d4e08-a0ab-4976-ace6-00e9a9680d9c.png)LemonMart 布局结构

在 Angular 中，将默认或登陆组件创建为单独的元素是最佳实践。这有助于减少必须加载的代码量和在每个页面上执行的逻辑，但在利用路由器时也会导致更灵活的架构：

使用内联模板和样式生成`home`组件：

```ts
$ npx ng g c home -m app --inline-template --inline-style
```

现在，你已经准备好配置路由器了。

# 设置默认路由

让我们开始为 LemonMart 设置一个简单的路由：

1.  配置你的`home`路由：

```ts
src/app/app-routing.module.ts 
...
const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
]
...
```

我们首先为`'home'`定义一个路径，并通过设置组件属性来告知路由渲染`HomeComponent`。然后，我们将应用的默认路径`''`重定向到`'/home'`。通过设置`pathMatch`属性，我们始终确保主页路由的这个非常特定的实例将作为着陆体验呈现。

1.  创建一个带有内联模板的`pageNotFound`组件

1.  为`PageNotFoundComponent`配置通配符路由：

```ts
src/app/app-routing.module.ts 
...
const routes: Routes = [
  ...
  { path: '**', component: PageNotFoundComponent }
]
...
```

这样，任何未匹配的路由都将被重定向到`PageNotFoundComponent`。

# RouterLink

当用户登陆到`PageNotFoundComponent`时，我们希望他们通过`RouterLink`重定向到`HomeComponent`：

1.  实现一个内联模板，使用`routerLink`链接回主页：

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

这种导航也可以通过`<a href>`标签实现；然而，在更动态和复杂的导航场景中，您将失去诸如自动活动链接跟踪或动态链接生成等功能。

Angular 的引导过程将确保`AppComponent`在您的`index.html`中的`<app-root>`元素内。然而，我们必须手动定义我们希望`HomeComponent`呈现的位置，以完成路由器配置。

# 路由出口

`AppComponent`被视为在`app-routing.module`中定义的根路由的根元素，这使我们能够在此根元素内定义 outlets，以使用`<router-outlet>`元素动态加载任何我们希望的内容：

1.  配置`AppComponent`以使用内联模板和样式

1.  为您的应用程序添加工具栏

1.  将您的应用程序名称作为按钮链接添加，以便在点击时将用户带到主页

1.  添加`<router-outlet>`以渲染内容：

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

现在，主页的内容将在`<router-outlet>`内呈现。

# 品牌、自定义和 Material 图标

为了构建一个吸引人且直观的工具栏，我们必须向应用引入一些图标和品牌，以便用户可以通过熟悉的图标轻松浏览应用。

# 品牌

在品牌方面，您应该确保您的 Web 应用程序具有自定义色板，并与桌面和移动浏览器功能集成，以展示您应用的名称和图标。

# 色板

使用 Material Color 工具选择一个色板，如第五章中所讨论的，*使用 Angular Material 增强 Angular 应用*。这是我为 LemonMart 选择的色板：

```ts
https://material.io/color/#!/?view.left=0&view.right=0&primary.color=2E7D32&secondary.color=C6FF00
```

# 实现浏览器清单和图标

您需要确保浏览器在浏览器选项卡中显示正确的标题文本和图标。此外，应创建一个清单文件，为各种移动操作系统实现特定的图标，以便用户将您的网站固定在手机上时，会显示一个理想的图标，类似于手机上的其他应用图标。这将确保如果用户将您的 Web 应用添加到其移动设备的主屏幕上，他们将获得一个本地外观的应用图标：

1.  从设计师或网站（如[`www.flaticon.com`](https://www.flaticon.com)）获取您网站标志的 SVG 版本

1.  在这种情况下，我将使用一个特定的柠檬图片：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ba4618d3-21b7-4b40-b2e7-a4243495bb5a.jpg) LemonMart 的标志性标志在使用互联网上找到的图像时，请注意适用的版权。在这种情况下，我已经购买了许可证以便发布这个柠檬标志，但是您可以在以下网址获取您自己的副本，前提是您提供图像作者所需的归属声明：[`www.flaticon.com/free-icon/lemon_605070`](https://www.flaticon.com/free-icon/lemon_605070)。

1.  使用[`realfavicongenerator.net`](https://realfavicongenerator.net)等工具生成`favicon.ico`和清单文件

1.  根据您的喜好调整 iOS、Android、Windows Phone、macOS 和 Safari 的设置

1.  确保设置一个版本号，favicons 可能会因缓存而臭名昭著；一个随机的版本号将确保用户始终获得最新版本

1.  下载并提取生成的`favicons.zip`文件到您的`src`文件夹中。

1.  编辑`angular.json`文件以在您的应用程序中包含新的资产：

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

1.  将生成的代码插入到`index.html`的`<head>`部分中：

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

1.  确保您的新 favicon 显示正确

为了进一步推广您的品牌，请考虑配置自定义的 Material 主题并利用[`material.io/color`](https://material.io/color/)，如*第五章，使用 Angular Material 增强 Angular 应用*中所讨论的那样。

# 自定义图标

现在，让我们在您的 Angular 应用程序中添加您的自定义品牌。您将需要用于创建 favicon 的 svg 图标：

1.  将图像放在`src/app/assets/img/icons`下，命名为`lemon.svg`

1.  将`HttpClientModule`导入`AppComponent`，以便可以通过 HTTP 请求`.svg`文件

1.  更新`AppComponent`以注册新的 svg 文件作为图标：

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

现在让我们为菜单、用户资料和注销添加剩余的图标。

# Material 图标

Angular Material 可以与 Material Design 图标直接配合使用，可以在`index.html`中将其作为 Web 字体导入到您的应用程序中。也可以自行托管字体；但是，如果您选择这条路，您也无法获得用户的浏览器在访问其他网站时已经缓存了字体的好处，从而节省了下载 42-56 KB 文件的速度和延迟。完整的图标列表可以在[`material.io/icons/`](https://material.io/icons/)找到。

现在让我们使用一些图标更新工具栏，并为主页设置一个最小的模板，用于模拟登录按钮：

1.  确保 Material 图标`<link>`标签已添加到`index.html`：

```ts
src/index.html
<head>
  ...
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
</head>
```

有关如何自行托管的说明可以在[`google.github.io/material-design-icons/#getting-icons`](http://google.github.io/material-design-icons/#getting-icons)的自行托管部分找到。

配置完成后，使用 Material 图标非常容易。

1.  更新工具栏，将菜单按钮放置在标题左侧。

1.  添加一个`fxFlex`，以便将剩余的图标右对齐。

1.  添加用户个人资料和注销图标：

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

1.  添加一个最小的登录模板：

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

您的应用程序应该类似于这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/2af6a8ec-e862-4438-aedb-17741cc1c0af.png)LemonMart with minimal login

在实现和显示/隐藏菜单、个人资料和注销图标方面还有一些工作要做，考虑到用户的身份验证状态。我们将在第九章中涵盖这些功能，*设计身份验证和授权*。现在您已经为应用程序设置了基本路由，需要学习如何在移动到设置带有子组件的延迟加载模块之前调试您的 Angular 应用程序。

# Angular Augury

Augury 是用于调试和分析 Angular 应用程序的 Chrome Dev Tools 扩展。这是一个专门为帮助开发人员直观地浏览组件树、检查路由状态并通过源映射在生成的 JavaScript 代码和开发人员编写的 TypeScript 代码之间启用断点调试的工具。您可以从[augury.angular.io](http://augury.angular.io)下载 Augury。安装后，当您为 Angular 应用程序打开 Chrome Dev Tools 时，您会注意到一个新的 Augury 标签，如下所示：

Chrome Dev Tools Augury

Augury 在理解您的 Angular 应用程序在运行时的行为方面提供了有用和关键的信息：

1.  当前的 Angular 版本列出为版本 5.1.2

1.  组件树

1.  路由器树显示了应用程序中配置的所有路由

1.  NgModules 显示了`AppModule`和应用程序的子模块

# 组件树

组件树选项卡显示了所有应用程序组件之间的关系以及它们如何相互作用：

1.  选择特定组件，如`HomeComponent`，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/9149a7d0-d849-4eb5-a669-d1a34a27b6ac.png)Augury 组件树

右侧的属性选项卡将显示一个名为“查看源代码”的链接，您可以使用它来调试您的组件。在下面更深的地方，您将能够观察组件属性的状态，例如 displayLogin 布尔值，包括您注入到组件中的服务及其状态。

您可以通过双击值来更改任何属性的值。例如，如果您想将 displayLogin 的值更改为`false`，只需双击包含 true 值的蓝色框并输入 false。您将能够观察到您的更改在您的 Angular 应用程序中的影响。

为了观察`HomeComponent`的运行时组件层次结构，您可以观察注射器图。

1.  单击注射器图选项卡，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7a070a59-28ee-47dd-9537-c6abf5dfd6a9.png)Augury 注射器图

该视图显示了您选择的组件是如何被渲染的。在这种情况下，我们可以观察到`HomeComponent`在`AppComponent`内部被渲染。这种可视化在追踪陌生代码库中特定组件的实现或存在深层组件树的情况下非常有帮助。

# 断点调试

让我再次重申，`console.log`语句绝对不应该提交到您的代码库中。一般来说，它们是浪费您的时间，因为它需要编辑代码，然后清理您的代码。此外，Augury 已经提供了您组件的状态，因此在简单的情况下，您应该能够利用它来观察或强制状态。

有一些特定用例，其中`console.log`语句可能会有用。这些大多是并行操作的异步工作流，并且依赖于及时的用户交互。在这些情况下，控制台日志可以帮助您更好地理解事件流和各个组件之间的交互。

Augury 目前还不够复杂，无法解决异步数据或通过函数返回的数据。还有其他常见情况，你可能希望观察属性的状态在设置时，甚至能够实时更改它们的值，以强制代码执行`if`-`else`或`switch`语句中的分支逻辑。对于这些情况，你应该使用断点调试。

假设`HomeComponent`上存在一些基本逻辑，它根据从`AuthService`获取的`isAuthenticated`值设置了一个`displayLogin`布尔值，如下所示：

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

1.  在`ngOnInit`函数内的第一行上设置一个断点

1.  刷新页面

1.  Chrome Dev Tools 将切换到源标签页，你会看到断点被触发，如蓝色所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f5c756b8-0127-47e6-bbe3-b838ed2b9af7.png)Chrome Dev Tools 断点调试

1.  悬停在`this.displayLogin`上并观察其值设置为`true`

1.  如果悬停在`this.authService.isAuthenticated()`上，你将无法观察到其值

当你的断点被触发时，你可以在控制台中访问当前状态的作用域，这意味着你可以执行函数并观察其值。

1.  在控制台中执行`isAuthenticated()`：

```ts
> !this.authService.isAuthenticated()
true
```

你会注意到它返回了`true`，这就是`this.displayLogin`的设置值。你仍然可以在控制台中强制转换`displayLogin`的值。

1.  将`displayLogin`设置为`false`：

```ts
> this.displayLogin = false
false
```

如果你观察`displayLogin`的值，无论是悬停在上面还是从控制台中检索，你会发现值被设置为`false`。

利用断点调试基础知识，你可以在不改变源代码的情况下调试复杂的场景。

# 路由树

路由树标签将显示路由的当前状态。这可以是一个非常有用的工具，可以帮助你可视化路由和组件之间的关系，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/31dc905e-b0e8-43af-bf4f-4354bc30a8ce.png)Augury 路由树

前面的路由树展示了一个深度嵌套的路由结构，其中包含主细节视图。你可以通过点击圆形节点来查看渲染给定组件所需的绝对路径和参数。

如您所见，对于`PersonDetailsComponent`来说，确定需要渲染主细节视图中的详细部分所需的参数集可能会变得复杂。

# NgModules

NgModules 选项卡显示了当前加载到内存中的`AppModule`和任何其他子模块：

1.  启动应用程序的`/home`路由

1.  观察 NgModules 选项卡，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c0304718-ed0f-45b5-95a0-e2b33ce8641e.png)Augury NgModules

您会注意到只有`AppModule`被加载。但是，由于我们的应用程序采用了延迟加载的架构，我们的其他模块尚未被加载。

1.  导航到`ManagerModule`中的一个页面

1.  然后，导航到`UserModule`中的一个页面

1.  最后，导航回到`/home`路由

1.  观察 NgModules 选项卡，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/08d7ca69-7989-459b-bdff-77b76691b3d9.png)Augury NgModules with Three Modules

1.  现在，您会注意到已经加载了三个模块到内存中。

NgModules 是一个重要的工具，可以可视化设计和架构的影响。

# 具有延迟加载的子模块

延迟加载允许由 webpack 驱动的 Angular 构建过程将我们的 Web 应用程序分隔成不同的 JavaScript 文件，称为块。通过将应用程序的部分分离成单独的子模块，我们允许这些模块及其依赖项被捆绑到单独的块中，从而将初始 JavaScript 捆绑包大小保持在最小限度。随着应用程序的增长，首次有意义的绘制时间保持恒定，而不是随着时间的推移不断增加。延迟加载对于实现可扩展的应用程序架构至关重要。

现在我们将介绍如何设置具有组件和路由的子模块。我们还将使用 Augury 来观察我们各种路由配置的效果。

# 配置具有组件和路由的子模块

管理模块需要一个着陆页，如此模拟所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7dae93fc-fe0e-4ca2-a439-3e58106c8bb9.png)Manager's Dashboard 让我们从为`ManagerModule`创建主屏幕开始：

1.  创建`ManagerHome`组件：

```ts
$ npx ng g c manager/managerHome -m manager -s -t
```

为了在`manager`文件夹下创建新组件，我们必须在组件名称前面加上`manager/`前缀。此外，我们指定该组件应该被导入并在`ManagerModule`中声明。由于这是另一个着陆页，它不太可能复杂到需要单独的 HTML 和 CSS 文件。您可以使用`--inline-style`（别名`-s`）和/或`--inline-template`（别名`-t`）来避免创建额外的文件。

1.  验证您的文件夹结构如下：

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

您会注意到`http://localhost:5000/manager`实际上还没有解析到一个组件，因为我们的 Angular 应用程序不知道`ManagerModule`的存在。让我们首先尝试强制急加载的方法，导入`manager.module`并注册 manager 路由到我们的应用程序。

# 急加载

这一部分纯粹是为了演示我们迄今为止学到的导入和注册路由的概念，并不会产生可扩展的解决方案，无论是急加载还是懒加载组件：

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

您会注意到`http://localhost:5000/manager`仍然没有渲染其主组件。

1.  使用 Augury 调试路由状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f0329219-b967-45ca-b949-33b7bab07308.png)带有急加载的路由树

1.  似乎`/manager`路径已经正确注册并指向正确的组件`ManagerHomeComponent`。问题在于`app-routing.module`中配置的`rootRouter`并不知道`/manager`路径，因此`**`路径优先，并渲染`PageNotFoundComponent`。

1.  作为最后的练习，在`app-routing.module`中实现`'manager'`路径，并像平常一样将`ManagerHomeComponent`分配给它：

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

现在您会注意到`http://localhost:5000/manager`正确显示`manager-home works!`；然而，如果您通过 Augury 调试路由状态，您会注意到`/manager`注册了两次。

这个解决方案不太可扩展，因为它强制所有开发人员维护一个单一的主文件来导入和配置每个模块。它容易产生合并冲突和沮丧，希望团队成员不会多次注册相同的路由。

可以设计一个解决方案将模块分成多个文件。您可以在`manager.module`中实现 Route 数组并导出它，而不是标准的`*-routing.module`。考虑以下示例：

```ts
example/manager/manager.module
export const managerModuleRoutes: Routes = [
  { path: '', component: ManagerHomeComponent }
]
```

然后需要将这些文件单独导入到`app-routing.module`中，并使用`children`属性进行配置：

```ts
example/app-routing.module
import { managerModuleRoutes } from './manager/manager.module'
...
{ path: 'manager', children: managerModuleRoutes },
```

这个解决方案将起作用，这是一个正确的解决方案，正如 Augury 路由树所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/5ca66d17-bbea-47b3-ae9d-2ce7bb069aaf.png)带有子路由的路由树

没有重复的注册，因为我们删除了`manager-routing.module`。此外，我们不必在`manager.module`之外导入`ManagerHomeComponent`，从而得到一个更好的可扩展解决方案。然而，随着应用程序的增长，我们仍然必须在`app.module`中注册模块，并且子模块仍然以潜在不可预测的方式耦合到父`app.module`中。此外，这段代码无法被分块，因为使用`import`导入的任何代码都被视为硬依赖。

# 懒加载

现在您了解了模块的急加载如何工作，您将能够更好地理解我们即将编写的代码，否则这些代码可能看起来像黑魔法，而神奇（也就是被误解的）代码总是导致意大利面式架构。

我们现在将急加载解决方案演变为懒加载解决方案。为了从不同模块加载路由，我们知道不能简单地导入它们，否则它们将被急加载。答案在于在`app-routing.module.ts`中使用`loadChildren`属性配置路由，该属性使用字符串通知路由器如何加载子模块：

1.  确保您打算懒加载的任何模块都*不*被导入到`app.module`中

1.  删除添加到`ManagerModule`的任何路由

1.  确保`ManagerRoutingModule`被导入到`ManagerModule`中。

1.  使用`loadChildren`属性实现或更新管理器路径：

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

懒加载是通过一个巧妙的技巧实现的，避免使用`import`语句。定义一个具有两部分的字符串文字，其中第一部分定义了模块文件的位置，例如`app/manager/manager.module`，第二部分定义了模块的类名。在构建过程和运行时可以解释字符串，以动态创建块，加载正确的模块并实例化正确的类。`ManagerModule`然后就像它自己的 Angular 应用程序一样，管理着所有子依赖项和路由。

1.  更新`manager-routing.module`路由，考虑到 manager 现在是它们的根路由：

```ts
src/app/manager/manager-routing.module.ts
const routes: Routes = [
  { path: '', redirectTo: '/manager/home', pathMatch: 'full' },
  { path: 'home', component: ManagerHomeComponent },
]
```

我们现在可以将`ManagerHomeComponent`的路由更新为更有意义的`'home'`路径。这个路径不会与`app-routing.module`中找到的路径冲突，因为在这个上下文中，`'home'`解析为`'manager/home'`，同样，当路径为空时，URL 看起来像`http://localhost:5000/manager`。

1.  通过查看 Augury 来确认懒加载是否起作用，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/cefe01e3-4052-4e6f-913d-cd3d872cbfa0.png)带有延迟加载的路由树`ManagerHomeComponent`的根节点现在命名为`manager [Lazy]`。

# 完成骨架走向

使用我们在本章前面创建的 LemonMart 站点地图，我们需要完成应用程序的骨架导航体验。为了创建这种体验，我们需要创建一些按钮来链接所有模块和组件。我们将逐个模块进行：

+   在开始之前，更新`home.component`上的登录按钮，链接到`Manager`模块：

```ts
src/app/home/home.component.ts
 ...
 <button mat-raised-button color="primary" routerLink="/manager">Login as Manager</button>
 ...
```

# 管理模块

由于我们已经为`ManagerModule`启用了延迟加载，让我们继续完成它的其他导航元素。

在当前设置中，`ManagerHomeComponent`在`app.component`中定义的`<router-outlet>`中呈现，因此当用户从`HomeComponent`导航到`ManagerHomeComponent`时，`app.component`中实现的工具栏保持不变。如果我们在`ManagerModule`中实现类似的工具栏，我们可以为跨模块导航子页面创建一致的用户体验。

为了使这个工作，我们需要复制`app.component`和`home/home.component`之间的父子关系，其中父级实现工具栏和`<router-outlet>`，以便子元素可以在其中呈现：

1.  首先创建基本的`manager`组件：

```ts
$ npx ng g c manager/manager -m manager --flat -s -t
```

`--flat`选项跳过目录创建，直接将组件放在`manager`文件夹下，就像`app.component`直接放在`app`文件夹下一样。

1.  使用`activeLink`跟踪实现导航工具栏：

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

需要注意的是，子模块不会自动访问父模块中创建的服务或组件。这是为了保持解耦架构的重要默认行为。然而，在某些情况下，有必要共享一些代码。在这种情况下，需要重新导入`mat-toolbar`。由于`MatToolbarModule`已经在`src/app/material.module.ts`中加载，我们可以将这个模块导入到`manager.module.ts`中，这样做不会产生性能或内存开销。

1.  `ManagerComponent`应该被导入到`ManagerModule`中：

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

1.  创建父/子路由。我们知道我们需要以下路由才能导航到我们的子页面，如下所示：

```ts
example
{ path: '', redirectTo: '/manager/home', pathMatch: 'full' },
{ path: 'home', component: ManagerHomeComponent },
{ path: 'users', component: UserManagementComponent },
{ path: 'receipts', component: ReceiptLookupComponent },
```

为了定位在`manager.component`中定义的`<router-outlet>`，我们需要首先创建一个父路由，然后为子页面指定路由：

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

现在您应该能够浏览应用程序。当您单击“登录为经理”按钮时，您将被带到此处显示的页面。可单击的目标已突出显示，如下所示：

！[](Images/16f4d60a-a3a9-4f65-9f74-992c704c63f2.png)带有可单击目标的经理仪表板

如果您单击 LemonMart，您将被带到主页。如果您单击“经理仪表板”，“用户管理”或“收据查找”，您将被导航到相应的子页面，而工具栏上的活动链接将以粗体和下划线显示。

# 用户模块

登录后，用户将能够通过侧边导航菜单访问其个人资料，并查看他们可以在 LemonMart 应用程序中访问的操作列表。在第九章中，*设计身份验证和授权*，当我们实现身份验证和授权时，我们将从服务器接收用户的角色。根据用户的角色，我们将能够自动导航或限制用户可以看到的选项。我们将在此模块中实现这些组件，以便它们只在用户登录后加载一次。为了完成骨架的搭建，我们将忽略与身份验证相关的问题：

1.  创建必要的组件：

```ts
$ npx ng g c user/profile -m user
$ npx ng g c user/logout -m user -t -s
$ npx ng g c user/navigationMenu -m user -t -s
```

1.  实现路由：

从在`app-routing`中实现懒加载开始：

```ts
src/app/app-routing.module.ts
... 
 { path: 'user', loadChildren: 'app/user/user.module#UserModule' },
```

确保`app-routing.module`中的`PageNotFoundComponent`路由始终是最后一个路由。

现在在`user-routing`中实现子路由：

```ts
src/app/user/user-routing.module.ts
...
const routes: Routes = [
  { path: 'profile', component: ProfileComponent },
  { path: 'logout', component: LogoutComponent },
]
```

我们正在为`NavigationMenuComponent`实现路由，因为它将直接用作 HTML 元素。此外，由于`userModule`没有着陆页面，因此没有定义默认路径。

1.  连接用户和注销图标：

```ts
src/app/app.component.ts ...
<mat-toolbar>
  ...
  <button mat-mini-fab routerLink="/user/profile" matTooltip="Profile" aria-label="User Profile"><mat-icon>account_circle</mat-icon></button>
  <button mat-mini-fab routerLink="/user/logout" matTooltip="Logout" aria-label="Logout"><mat-icon>lock_open</mat-icon></button>
</mat-toolbar>
```

图标按钮可能会让人费解，因此最好为它们添加工具提示。为了使工具提示起作用，请从`mat-icon-button`指令切换到`mat-mini-fab`指令，并确保在`material.module`中导入`MatTooltipModule`。此外，确保为仅包含图标的按钮添加`aria-label`，以便依赖屏幕阅读器的残障用户仍然可以浏览您的 Web 应用程序。

1.  确保应用程序正常运行。

请注意，两个按钮彼此之间距离太近，如下所示：

！[](Images/daf74636-eb0d-4688-bca3-2305ebb2ecc3.png)带图标的工具栏

1.  您可以通过在`<mat-toolbar>`中添加`fxLayoutGap="8px"`来解决图标布局问题；然而，现在柠檬标志与应用程序名称相距太远，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/83d825ac-5e6f-474f-913f-c5773d0780ab.png)带有填充图标的工具栏

1.  可以通过合并图标和按钮来解决标志布局问题：

```ts
src/app/app.component.ts ...<mat-toolbar>  ...
  <a mat-icon-button routerLink="/home"><mat-icon svgIcon="lemon"></mat-icon><span class="mat-h2">LemonMart</span></a>
  ...
</mat-toolbar>
```

如下截图所示，分组修复了布局问题：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/6bcb1dd7-d85d-479a-ae80-8eb0e03656e3.png)带有分组和填充元素的工具栏

从用户体验的角度来看，这更加理想；现在用户也可以通过点击柠檬返回到主页。

# POS 和库存模块

我们的基本框架假定经理的角色。为了能够访问我们即将创建的所有组件，我们需要使经理能够访问 pos 和 inventory 模块。

更新`ManagerComponent`，添加两个新按钮：

```ts
src/app/manager/manager.component.ts
<mat-toolbar color="accent" fxLayoutGap="8px">
  ...
  <span class="flex-spacer"></span>
  <button mat-mini-fab routerLink="/inventory" matTooltip="Inventory" aria-label="Inventory"><mat-icon>list</mat-icon></button>
  <button mat-mini-fab routerLink="/pos" matTooltip="POS" aria-label="POS"><mat-icon>shopping_cart</mat-icon></button>
</mat-toolbar>
```

请注意，这些路由链接将会将我们从`ManagerModule`中导航出去，因此工具栏消失是正常的。

现在，你需要实现剩下的两个模块。

# POS 模块

POS 模块与用户模块非常相似，只是`PosComponent`将成为默认路由。这将是一个复杂的组件，带有一些子组件，因此请确保它是在一个目录中创建的：

1.  创建`PosComponent`

1.  将`PosComponent`注册为默认路由

1.  为`PosModule`配置延迟加载

1.  确保应用程序正常运行

# 库存模块

库存模块与`ManagerModule`非常相似，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a2721b96-90be-449b-b50e-5988fb751ee1.png)库存仪表盘模拟

1.  创建基本的`Inventory`组件

1.  注册`MaterialModule`

1.  创建库存仪表盘、库存录入、产品和类别组件

1.  在`inventory-routing.module`中配置父子路由

1.  为`InventoryModule`配置延迟加载

1.  确保应用程序正常运行，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f88c694c-8e92-47c3-bc73-c713a735534c.png)LemonMart 库存仪表盘

现在应用程序的基本框架已经完成，重要的是检查路由树，以确保延迟加载已经正确配置，并且模块没有意外地急加载。

# 检查路由树

导航到应用程序的基本路由，并使用 Augury 检查路由树，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/23455131-eadf-44ea-b937-3f331d03b588.png)急加载错误的路由树

除了最初需要的组件之外，其他所有内容都应该用[Lazy]属性标记。如果由于某种原因，路由没有用[Lazy]标记，那么它们很可能被错误地导入到`app.module`或其他组件中。

在上面的截图中，您可能会注意到`ProfileComponent`和`LogoutComponent`是急加载的，而`user`模块被正确标记为[Lazy]。即使通过工具和代码库进行多次视觉检查，也可能让您寻找罪魁祸首。但是，如果您全局搜索`UserModule`，您很快就会发现它被导入到`app.module`中。

为了安全起见，请确保删除`app.module`中的模块导入语句，您的文件应该像下面这样：

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

下一张截图显示了修正后的路由器树：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a0e0138e-e2be-48a1-8e2c-c8a86f7b2ca0.png)带有延迟加载的路由器树确保在继续之前执行`npm test`和`npm run e2e`时没有错误。

# 通用测试模块

现在我们有很多模块要处理，配置每个规范文件的导入和提供者变得很繁琐。为此，我建议创建一个通用测试模块，其中包含您可以在各个领域重复使用的通用配置。

首先创建一个新的`.ts`文件。

1.  创建`common/common.testing.ts`

1.  用通用测试提供者、虚拟和模块填充它，如下所示：

我已经提供了`ObservableMedia`、`MatIconRegistry`、`DomSanitizer`的虚拟实现，以及`commonTestingProviders`和`commonTestingModules`的数组。

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

现在让我们看一下这个共享配置文件的示例用法：

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

大多数其他模块只需要导入`commonTestingModules`。

在所有测试通过之前不要继续前进！

# 总结

在本章中，您学会了如何有效地使用 Angular CLI 来创建主要的 Angular 组件和脚手架。您创建了您的应用的品牌，利用了自定义和内置的 Material 图标。您学会了如何使用 Augury 调试复杂的 Angular 应用。最后，您开始构建基于路由器的应用程序，尽早定义用户角色，考虑懒加载的设计，并尽早确定行走骨架导航体验。

总结一下，为了实现基于路由器的实现，您需要这样做：

1.  尽早定义用户角色

1.  考虑懒加载的设计

1.  实现一个行走骨架导航体验

1.  围绕主要数据组件进行设计

1.  强制执行解耦的组件架构

1.  区分用户控件和组件

1.  最大程度地重用代码

在这一章中，您执行了 1-3 步；在接下来的三章中，您将执行 4-7 步。在第八章中，《持续集成和 API 设计》，我们将讨论围绕主要数据组件进行设计，并启用持续集成以确保高质量的可交付成果。在第九章中，《设计身份验证和授权》，我们将深入探讨安全考虑，并设计有条件的导航体验。在第十章中，《Angular 应用设计和配方》，我们将通过坚持解耦的组件架构，巧妙选择创建用户控件与组件，并利用各种 TypeScript、RxJS 和 Angular 编码技术来最大程度地重用代码。
