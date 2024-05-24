# Angular 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7`](https://zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Angular 是世界上最受欢迎的框架之一，不仅用于构建 Web 应用程序，甚至还用于移动应用程序和桌面应用程序。由 Google 支持并被 Google 使用，这个框架被数百万个应用程序使用。尽管该框架非常适合任何规模的应用程序，但企业特别喜欢 Angular，因为它具有明确的观点，并且因为其一致的生态系统包括您创建基于 Web 技术的应用程序所需的所有工具。

虽然学习核心技术如 JavaScript、HTML 和 CSS 对于成为 Web 开发人员至关重要，但是当涉及到框架时，学习框架本身的核心概念也非常重要。当我们使用 Angular 时，通过学习并使用 Angular 生态系统中的正确工具，我们可以为我们的 Web 应用程序做很多令人惊叹的事情。这就是本书的用武之地。

本书是为中级和高级 Angular 开发人员编写的，以便通过可以轻松遵循、玩耍并练习自己变化的食谱来提高他们的 Angular 开发技能。您不仅会从食谱本身中学到东西，还会从与食谱相关的实际项目中学到东西。因此，这些食谱和项目中有很多隐藏的宝石等待着您。

编码愉快！

# 本书适合谁

本书适用于中级水平的 Angular Web 开发人员，他们正在寻找在 Angular 企业开发中常见问题的可行解决方案。使用 Angular 技术的移动开发人员也会发现本书很有用。理解 JavaScript 和 TypeScript 的工作经验对更有效地理解本书中涵盖的主题是必要的。

# 本书涵盖的内容

*第一章*, *获胜的组件通信*，解释了在 Angular 中实现组件之间通信的不同技术。还涵盖了`@Input()`和`@Output()`修饰符、服务和生命周期钩子。还有一个关于如何创建动态 Angular 组件的示例。

*第二章*, *理解和使用 Angular 指令*，介绍了 Angular 指令，并提供了一些使用 Angular 指令的示例，包括属性指令和结构指令。

第三章，Angular 中依赖注入的魔力，包括覆盖了可选依赖项，配置注入令牌，使用`providedIn: 'root'`元数据为 Angular 服务提供者，值提供者和别名类提供者的示例。

第四章，理解 Angular 动画，包括实现多状态动画，交错动画，关键帧动画以及在 Angular 应用程序中切换路由时的动画的示例。

第五章，Angular 和 RxJS - 组合的精华，涵盖了 RxJS 实例和静态方法的用法。它还包括一些关于`combineLatest`，`flatMap`和`switchMap`操作符的用法的示例，并介绍了一些关于使用 RxJS 流的技巧和窍门。

第六章，使用 NgRx 进行响应式状态管理，涵盖了关于著名的 NgRX 库及其核心概念的示例。它涵盖了 NgRx 动作，减速器，选择器和效果等核心概念，并介绍了如何使用`@ngrx/store-devtools`和`@component/store`等包。

第七章，理解 Angular 导航和路由，探讨了有关延迟加载路由，路由守卫，预加载路由策略以及与 Angular 路由一起使用的一些有趣技术的示例。

第八章，精通 Angular 表单，涵盖了模板驱动表单，响应式表单，表单验证，测试表单以及创建自己的表单控件的示例。

第九章，Angular 和 Angular CDK，包括许多很酷的 Angular CDK 示例，包括虚拟滚动，键盘导航，覆盖 API，剪贴板 API，CDK 拖放，CDK 步进器 API 和 CDK 文本框 API。

第十章，使用 Jest 在 Angular 中编写单元测试，涵盖了使用 Jest 进行单元测试的示例，探索 Jest 中的全局模拟，模拟服务/子组件/管道，使用 Angular CDK 组件挽具进行单元测试等内容。

*第十一章**，使用 Cypress 进行 Angular 的 E2E 测试*，介绍了在 Angular 应用中使用 Cypress 进行 E2E 测试的示例。它涵盖了验证表单、等待 XHR 调用、模拟 HTTP 调用响应、使用 Cypress 捆绑包以及在 Cypress 中使用固定装置。

*第十二章*，*Angular 中的性能优化*，包含一些通过使用 OnPush 变更检测策略、延迟加载特性路由、从组件中分离变更检测器、使用 Angular 的 Web Workers、使用纯管道、向 Angular 应用添加性能预算以及使用`webpack-bundle`分析器来改善 Angular 应用性能的酷技巧。

*第十三章*，*使用 Angular 构建 PWA*，包含了创建一个 PWA 的示例。它涵盖了为 PWA 指定主题颜色、使用设备的深色模式、提供自定义 PWA 安装提示、使用 Angular 的服务工作器预缓存请求以及使用 App Shell。

# 要充分利用本书

本书的示例是基于 Angular v12 构建的，Angular 遵循语义化版本控制发布。由于 Angular 不断改进，为了稳定性，Angular 团队为更新提供了可预测的发布周期。发布频率如下：

+   每 6 个月发布一个重大版本。

+   每个重大版本有 1 到 3 个次要版本。

+   几乎每周发布一个补丁版本和预发布版本（下一个或 rc）构建。

来源：[`angular.io/guide/releases#release-frequency`](https://angular.io/guide/releases#release-frequency)

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Table.jpg)

**如果您正在使用本书的数字版本，我们建议您自己输入代码或从书的 GitHub 存储库中访问代码（链接在下一节中提供）。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。**

阅读完本书后，请务必在[`ahsanayaz.com/twitter`](https://ahsanayaz.com/twitter)上发推文，让我知道您对本书的反馈。此外，您可以根据自己的喜好修改本书提供的代码，将其上传到您的 GitHub 存储库并分享。我会确保转发它 :)

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件[`github.com/PacktPublishing/Angular-Cookbook`](https://github.com/PacktPublishing/Angular-Cookbook)。如果代码有更新，将在 GitHub 存储库中更新。

我们还有来自丰富书籍和视频目录的其他代码捆绑包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图和图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781838989439_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781838989439_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。例如：“现在，我们将把代码从`the-amazing-list-component.html`文件移动到`the-amazing-list-item.component.html`文件，用于项目的标记。”

一块代码设置如下：

```ts
openMenu($event, itemTrigger) {
    if ($event) {
      $event.stopImmediatePropagation();
    }
    this.popoverMenuTrigger = itemTrigger;
    this.menuShown = true;
  }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```ts
.menu-popover {
  ...
  &::before {...}
  &--up {
    transform: translateY(-20px);
    &::before {
      top: unset !important;
      transform: rotate(180deg);
      bottom: -10px;
    }
  }
  &__list {...}
}
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词以**粗体**显示。例如：“您会注意到我们无法看到输入内容的全部内容-这在最好的时候有点烦人，因为在按下**操作**按钮之前，您无法真正审查它。”

提示或重要说明

出现如下。


# 第一章：*第一章*：获胜的组件通信

在本章中，您将掌握 Angular 中的组件通信。您将学习建立组件之间通信的不同技术，并了解哪种技术适用于哪种情况。您还将学习如何在本章中创建一个动态的 Angular 组件。

以下是本章将要涵盖的配方：

+   使用组件`@Input(s)`和`@Output(s)`进行组件通信

+   使用服务进行组件通信

+   使用 setter 拦截输入属性的更改

+   使用`ngOnChanges`拦截输入属性的更改

+   通过模板变量在父模板中访问子组件

+   通过`ViewChild`在父组件类中访问子组件

+   在 Angular 中创建你的第一个动态组件

# 技术要求

在本章的配方中，请确保您的计算机上安装了**Git**和**Node.js**。您还需要安装`@angular/cli`包，可以在终端中使用`npm install -g @angular/cli`来安装。本章的代码可以在[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter01`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter01)找到。

# 使用组件@Input(s)和@Output(s)进行组件通信

您将从一个具有父组件和两个子组件的应用程序开始。然后，您将使用 Angular 的`@Input`和`@Ouput`装饰器，使用属性和`EventEmitter`(s)在它们之间建立通信。

## 准备工作

我们将要使用的项目位于克隆存储库中的`chapter01/start_here/cc-inputs-outputs`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。完成后，运行`ng serve -o`。

这应该在新的浏览器标签页中打开应用程序，你应该看到以下内容：

![图 1.1 - 运行在 http://localhost:4200 上的 cc-inputs-outputs 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.01_B15150.jpg)

图 1.1 - 运行在 http://localhost:4200 上的 cc-inputs-outputs 应用程序

## 如何做…

到目前为止，我们有一个带有`AppComponent`、`NotificationsButtonComponent`和`NotificationsManagerComponent`的应用程序。虽然`AppComponent`是其他两个组件的父组件，但它们之间绝对没有组件通信来同步通知计数值。让我们使用以下步骤建立它们之间的适当通信：

1.  我们将从`NotificationsManagerComponent`中移除`notificationsCount`变量，并将其放在`AppComponent`中。为此，只需在`app.component.ts`中创建一个`notificationsCount`属性即可：

```ts
export class AppComponent {
  notificationsCount = 0;
}
```

1.  然后，将`notifications-manager.component.ts`中的`notificationsCount`属性转换为`@Input()`，并将其重命名为`count`，并替换其用法如下：

```ts
import { Component, OnInit, Input } from '@angular/core';
@Component({
  selector: 'app-notifications-manager',
  templateUrl: './notifications-manager.component.html',
  styleUrls: ['./notifications-manager.component.scss']
})
export class NotificationsManagerComponent implements OnInit {
  @Input() count = 0
  constructor() { }
  ngOnInit(): void {
  }
  addNotification() {
    this.count++;
  }
  removeNotification() {
    if (this.count == 0) {
      return;
    }
    this.count--;
  } 
  resetCount() {
    this.count = 0;
  }
}
```

1.  更新`notifications-manager.component.html`以使用`count`而不是`notificationsCount`：

```ts
 <div class="notif-manager">
  <div class="notif-manager__count">
    Notifications Count: {{count}}
  </div>
  ...
</div>
```

1.  接下来，将`app.component.html`中的`notificationsCount`属性作为输入传递给`<app-notifications-manager>`元素：

```ts
 <div class="content" role="main">
  <app-notifications-manager
    [count]="notificationsCount">
  </app-notifications-manager>
</div>
```

您现在可以通过将`app.component.ts`中的`notificationsCount`的值分配为`10`来测试是否正确地从`app.component.html`传递到`app-notifications-manager`。您将看到，在`NotificationsManagerComponent`中，显示的初始值将为`10`：

```ts
export class AppComponent {
  notificationsCount = 10;
}
```

1.  接下来，在`notifications-button.component.ts`中创建一个`@Input()`，命名为`count`：

```ts
import { Component, OnInit, Input } from '@angular/core';
...
export class NotificationsButtonComponent implements OnInit {
  @Input() count = 0;
  ...
}
```

1.  同时也将`notificationsCount`传递给`<app-notifications-button>`，并在`app.component.html`中进行相应设置：

```ts
<!-- Toolbar -->
<div class="toolbar" role="banner">
  ...
  <span>@Component Inputs and Outputs</span>
  <div class="spacer"></div>
  <div class="notif-bell">
    <app-notifications-button     [count]="notificationsCount">
    </app-notifications-button>
  </div>
</div>
...
```

1.  在`notifications-button.component.html`中使用`count`输入与通知图标：

```ts
<div class="bell">
  <i class="material-icons">notifications</i>
  <div class="bell__count">
    <div class="bell__count__digits">
      {{count}}
    </div>
  </div>
</div>
```

现在，您还应该看到通知图标计数为`10`的值。

*现在，如果您通过从`NotificationsManagerComponent`中添加/删除通知来更改计数，通知图标上的计数将不会改变。*

1.  为了将来自`NotificationsManagerComponent`到`NotificationsButtonComponent`的更改进行通信，我们现在将使用 Angular 的`@Output`。在`notifications-manager.component.ts`中使用`@Output`和`@EventEmitter`来自`'@angular/core'`：

```ts
import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
...
export class NotificationsManagerComponent implements OnInit {
  @Input() count = 0
  @Output() countChanged = new EventEmitter<number>();
  ...
  addNotification() {
    this.count++;
    this.countChanged.emit(this.count);
  }
  removeNotification() {
    ...
    this.count--;
    this.countChanged.emit(this.count);
  }
  resetCount() {
    this.count = 0;
    this.countChanged.emit(this.count);
  }
}
```

1.  然后，我们将在`app.component.html`中监听来自`NotificationsManagerComponent`的先前发出的事件，并相应地更新`notificationsCount`属性：

```ts
<div class="content" role="main">
  <app-notifications-manager   (countChanged)="updateNotificationsCount($event)"   [count]="notificationsCount"></app-notifications-  manager>
</div>
```

1.  由于我们先前已经监听了`countChanged`事件并调用了`updateNotificationsCount`方法，我们需要在`app.component.ts`中创建这个方法，并相应地更新`notificationsCount`属性的值：

```ts
export class AppComponent {
  notificationsCount = 10;
  updateNotificationsCount(count: number) {
    this.notificationsCount = count;
  }
}
```

## 工作原理…

为了使用`@Input`和`@Output`在组件之间进行通信，数据流将始终从*子组件* **到** *父组件*，父组件可以将新的（更新的）值*作为输入*提供给所需的子组件。因此，`NotificationsManagerComponent`发出`countChanged`事件。`AppComponent`（作为父组件）监听该事件并更新`notificationsCount`的值，这将自动更新`NotificationsButtonComponent`中的`count`属性，因为`notificationsCount`被传递为`@Input()` count 到`NotificationsButtonComponent`。*图 1.2*显示了整个过程：

![图 1.2 - 使用输入和输出进行组件通信的工作原理](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.02_B15150.jpg)

图 1.2 - 使用输入和输出进行组件通信的工作原理

## 另请参阅

+   Angular 组件如何通信？[`www.thirdrocktechkno.com/blog/how-angular-components-communicate`](https://www.thirdrocktechkno.com/blog/how-angular-components-communicate)

+   *Dhananjay Kumar 的 Angular 组件通信*：[`www.youtube.com/watch?v=I8Z8g9APaDY`](https://www.youtube.com/watch?v=I8Z8g9APaDY)

# 使用服务进行组件通信

在这个配方中，您将从一个具有父组件和子组件的应用程序开始。然后，您将使用 Angular 服务来建立它们之间的通信。我们将使用`BehaviorSubject`和 Observable 流来在组件和服务之间进行通信。

## 准备就绪

此处的配方项目位于`chapter01/start_here/cc-services`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这将在新的浏览器标签中打开应用程序，您应该看到应用程序如下所示：

![图 1.3 - cc-services 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.03_B15150.jpg)

图 1.3 - cc-services 应用程序运行在 http://localhost:4200

## 如何做…

与之前的配方类似，我们有一个带有`AppComponent`、`NotificationsButtonComponent`和`NotificationsManagerComponent`的应用程序。`AppComponent`是前面提到的另外两个组件的父组件，我们需要使用以下步骤在它们之间建立适当的通信：

1.  在`chapter01/start_here/cc-services/src/app`项目中创建一个名为`services`的新文件夹。这将是我们新服务的所在地。

1.  从终端中，导航到项目中，即`chapter01/start_here/cc-services`内，并创建一个名为`NotificationService`的新服务，如下所示：

```ts
ng g service services/Notifications
```

1.  在`notifications.service.ts`中创建一个名为`count`的`BehaviorSubject`，并将其初始化为`0`，因为`BehaviorSubject`需要一个初始值：

```ts
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
@Injectable({
  providedIn: 'root'
})
export class NotificationsService {
  private count: BehaviorSubject<number> = new   BehaviorSubject<number>(0);
  constructor() { }
}
```

注意`BehaviorSubject`是一个`private`属性，我们稍后将仅从服务内部使用`public`方法来更新它。

1.  现在，使用`count`的`BehaviorSubject`上的`.asObservable()`方法创建一个名为`count$`的`Observable`：

```ts
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
...
export class NotificationsService {
  private count: BehaviorSubject<number> = new   BehaviorSubject<number>(0);
  count$: Observable<number> = this.count.asObservable();
  ...
}
```

1.  将`notifications-manager.component.ts`中的`notificationsCount`属性转换为名为`notificationsCount$`的 Observable。在组件中注入`NotificationsService`并将服务的`count$` Observable 分配给组件的`notificationsCount$`变量：

```ts
import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs';
import { NotificationsService } from '../services/notifications.service';
...
export class NotificationsManagerComponent implements OnInit {
  notificationsCount$: Observable<number>;
  constructor(private notificationsService:   NotificationsService) { }

  ngOnInit(): void {
    this.notificationsCount$ = this.notificationsService.    count$;
  }
  ...
}
```

1.  暂时注释掉更新通知计数的代码；我们稍后会回来处理它：

```ts
...
export class NotificationsManagerComponent implements OnInit {
  ...
  addNotification() {
    // this.notificationsCount++;
  }
  removeNotification() {
    // if (this.notificationsCount == 0) {
    //   return;
    // }
    // this.notificationsCount--;
  }
  resetCount() {
    // this.notificationsCount = 0;
  }
}
```

1.  在`notifications-manager.component.html`中使用`notificationsCount$` Observable 和`async`管道来显示其值：

```ts
<div class="notif-manager">
  <div class="notif-manager__count">
    Notifications Count: {{notificationsCount$ | async}}
  </div>
  ...
</div>
```

1.  现在，类似地在`notifications-button.component.ts`中注入`NotificationsService`，在`NotificationsButtonComponent`中创建一个名为`notificationsCount$`的 Observable，并将服务的`count$` Observable 分配给它：

```ts
import { Component, OnInit } from '@angular/core';
import { NotificationsService } from '../services/notifications.service';
import { Observable } from 'rxjs';
 ...
export class NotificationsButtonComponent implements OnInit {
  notificationsCount$: Observable<number>;
  constructor(private notificationsService:   NotificationsService) { }

  ngOnInit(): void {
    this.notificationsCount$ = this.notificationsService.    count$;
  }
}
```

1.  在`notifications-button.component.html`中使用`notificationsCount$` Observable 和`async`管道：

```ts
<div class="bell">
  <i class="material-icons">notifications</i>
  <div class="bell__count">
    <div class="bell__count__digits">
      {{notificationsCount$ | async}}
    </div>
  </div>
</div>
```

如果现在刷新应用程序，您应该能够看到通知管理器组件和通知按钮组件的值都为`0`。

1.  将`count`的`BehaviorSubject`的初始值更改为`10`，并查看是否在两个组件中都反映出来：

```ts
...
export class NotificationsService {
  private count: BehaviorSubject<number> = new   BehaviorSubject<number>(10);
  ...
}
```

1.  现在，在`notifications.service.ts`中创建一个名为`setCount`的方法，这样我们就能够更新`count`的`BehaviorSubject`的值：

```ts
...
export class NotificationsService {
  …
  constructor() {}
  setCount(countVal) {
    this.count.next(countVal);
  }
}
```

1.  现在我们已经有了`setCount`方法，让我们在`notifications-manager.component.ts`中使用它来根据按钮点击更新其值。为了这样做，我们需要获取`notificationsCount$` Observable 的最新值，然后执行一些操作。我们首先在`NotificationsManagerComponent`中创建一个`getCountValue`方法，如下所示，并在`notificationsCount$` Observable 上使用`subscribe`和`first`操作符来获取其最新值：

```ts
...
import { first } from 'rxjs/operators';
...
export class NotificationsManagerComponent implements OnInit {
  ngOnInit(): void {
    this.notificationsCount$ = this.notificationsService.    count$;
  }
  ...
  getCountValue(callback) {
    this.notificationsCount$
      .pipe(
        first()
      ).subscribe(callback)
  }
  ...
}
```

1.  现在，我们将在我们的`addNotification`、`removeNotification`和`resetCount`方法中使用`getCountValue`方法。我们将不得不从这些方法中将回调函数传递给`getCountValue`方法。让我们先从`addNotification`方法开始：

```ts
import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs';
import { NotificationsService } from '../services/notifications.service';
import { first } from 'rxjs/operators';

...
export class NotificationsManagerComponent implements OnInit {
  ...
  addNotification() {
    this.getCountValue((countVal) => {
      this.notificationsService.setCount(++countVal)
    });
  }
  ...
}
```

有了上述代码，每当我们点击**添加通知**按钮时，您应该已经看到两个组件正确地反映了更新的值。

1.  现在让我们实现`removeNotification`和`resetCount`的相同逻辑：

```ts
...
export class NotificationsManagerComponent implements OnInit {
  ...
  removeNotification() {
    this.getCountValue((countVal) => {
      if (countVal === 0) {
        return;
      }
      this.notificationsService.setCount(--countVal);
    })
  }
  resetCount() {
    this.notificationsService.setCount(0);
  }
}
```

## 工作原理…

`BehaviorSubject`是一种特殊类型的`Observable`，它需要一个初始值，并且可以被多个订阅者使用。在这个食谱中，我们创建了一个`BehaviorSubject`，然后使用`BehaviorSubject`上的`.asObservable()`方法创建了一个`Observable`。虽然我们本来可以直接使用`BehaviorSubject`，但是社区推荐使用`.asObservable()`方法。

一旦我们在`NotificationsService`中创建了名为`count$`的 Observable，我们就在我们的组件中注入`NotificationsService`，并将`count$` Observable 分配给组件的一个本地属性。然后，我们直接在`NotificationsButtonComponent`的模板（`html`）和`NotificationsManagerComponent`的模板中使用`async`管道订阅这个本地属性（它是一个 Observable）。

然后，每当我们需要更新`count$` Observable 的值时，我们使用`NotificationsService`的`setCount`方法来使用`BehaviorSubject`的`.next()`方法更新实际的值。这将通过`count$` Observable 自动发出新值，并在两个组件中更新视图的新值。

## 另请参阅

+   RxJS 官方文档中的 Subjects：[`www.learnrxjs.io/learn-rxjs/subjects`](https://www.learnrxjs.io/learn-rxjs/subjects)

+   `BehaviorSubject`与`Observable`在 Stack Overflow 上的比较：[`stackoverflow.com/a/40231605`](https://stackoverflow.com/a/40231605)

# 使用 setter 拦截输入属性更改

在这个食谱中，您将学习如何拦截从父组件传递的`@Input`的更改，并对此事件执行一些操作。我们将拦截从`VersionControlComponent`父组件传递给`VcLogsComponent`子组件的`vName`输入。我们将使用 setter 在`vName`的值更改时生成日志，并在子组件中显示这些日志。

## 准备工作

这个食谱的项目位于`chapter01.start_here/cc-setters`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。这应该会在新的浏览器选项卡中打开应用程序，您应该看到应用程序如下所示：

![图 1.4 – cc-setters 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.04_B15150.jpg)

图 1.4 – cc-setters 应用程序在 http://localhost:4200 上运行

## 如何做…

1.  首先，我们将在`VcLogsComponent`中创建一个日志数组，以存储稍后我们将使用模板显示的所有日志：

```ts
export class VcLogsComponent implements OnInit {
  @Input() vName;
  logs: string[] = [];
  constructor() { }
...
}
```

1.  让我们创建 HTML 来显示日志的位置。使用以下代码将日志容器和日志项添加到`vc-logs.component.html`中：

```ts
<h5>Latest Version = {{vName}}</h5>
<div class="logs">
  <div class="logs__item" *ngFor="let log of logs">
    {{log}}
  </div>
</div>
```

1.  然后，我们将为要显示的日志容器和日志项添加一些样式。更改后，视图应如*图 1.5*所示。更新`vc-logs.component.scss`文件如下：

```ts
h5 {
  text-align: center;
}
.logs {
  padding: 1.8rem;
  background-color: #333;
  min-height: 200px;
  border-radius: 14px;
  &__item {
    color: lightgreen;
  }
}
```

以下截图显示了具有日志容器样式的应用程序：

![图 1.5 – 具有日志容器样式的 cc-setters 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.05_B15150.jpg)

图 1.5 – 具有日志容器样式的 cc-setters 应用程序

1.  现在，我们将把`vc-logs.component.ts`中的`@Input()`转换为使用 getter 和 setter，以便我们可以拦截输入更改。为此，我们还将创建一个名为`_vName`的内部属性。代码应如下所示：

```ts
...
export class VcLogsComponent implements OnInit {
  _vName: string;
@Input() 
  get vName() {
    return this._vName;
  };
  set vName(name: string) {
   this._vName = name;
  }
  logs: string[] = [];
  constructor() { }
...
}
```

1.  通过*步骤 4*中的更改，应用程序的工作方式与以前完全相同，即完美。现在，让我们修改 setter 以创建这些日志。对于初始值，我们将有一个日志，说'初始版本是 x.x.x'：

```ts
export class VcLogsComponent implements OnInit {
  ...
  set vName(name: string) {
    if (!name) return;
    if (!this._vName) {
      this.logs.push('initial version is ${name.trim()}')
    }
    this._vName = name;
  }
...
}
```

1.  现在，作为最后一步，每当我们更改版本名称时，我们需要显示一个不同的消息，说'版本更改为 x.x.x'。*图 1.6*显示了最终输出。对于所需的更改，我们将在`vName` setter 中编写一些进一步的代码如下：

```ts
export class VcLogsComponent implements OnInit {
  ...
  set vName(name: string) {
    if (!name) return;
    if (!this._vName) {
      this.logs.push('initial version is ${name.trim()}')
    } else {
      this.logs.push('version changed to ${name.trim()}')
    }
    this._vName = name;
  }
```

以下截图显示了最终输出：

![图 1.6 – 使用 setter 的最终输出](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.06_B15150.jpg)

图 1.6 – 使用 setter 的最终输出

## 它是如何工作的…

Getter 和 setter 是 JavaScript 的内置功能的组成部分。许多开发人员在使用原始 JavaScript 或 TypeScript 时在其项目中使用它们。幸运的是，Angular 的`@Input()`也可以使用 getter 和 setter，因为它们基本上是提供的类的属性。

对于这个示例，我们使用一个 getter，更具体地说，是一个 setter 来处理我们的输入，所以每当输入发生变化时，我们使用 setter 方法来执行额外的任务。此外，我们在 HTML 中使用相同输入的 setter，所以当更新时，我们直接在视图中显示值。

始终使用私有变量/属性与 getter 和 setter 是一个好主意，以便在组件接收输入和在组件本身中存储输入方面有一个关注点的分离。

## 另请参阅

+   [`angular.io/guide/component-interaction#intercept-input-property-changes-with-a-setter`](https://angular.io/guide/component-interaction#intercept-input-property-changes-with-a-setter)

+   [`www.jackfranklin.co.uk/blog/es5-getters-setters`](https://www.jackfranklin.co.uk/blog/es5-getters-setters) by Jack Franklin

# 使用`ngOnChanges`来拦截输入属性的更改

在这个示例中，您将学习如何使用`ngOnChanges`来拦截使用`SimpleChanges` API 的更改。我们将监听从`VersionControlComponent`父组件传递给`VcLogsComponent`子组件的`vName`输入。

## 准备工作

这个示例的项目位于`chapter01/start_here/cc-ng-on-changes`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。这应该会在新的浏览器标签中打开应用程序，您应该会看到应用程序如下所示：

![图 1.7 - cc-ng-on-changes 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.07_B15150.jpg)

图 1.7 - cc-ng-on-changes 应用程序在 http://localhost:4200 上运行

## 如何做…

1.  首先，在`VcLogsComponent`中创建一个 logs 数组，以便稍后在模板中显示所有的日志：

```ts
export class VcLogsComponent implements OnInit {
  @Input() vName;
  logs: string[] = [];
  constructor() { }
...
}
```

1.  让我们创建一个用于显示日志的 HTML。让我们使用以下代码在`vc-logs.component.html`中添加日志容器和日志项：

```ts
<h5>Latest Version = {{vName}}</h5>
<div class="logs">
  <div class="logs__item" *ngFor="let log of logs">
    {{log}}
  </div>
</div>
```

1.  然后，我们将在`vc-logs.component.scss`中添加一些样式，以便显示日志容器和日志项，如下所示：

```ts
h5 {
  text-align: center;
}
.logs {
  padding: 1.8rem;
  background-color: #333;
  min-height: 200px;
  border-radius: 14px;
  &__item {
    color: lightgreen;
  }
}
```

您应该会看到类似于这样的东西：

![图 1.8 - cc-ng-on-changes 应用程序带有日志容器样式](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.08_B15150.jpg)

图 1.8 - cc-ng-on-changes 应用程序带有日志容器样式

1.  现在，让我们在`vc-logs.component.ts`文件中实现`VcLogsComponent`中的`ngOnChanges`，使用简单的更改如下：

```ts
import { Component, OnInit, Input, OnChanges, SimpleChanges } from '@angular/core';
...
export class VcLogsComponent implements OnInit, OnChanges {
  @Input() vName;
  logs: string[] = [];
  constructor() {}
  ngOnInit(): void {}
  ngOnChanges(changes: SimpleChanges) {
  }
}
```

1.  现在，我们可以为`vName`输入的初始值添加一个日志，内容为`'initial version is x.x.x'`。我们通过使用`.isFirstChange()`方法来检查是否为初始值来实现这一点，如下所示：

```ts
...
export class VcLogsComponent implements OnInit, OnChanges {
  ...
  ngOnChanges(changes: SimpleChanges) {
    const currValue = changes.vName.currentValue;
    if (changes.vName.isFirstChange()) {
      this.logs.push('initial version is       ${currValue.trim()}')
    }
  }
}
```

1.  让我们处理在分配初始值后更新版本的情况。为此，我们将添加另一个日志，使用`else`条件，内容为`'version changed to x.x.x'`，如下所示：

```ts
...
export class VcLogsComponent implements OnInit, OnChanges {
  ...
  ngOnChanges(changes: SimpleChanges) {
    const currValue = changes.vName.currentValue;
    if (changes.vName.isFirstChange()) {
      this.logs.push('initial version is       ${currValue.trim()}')
    } else {
      this.logs.push('version changed to       ${currValue.trim()}')
    }
  }
}
```

## 工作原理…

`ngOnChanges`是 Angular 提供的许多生命周期钩子之一。它甚至在`ngOnInit`钩子之前触发。因此，您在第一次调用时获得*初始值*，稍后获得*更新后的值*。每当任何输入发生更改时，都会使用`SimpleChanges`触发`ngOnChanges`回调，并且您可以获取先前的值、当前的值以及表示这是否是输入的第一次更改的布尔值（即初始值）。当我们在父级更新`vName`输入的值时，`ngOnChanges`会使用更新后的值进行调用。然后，根据情况，我们将适当的日志添加到我们的`logs`数组中，并在 UI 上显示它。

## 另请参阅

+   Angular 生命周期钩子：[`angular.io/guide/lifecycle-hooks`](https://angular.io/guide/lifecycle-hooks)

+   使用`ngOnChanges`的变更检测钩子：[`angular.io/guide/lifecycle-hooks#using-change-detection-hooks`](https://angular.io/guide/lifecycle-hooks#using-change-detection-hooks)

+   `SimpleChanges` API 参考：[`angular.io/api/core/SimpleChanges`](https://angular.io/api/core/SimpleChanges)

# 通过模板变量在父模板中访问子组件

在这个示例中，您将学习如何使用**Angular 模板引用变量**来访问父组件模板中的子组件。您将从一个具有`AppComponent`作为父组件和`GalleryComponent`作为子组件的应用程序开始。然后，您将在父模板中为子组件创建一个模板变量，以便访问它并在组件类中执行一些操作。

## 准备工作

我们要处理的项目位于克隆存储库内的`chapter01/start_here/cc-template-vars`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器选项卡中打开应用程序，并且您应该看到类似以下内容的东西：

![图 1.9 - 在 http://localhost:4200 上运行的 cc-template-vars 应用程序的运行情况]

](image/Figure_1.09_B15150.jpg)

图 1.9 - 运行在 http://localhost:4200 上的 cc-template-vars 应用程序

1.  点击顶部的按钮以查看各自的控制台日志。

## 如何做...

1.  我们将从在`app.component.html`文件中的`<app-gallery>`组件上创建一个名为`#gallery`的模板变量开始：

```ts
...
<div class="content" role="main">
  ...
  <app-gallery #gallery></app-gallery>
</div>
```

1.  接下来，我们修改`app.component.ts`中的`addNewPicture()`和`removeFirstPicture()`方法，以接受一个名为`gallery`的参数，这样当我们点击按钮时，它们可以接受来自`app.component.html`的模板变量。代码应该如下所示：

```ts
import { Component } from '@angular/core';
import { GalleryComponent } from './components/gallery/gallery.component';
...
export class AppComponent {
  ...
  addNewPicture(gallery: GalleryComponent) {
    console.log('added new picture');
  }
  removeFirstPicture(gallery: GalleryComponent) {
    console.log('removed first picture');
  }
}
```

1.  现在，让我们将`app.component.html`中的`#gallery`模板变量传递给两个按钮的点击处理程序，如下所示：

```ts
…
<div class="content" role="main">
  <div class="gallery-actions">
    <button class="btn btn-primary"     (click)="addNewPicture(gallery)">Add Picture</button>
    <button class="btn btn-danger"     (click)="removeFirstPicture(gallery)">Remove     First</button>
  </div>
  ...
</div>
```

1.  现在，我们可以实现添加新图片的代码。为此，我们将访问`GalleryComponent`的`generateImage()`方法，并将一个新项添加到`pictures`数组中作为第一个元素。代码如下：

```ts
...
export class AppComponent {
  ...
  addNewPicture(gallery: GalleryComponent) {
    gallery.pictures.unshift(gallery.generateImage());
  }
  ...
}
```

1.  要从数组中删除第一个项目，我们将在`GalleryComponent`类中的`pictures`数组上使用数组的`shift`方法来删除第一个项目，如下所示：

```ts
...
export class AppComponent {
   ...
  removeFirstPicture(gallery: GalleryComponent) {
    gallery.pictures.shift();
  }
}
```

## 它是如何工作的...

模板引用变量通常是模板中的 DOM 元素的引用。它也可以引用指令（其中包含一个组件）、元素、`TemplateRef`或 Web 组件（来源：[`angular.io/guide/template-reference-variables`](https://angular.io/guide/template-reference-variables)）。

实质上，我们可以引用我们的`<app-gallery>`组件，它在 Angular 中是一个指令。一旦我们在模板中有了这个变量，我们将引用传递给我们组件中的函数作为函数参数。然后，我们可以从那里访问`GalleryComponent`的属性和方法。您可以看到，我们能够直接从`AppComponent`中添加和删除`GalleryComponent`中的`pictures`数组中的项目，而`AppComponent`是整个流程中的父组件。

## 另请参阅

+   Angular 模板变量：[`angular.io/guide/template-reference-variables`](https://angular.io/guide/template-reference-variables)

+   Angular 模板语句：[`angular.io/guide/template-statements`](https://angular.io/guide/template-statements)

# 使用 ViewChild 在父组件类中访问子组件

在这个示例中，您将学习如何使用`ViewChild`装饰器来访问父组件类中的子组件。您将从一个具有`AppComponent`作为父组件和`GalleryComponent`作为子组件的应用程序开始。然后，您将在父组件类中为子组件创建一个`ViewChild`来访问它并执行一些操作。

## 准备工作

我们要处理的项目位于克隆存储库内的`chapter01/start_here/cc-view-child`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。完成后，运行`ng serve -o`。

1.  这将在新的浏览器标签中打开应用程序，您应该会看到类似以下内容的内容：![图 1.10 - 在 http://localhost:4200 上运行的 cc-view-child 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.10_B15150.jpg)

图 1.10 - 在 http://localhost:4200 上运行的 cc-view-child 应用程序

1.  点击顶部的按钮查看相应的控制台日志。

## 如何做…

1.  我们将从将`GalleryComponent`导入到我们的`app.component.ts`文件开始，以便我们可以为其创建一个`ViewChild`：

```ts
import { Component } from '@angular/core';
import { GalleryComponent } from './components/gallery/gallery.component';
...
export class AppComponent {
  ...
}
```

1.  然后，我们将使用`ViewChild()`装饰器为`GalleryComponent`创建`ViewChild`，如下所示：

```ts
import { Component, ViewChild } from '@angular/core';
import { GalleryComponent } from './components/gallery/gallery.component';
export class AppComponent {
  title = 'cc-view-child';
  @ViewChild(GalleryComponent) gallery;
  ...
}
```

1.  现在，我们将实现添加新图片的逻辑。为此，在`AppComponent`内的`addNewPicture`方法中，我们将使用*步骤 2*中创建的`gallery`属性。这是为了访问子组件中的`pictures`数组。完成后，我们将使用`GalleryComponent`的`generateImage`方法将新图片添加到该数组的顶部，如下所示：

```ts
...
export class AppComponent {
  title = 'cc-view-child';
  @ViewChild(GalleryComponent) gallery: GalleryComponent;
  addNewPicture() {
    this.gallery.pictures.unshift(    this.gallery.generateImage());
  }
  ...
}
```

1.  为了处理删除图片，我们将在`AppComponent`类内的`removeFirstPicture`方法中添加逻辑。我们也将使用视图子组件。我们将简单地在`pictures`数组上使用`Array.prototype.shift`方法来删除第一个元素，如下所示：

```ts
...
export class AppComponent {
...
  removeFirstPicture() {
    this.gallery.pictures.shift();
  }
}
```

## 它是如何工作的…

`ViewChild()` 基本上是 `@angular/core` 包提供的装饰器。它为 Angular 变更检测器配置了一个**视图查询**。变更检测器尝试找到与查询匹配的第一个元素，并将其分配给与 `ViewChild()` 装饰器关联的属性。在我们的示例中，我们通过将 `GalleryComponent` 作为查询参数来创建一个视图子元素，即 `ViewChild(GalleryComponent)`。这允许 Angular 变更检测器在 `app.component.html` 模板中找到 `<app-gallery>` 元素，然后将其分配给 `AppComponent` 类中的 `gallery` 属性。重要的是将 gallery 属性的类型定义为 `GalleryComponent`，这样我们稍后可以在组件中轻松使用 TypeScript 魔法。

重要提示

视图查询在 `ngOnInit` 生命周期钩子之后和 `ngAfterViewInit` 钩子之前执行。

## 另请参阅

+   Angular `ViewChild`：[`angular.io/api/core/ViewChild`](https://angular.io/api/core/ViewChild)

+   数组的 shift 方法：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/shift`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/shift)

# 在 Angular 中创建您的第一个动态组件

在这个示例中，您将学习如何在 Angular 中创建**动态组件**，这些组件根据不同的条件动态创建。为什么？因为您可能有几个复杂的条件，并且您希望根据这些条件加载特定的组件，而不是只将每个可能的组件放在模板中。我们将使用 `ComponentFactoryResolver` 服务、`ViewChild()` 装饰器和 `ViewContainerRef` 服务来实现动态加载。我很兴奋，你也是！

## 准备就绪

我们将要处理的项目位于克隆存储库中的 `chapter01/start_here/ng-dynamic-components` 中。

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该在新的浏览器选项卡中打开应用程序，您应该看到类似以下内容：

![图 1.11 - ng-dynamic-components 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.11_B15150.jpg)

图 1.11 - ng-dynamic-components 应用程序在 http://localhost:4200 上运行

1.  点击顶部的按钮以查看相应的控制台日志。

## 如何做…

1.  首先，让我们从我们的`social-card.component.html`文件中删除带有`[ngSwitch]`和`*ngSwitchCase`指令的元素，并将它们替换为一个简单的带有模板变量命名为`#vrf`的`div`。我们将使用这个`div`作为容器。代码应该如下所示：

```ts
<div class="card-container" #vrf></div>
```

1.  接下来，我们将在`social-card.component.ts`中添加`ComponentFactoryResolver`服务，如下所示：

```ts
import { Component, OnInit, Input, ComponentFactoryResolver } from '@angular/core';
...
export class SocialCardComponent implements OnInit {
  @Input() type: SocialCardType;
  cardTypes = SocialCardType;
  constructor(private componentFactoryResolver:   ComponentFactoryResolver) { }
  ...
}
```

1.  现在，在同一个文件中为`ViewContainerRef`创建一个`ViewChild`，这样我们就可以从模板中引用`#vrf` div，如下所示：

```ts
import { Component, OnInit, Input, ComponentFactoryResolver, ViewChild, ViewContainerRef } from '@angular/core';
...
export class SocialCardComponent implements OnInit {
  @Input() type: SocialCardType;
  @ViewChild('vrf', {read: ViewContainerRef}) vrf:   ViewContainerRef;
  cardTypes = SocialCardType;
  ...
}
```

1.  为了动态创建组件，我们需要监听类型输入的变化。所以，每当它发生变化时，我们就动态加载适当的组件。为此，我们将在`SocialCardComponent`中实现`ngOnChanges`钩子，并暂时在控制台上记录更改。一旦实现，您应该在点击 Facebook 或 Twitter 按钮时在控制台上看到日志。

```ts
import { Component, OnInit, OnChanges, Input, ComponentFactoryResolver, ViewChild, ViewContainerRef, SimpleChanges } from '@angular/core';
...
export class SocialCardComponent implements OnInit, OnChanges {
  ...
  ngOnChanges(changes: SimpleChanges) {
    if (changes.type.currentValue !== undefined) {
      console.log('card type changed to:       ${changes.type.currentValue}')
    }
  }
}
```

1.  现在，我们将在`SocialCardComponent`中创建一个名为`loadDynamicComponent`的方法，该方法接受社交卡的类型，即`SocialCardType`，并决定动态加载哪个组件。我们还将在方法内部创建一个名为`component`的变量，以选择要加载的组件。代码应该如下所示：

```ts
import {...} from '@angular/core';
import { SocialCardType } from 'src/app/constants/social-card-type';
import { FbCardComponent } from '../fb-card/fb-card.component';
import { TwitterCardComponent } from '../twitter-card/twitter-card.component';
...
export class SocialCardComponent implements OnInit {
  ...
  ngOnChanges(changes: SimpleChanges) {
    if (changes.type.currentValue !== undefined) {
      this.loadDynamicComponent(      changes.type.currentValue)
    }
  }
  loadDynamicComponent(type: SocialCardType) {
    let component;
    switch (type) {
      case SocialCardType.Facebook:
        component = FbCardComponent;
        break;
      case SocialCardType.Twitter:
        component = TwitterCardComponent;
        break;
    }
  }
}
```

1.  现在我们知道要动态加载哪个组件，让我们使用`componentFactoryResolver`来解析组件，然后在`ViewContainerRef`(`vrf`)中创建组件，如下所示：

```ts
...
export class SocialCardComponent implements OnInit {
  ...
  loadDynamicComponent(type: SocialCardType) {
    let component;
    switch (type) {
      ...
    }
    const componentFactory = this.componentFactory     Resolver.resolveComponentFactory(component);
    this.vrf.createComponent(componentFactory);
  }
}
```

通过前面的更改，我们已经接近成功了。当您第一次点击 Facebook 或 Twitter 按钮时，您应该看到适当的组件被动态创建。

但是…如果你再次点击其中任何一个按钮，你会看到组件被添加到视图中作为一个额外的元素。

检查后，它可能看起来像这样：

![图 1.12 - 预览多个元素被添加到 ViewContainerRef](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_1.12_B15150.jpg)

图 1.12 - 预览多个元素被添加到 ViewContainerRef

阅读*它是如何工作的…*部分，了解为什么会发生这种情况。但要解决这个问题，我们只需在创建动态组件之前在`ViewContainerRef`上执行`clear()`，如下所示：

```ts
...
export class SocialCardComponent implements OnInit {
  ...
  loadDynamicComponent(type: SocialCardType) {
    ...
    const componentFactory = this.    componentFactoryResolver.    resolveComponentFactory(component);
    this.vrf.clear();
    this.vrf.createComponent(componentFactory);
  }
}
```

## 它是如何工作的…

`ComponentFactoryResolver`是一个 Angular 服务，允许您在运行时动态解析组件。在我们的示例中，我们使用`resolveComponentFactory`方法，该方法接受一个**组件**并返回一个`ComponentFactory`。我们可以始终使用`ComponentFactory`的`create`方法来创建组件的实例。但在这个示例中，我们使用了`ViewContainerRef`的`createComponent`方法，该方法接受`ComponentFactory`作为输入。然后它在后台使用`ComponentFactory`来生成组件，然后将其添加到附加的`ViewContainerRef`中。每次您创建一个组件并将其附加到`ViewContainerRef`时，它都会将新组件添加到现有元素列表中。对于我们的示例，我们只需要一次显示一个组件，即`FBCardComponent`或`TwitterCardComponent`。因此，在添加元素之前，我们在`ViewContainerRef`上使用了`clear()`方法，以便只存在单个元素。

## 另请参阅

+   `resolveComponentFactory`方法：[`angular.io/api/core/ComponentFactoryResolver#resolvecomponentfactory`](https://angular.io/api/core/ComponentFactoryResolver#resolvecomponentfactory)

+   Angular 关于动态组件加载器的文档：[`angular.io/guide/dynamic-component-loader`](https://angular.io/guide/dynamic-component-loader)

+   `ViewContainerRef`文档：[`angular.io/api/core/ViewContainerRef`](https://angular.io/api/core/ViewContainerRef)

+   在 Angular 9 中使用 IVY 动态加载组件：[`labs.thisdot.co/blog/loading-components-dynamically-in-angular-9-with-ivy`](https://labs.thisdot.co/blog/loading-components-dynamically-in-angular-9-with-ivy)


# 第二章：*第二章*：理解和使用 Angular 指令

在本章中，您将深入了解 Angular 指令。您将学习关于属性指令，使用一个非常好的真实世界示例来使用高亮指令。您还将编写您的第一个结构指令，并了解`ViewContainer`和`TemplateRef`服务如何一起工作，以从**文档对象模型**（**DOM**）中添加/删除元素，就像`*ngIf`的情况一样，并创建一些真正酷炫的属性指令来执行不同的任务。最后，您将学习如何在同一个**超文本标记语言**（**HTML**）元素上使用多个结构指令，以及如何增强自定义指令的模板类型检查。

以下是本章我们将要涵盖的食谱：

+   使用属性指令来处理元素的外观

+   创建一个用于计算文章阅读时间的指令

+   创建一个基本指令，允许您垂直滚动到一个元素

+   编写您的第一个自定义结构指令

+   如何同时使用`*ngIf`和`*ngSwitch`

+   增强自定义指令的模板类型检查

# 技术要求

对于本章的食谱，请确保您的机器上安装了**Git**和**Node.js**。您还需要安装`@angular/cli`包，您可以在终端中使用`npm install -g @angular/cli`来安装。本章的代码可以在[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter02`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter02)找到。

# 使用属性指令来处理元素的外观

在这个食谱中，您将使用名为**highlight**的 Angular 属性指令。使用这个指令，您将能够在段落中搜索单词和短语，并在进行搜索时将它们高亮显示。当我们进行搜索时，整个段落的容器背景也会改变。

## 准备工作

我们将要使用的项目位于克隆存储库中的`chapter02/start_here/ad-attribute-directive`中：

1.  在**Visual Studio Code**（**VS Code**）中打开项目。

1.  打开终端，并运行`npm install`来安装项目的依赖。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器标签中打开应用程序，你应该会看到类似这样的东西：

![图 2.1 - ad-attribute-directives 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.01_B15150.jpg)

图 2.1 - 在 http://localhost:4200 上运行的 ad-attribute-directives 应用程序

## 如何做…

到目前为止，该应用程序具有搜索输入框和段落文本。我们需要能够在搜索框中输入搜索查询，以便我们可以在段落中突出显示匹配的文本。以下是我们实现这一点的步骤：

1.  我们将在`app.component.ts`文件中创建一个名为`searchText`的属性，我们将用作搜索文本输入的**模型**：

```ts
...
export class AppComponent {
  title = 'ad-attribute-directive';
  searchText = '';
}
```

1.  然后，我们在`app.component.html`文件中使用`searchText`属性作为`ngModel`的搜索输入，如下所示：

```ts
…
<div class="content" role="main">
  ...
    <input [(ngModel)]="searchText" type="text"     class="form-control" placeholder="Search Text"     aria-label="Username" aria-describedby=    "basic-addon1">
  </div>
```

重要提示

请注意，`ngModel`没有`FormsModule`无法工作，因此我们已经将`FormsModule`导入到我们的`app.module.ts`文件中。

1.  现在，我们将通过在`ad-attributes-directive`项目中使用以下命令来创建一个名为`highlight`的**属性指令**：

```ts
 ng g d directives/highlight
```

1.  上述命令生成了一个具有名为`appHighlight`的选择器的指令。请参阅*它是如何工作的…*部分，了解为什么会发生这种情况。现在我们已经放置了指令，我们将为指令创建两个输入，以从`AppComponent`（从`app.component.html`）传递 - 一个用于搜索文本，另一个用于突出显示颜色。在`highlight.directive.ts`文件中，代码应如下所示：

```ts
 import { Directive, Input } from '@angular/core';
@Directive({
  selector: '[appHighlight]'
})
export class HighlightDirective {
  @Input() highlightText = '';
  @Input() highlightColor = 'yellow';
  constructor() { }
}
```

1.  由于我们现在已经放置了输入，让我们在`app.component.html`中使用`appHighlight`指令，并将`searchText`模型从那里传递到`appHighlight`指令：

```ts
<div class="content" role="main">
  ...
  <p class="text-content" appHighlight   [highlightText]="searchText">
    ...
  </p>
</div>
```

1.  现在我们将监听`searchText`输入的输入更改，使用`ngOnChanges`。请参阅*第一章**，Winning Components Communication**,*中的*使用 ngOnChanges 拦截输入属性更改*一节，了解如何监听输入更改。现在，当输入更改时，我们只会执行`console.log`：

```ts
import { Directive, Input, SimpleChanges, OnChanges } from '@angular/core';
@Directive({
  selector: '[appHighlight]'
})
export class HighlightDirective implements OnChanges {
  ...
  ngOnChanges(changes: SimpleChanges) {
    if (changes.highlightText.firstChange) {
      return;
    }
    const { currentValue } = changes.highlightText;
    console.log(currentValue);
  }
}
```

1.  现在，我们将编写一些逻辑，以便在实际有东西要搜索时该怎么做。为此，我们将首先导入`ElementRef`服务，以便我们可以访问应用指令的模板元素。以下是我们将如何做到这一点：

```ts
import { Directive, Input, SimpleChanges, OnChanges, ElementRef } from '@angular/core';
@Directive({
  selector: '[appHighlight]'
})
export class HighlightDirective implements OnChanges {
  @Input() highlightText = '';
  @Input() highlightColor = 'yellow';
  constructor(private el: ElementRef) { }
  ...
}
```

1.  现在，我们将用一些硬编码的样式替换`el`元素中的每个匹配文本。更新`highlight.directive.ts`中的`ngOnChanges`代码如下，并查看结果：

```ts
ngOnChanges(changes: SimpleChanges) {
    if (changes.highlightText.firstChange) {
      return;
    }
    const { currentValue } = changes.highlightText;
    if (currentValue) {
      const regExp = new RegExp(`(${currentValue})`,       'gi')
      this.el.nativeElement.innerHTML =       this.el.nativeElement.innerHTML.replace       (regExp, `<span style="background-color:       ${this.highlightColor}">\$1</span>`)
    }
 }
```

提示

您会注意到，如果您输入一个单词，它仍然只会显示一个字母被突出显示。这是因为每当我们替换`innerHTML`属性时，我们最终会改变原始文本。让我们在下一步中修复这个问题。

1.  为了保持原始文本不变，让我们创建一个名为`originalHTML`的属性，并在第一次更改时为其分配一个初始值。我们还将在替换值时使用`originalHTML`属性：

```ts
...
export class HighlightDirective implements OnChanges {
  @Input() highlightText = '';
  @Input() highlightColor = 'yellow';
  originalHTML = '';
  constructor(private el: ElementRef) { }
  ngOnChanges(changes: SimpleChanges) {
    if (changes.highlightText.firstChange) {
      this.originalHTML = this.el.nativeElement.      innerHTML;
      return;
    }
    const { currentValue } = changes.highlightText;
    if (currentValue) {
      const regExp = new RegExp(`(${currentValue})`,       'gi')
      this.el.nativeElement.innerHTML =       this.originalHTML.replace(regExp, `<span       style="background-color: ${this.      highlightColor}">\$1</span>`)
    }
  }
}
```

1.  现在，我们将编写一些逻辑，当我们删除搜索查询时（当搜索文本为空时），将一切重置回`originalHTML`属性。为了这样做，让我们添加一个`else`条件，如下所示：

```ts
...
export class HighlightDirective implements OnChanges {
  ...
  ngOnChanges(changes: SimpleChanges) {
   ...
    if (currentValue) {
      const regExp = new RegExp(`(${currentValue})`,       'gi')
      this.el.nativeElement.innerHTML = this.      originalHTML.replace(regExp, `<span       style="background-color: ${this.      highlightColor}">\$1</span>`)
    } else {
      this.el.nativeElement.innerHTML =       this.originalHTML;
    }
  }
}
```

## 它是如何工作的...

我们创建一个属性指令，接受`highlightText`和`highlightColor`输入，然后使用`SimpleChanges` **应用程序编程接口** (**API**) 和`ngOnChanges`生命周期钩子监听`highlightText`输入的更改。

首先，我们要确保通过使用`ElementRef`服务获取附加的元素来保存目标元素的原始内容，使用元素上的`.nativeElement.innerHTML`，然后将其保存到指令的`originalHTML`属性中。然后，每当输入发生变化时，我们将文本替换为一个额外的 HTML 元素（一个`<span>`元素），并将背景颜色添加到这个`span`元素。然后，我们用这个修改后的内容替换目标元素的`innerHTML`属性。就是这样神奇！

## 另请参阅

+   测试 Angular 属性指令文档([`angular.io/guide/testing-attribute-directives`](https://angular.io/guide/testing-attribute-directives))

# 创建一个指令来计算文章的阅读时间

在这个示例中，您将创建一个属性指令来计算文章的阅读时间，就像 Medium 一样。这个示例的代码受到了我在 GitHub 上现有存储库的启发，您可以在以下链接查看：[`github.com/AhsanAyaz/ngx-read-time`](https://github.com/AhsanAyaz/ngx-read-time)。

## 准备工作

这个示例的项目位于`chapter02/start_here/ng-read-time-directive`中：

1.  在 VS Code 中打开项目。

1.  打开终端，运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，您应该会看到类似于这样的东西：

![图 2.2 - ng-read-time-directive 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.02_B15150.jpg)

图 2.2 - ng-read-time-directive 应用正在 http://localhost:4200 上运行

## 如何做…

现在，在我们的`app.component.html`文件中有一个段落，我们需要计算**阅读时间**（以分钟为单位）。让我们开始吧：

1.  首先，我们将创建一个名为`read-time`的属性指令。为此，请运行以下命令：

```ts
ng g directive directives/read-time
```

1.  上面的命令创建了一个`appReadTime`指令。我们首先将这个指令应用到`app.component.html`文件中`id`属性设置为`mainContent`的`div`上，如下所示：

```ts
...
<div class="content" role="main" id="mainContent" appReadTime>
...
</div>
```

1.  现在，我们将为我们的`appReadTime`指令创建一个配置对象。这个配置将包含一个`wordsPerMinute`值，我们将根据这个值来计算阅读时间。让我们在`read-time.directive.ts`文件中创建一个输入，其中包含一个导出的`ReadTimeConfig`接口，用于配置，如下所示：

```ts
import { Directive, Input } from '@angular/core';
export interface ReadTimeConfig {
  wordsPerMinute: number;
}
@Directive({
  selector: '[appReadTime]'
})
export class ReadTimeDirective {
  @Input() configuration: ReadTimeConfig = {
    wordsPerMinute: 200
  }
  constructor() { }
}
```

1.  现在我们可以继续获取文本以计算阅读时间。为此，我们将使用`ElementRef`服务来检索元素的`textContent`属性。我们将提取`textContent`属性并将其分配给`ngOnInit`生命周期钩子中的一个名为`text`的局部变量，如下所示：

```ts
import { Directive, Input, ElementRef, OnInit } from '@angular/core';
...
export class ReadTimeDirective implements OnInit {
  @Input() configuration: ReadTimeConfig = {
    wordsPerMinute: 200
  }
  constructor(private el: ElementRef) { }
  ngOnInit() {
    const text = this.el.nativeElement.textContent;
  }
}
```

1.  现在我们的文本变量已经填满了元素的整个文本内容，我们可以计算阅读这段文本所需的时间。为此，我们将创建一个名为`calculateReadTime`的方法，并将`text`属性传递给它，如下所示：

```ts
...
export class ReadTimeDirective implements OnInit {
  ...
  ngOnInit() {
    const text = this.el.nativeElement.textContent;
    const time = this.calculateReadTime(text);
  }
  calculateReadTime(text: string) {
    const wordsCount = text.split(/\s+/g).length;
    const minutes = wordsCount / this.configuration.    wordsPerMinute;
    return Math.ceil(minutes);
  }
}
```

1.  现在我们已经得到了以分钟为单位的时间，但目前它还不是一个用户可读的格式，因为它只是一个数字。我们需要以一种用户可以理解的方式显示它。为此，我们将进行一些小的计算，并创建一个适当的字符串来显示在**用户界面**（**UI**）上。代码如下所示：

```ts
...
@Directive({
  selector: '[appReadTime]'
})
export class ReadTimeDirective implements OnInit {
...
  ngOnInit() {
    const text = this.el.nativeElement.textContent;
    const time = this.calculateReadTime(text);
    const timeStr = this.createTimeString(time);
    console.log(timeStr);
  }
...
  createTimeString(timeInMinutes) {
    if (timeInMinutes === 1) {
      return '1 minute';
    } else if (timeInMinutes < 1) {
      return '< 1 minute';
    } else {
      return `${timeInMinutes} minutes`;
    }
  }
}
```

*请注意，到目前为止，当您刷新应用程序时，您应该能够在控制台上看到分钟数。*

1.  现在，让我们在指令中添加一个`@Output()`，这样我们就可以在父组件中获取阅读时间并在 UI 上显示它。让我们在`read-time.directive.ts`文件中添加如下内容：

```ts
import { Directive, Input, ElementRef, OnInit, Output, EventEmitter } from '@angular/core';
...
export class ReadTimeDirective implements OnInit {
  @Input() configuration: ReadTimeConfig = {
    wordsPerMinute: 200
  }
  @Output() readTimeCalculated = new   EventEmitter<string>();
  constructor(private el: ElementRef) { }
...
}
```

1.  让我们使用`readTimeCalculated`输出来在我们计算出阅读时间时从`ngOnInit()`方法中发出`timeStr`变量的值：

```ts
...
export class ReadTimeDirective {
...
  ngOnInit() {
    const text = this.el.nativeElement.textContent;
    const time = this.calculateReadTime(text);
    const timeStr = this.createTimeString(time);
    this.readTimeCalculated.emit(timeStr);
  }
...
}
```

1.  由于我们使用 `readTimeCalculated` 输出来发出阅读时间值，我们必须在 `app.component.html` 文件中监听这个输出的事件，并将其分配给 `AppComponent` 类的一个属性，以便我们可以在视图中显示它。但在此之前，我们将在 `app.component.ts` 文件中创建一个本地属性来存储输出事件的值，并且我们还将创建一个在输出事件触发时调用的方法。代码如下所示：

```ts
...
export class AppComponent {
  readTime: string;
  onReadTimeCalculated(readTimeStr: string) {
    this.readTime = readTimeStr;
} 
}
```

1.  我们现在可以在 `app.component.html` 文件中监听输出事件，然后当 `readTimeCalculated` 输出事件被触发时调用 `onReadTimeCalculated` 方法：

```ts
...
<div class="content" role="main" id="mainContent" appReadTime (readTimeCalculated)="onReadTimeCalculated($event)">
...
</div>
```

1.  现在，我们可以在 `app.component.html` 文件中显示阅读时间，如下所示：

```ts
<div class="content" role="main" id="mainContent" appReadTime (readTimeCalculated)="onReadTimeCalculated($event)">
  <h4>Read time = {{readTime}}</h4>
  <p class="text-content">
    Silent sir say desire fat him letter. Whatever     settling goodness too and honoured she building     answered her. ...
  </p>
...
</div>
```

## 它是如何工作的…

`appReadTime` 指令是这个示例的核心。我们在指令内部使用 `ElementRef` 服务来获取指令附加到的原生元素，然后取出它的文本内容。然后，我们只需要进行计算。我们首先使用 `/\s+/g` **正则表达式** (**regex**) 将整个文本内容分割成单词，从而计算出文本内容中的总单词数。然后，我们将单词数除以配置中的 `wordsPerMinute` 值，以计算阅读整个文本需要多少分钟。*轻而易举*。

## 另请参阅

+   Ngx Read Time 库 ([`github.com/AhsanAyaz/ngx-read-time`](https://github.com/AhsanAyaz/ngx-read-time))

+   Angular 属性指令文档 ([`angular.io/guide/testing-attribute-directives`](https://angular.io/guide/testing-attribute-directives))

# 创建一个基本指令，允许您垂直滚动到一个元素

在这个示例中，您将创建一个指令，允许用户点击时滚动到页面上的特定元素。

## 准备工作

这个示例的项目位于 `chapter02/start_here/ng-scroll-to-directive`：

1.  在 VS Code 中打开项目。

1.  打开终端，并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该在新的浏览器标签中打开应用程序，您应该看到类似于这样的东西：

![图 2.3 – ng-scroll-to-directive 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.03_B15150.jpg)

图 2.3 – ng-scroll-to-directive 应用程序运行在 http://localhost:4200

## 如何做…

1.  首先，我们将创建一个`scroll-to`指令，以便我们可以通过平滑滚动到不同的部分来增强我们的应用程序。我们将使用以下命令在项目中实现这一点：

```ts
ng g directive directives/scroll-to
```

1.  现在，我们需要使指令能够接受一个包含我们将在元素的`click`事件上滚动到的目标部分的**层叠样式表**（**CSS**）**查询选择器**的`@Input()`。让我们将输入添加到我们的`scroll-to.directive.ts`文件中，如下所示：

```ts
import { Directive, Input } from '@angular/core';
@Directive({
  selector: '[appScrollTo]'
})
export class ScrollToDirective {
  @Input() target = '';
  constructor() { }
}
```

1.  现在，我们将`appScrollTo`指令应用到`app.component.html`文件中的链接上，同时还指定了相应的目标，以便我们可以在接下来的步骤中实现滚动逻辑。代码应该如下所示：

```ts
...
<div class="content" role="main">
  <div class="page-links">
    <h4 class="page-links__heading">
      Links
    </h4>
    <a class="page-links__link" appScrollTo     target="#resources">Resources</a>
    <a class="page-links__link" appScrollTo     target="#nextSteps">Next Steps</a>
    <a class="page-links__link" appScrollTo     target="#moreContent">More Content</a>
    <a class="page-links__link" appScrollTo     target="#furtherContent">Further Content</a>
    <a class="page-links__link" appScrollTo     target="#moreToRead">More To Read</a>
  </div>
  ...
  <div class="to-top-button">
    <a appScrollTo target="#toolbar" class=    "material-icons">
      keyboard_arrow_up
    </a>
  </div>
</div>
```

1.  现在，我们将实现`HostListener()`装饰器，将`click`事件绑定到附加了指令的元素上。当我们点击链接时，我们将在控制台上记录`target`输入的值。让我们实现这个，然后你可以尝试点击链接，看看控制台上`target`输入的值：

```ts
import { Directive, Input, HostListener } from '@angular/core';
@Directive({
  selector: '[appScrollTo]'
})
export class ScrollToDirective {
  @Input() target = '';
  @HostListener('click')
  onClick() {
    console.log(this.target);
  }
  ...
}
```

1.  由于我们已经设置了`click`处理程序，现在我们可以实现滚动到特定目标的逻辑。为此，我们将使用`document.querySelector`方法，使用`target`变量的值来获取元素，然后使用`Element.scrollIntoView()` web API 来滚动目标元素。通过这个改变，当你点击相应的链接时，页面应该已经滚动到目标元素了：

```ts
...
export class ScrollToDirective {
  @Input() target = '';
  @HostListener('click')
  onClick() {
    const targetElement = document.querySelector     (this.target);
    targetElement.scrollIntoView();
  }
  ...
}
```

1.  好了，我们让滚动起作用了。"*但是，阿赫桑，有什么新鲜事吗？这不是我们以前使用 href 实现的吗？*" 好吧，你是对的。但是，我们将使滚动非常*平滑*。我们将使用`scrollIntoViewOptions`作为`scrollIntoView`方法的参数，使用`{behavior: "smooth"}`值在滚动过程中使用动画。代码应该如下所示：

```ts
...
export class ScrollToDirective {
  @Input() target = '';
  @HostListener('click')
  onClick() {
    const targetElement = document.querySelector     (this.target);
    targetElement.scrollIntoView({behavior: 'smooth'});
  }
  constructor() { }
}
```

## 工作原理...

这个食谱的精髓是我们在 Angular 指令中使用的 web API，即`Element.scrollIntoView()`。我们首先将我们的`appScrollTo`指令附加到应该在点击时触发滚动的元素上。我们还通过为每个附加的指令使用`target`输入来指定要滚动到哪个元素。然后，我们在指令内部实现`click`处理程序，使用`scrollIntoView()`方法滚动到特定目标，并且为了在滚动时使用平滑动画，我们将`{behavior: 'smooth'}`对象作为参数传递给`scrollIntoView()`方法。

## 还有更多...

+   `scrollIntoView()` 方法文档 ([`developer.mozilla.org/en-US/docs/Web/API/Element/scrollIntoView`](https://developer.mozilla.org/en-US/docs/Web/API/Element/scrollIntoView))

+   Angular 属性指令文档 ([`angular.io/guide/testing-attribute-directives`](https://angular.io/guide/testing-attribute-directives))

# 编写您的第一个自定义结构指令

在这个示例中，您将编写您的第一个自定义结构指令，名为 `*appIfNot`，它将执行与 `*ngIf` 相反的操作 - 也就是说，您将向指令提供一个布尔值，当该值为 `false` 时，它将显示附加到指令的内容，而不是 `*ngIf` 指令在提供的值为 `true` 时显示内容。

## 准备工作

此示例中的项目位于 `chapter02/start_here/ng-if-not-directive`：

1.  在 VS Code 中打开项目。

1.  打开终端，并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这将在新的浏览器选项卡中打开应用程序，您应该看到类似于这样的内容：

![图 2.4 - ng-if-not-directive 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.04_B15150.jpg)

图 2.4 - ng-if-not-directive 应用程序在 http://localhost:4200 上运行

## 如何做…

1.  首先，我们将使用以下命令在项目根目录中创建一个指令：

```ts
ng g directive directives/if-not
```

1.  现在，在 `app.component.html` 文件中，我们可以使用我们的 `*appIfNot` 指令，而不是 `*ngIf` 指令。我们还将条件从 `visibility === VISIBILITY.Off` 反转为 `visibility === VISIBILITY.On`，如下所示：

```ts
...
<div class="content" role="main">
  ...
  <div class="page-section" id="resources"   *appIfNot="visibility === VISIBILITY.On">
    <!-- Resources -->
    <h2>Content to show when visibility is off</h2>
  </div>
</div>
```

1.  现在，我们已经设置了条件，我们需要在 `*appIfNot` 指令内部创建一个接受布尔值的 `@Input`。我们将使用一个 **setter** 来拦截值的变化，并暂时将值记录在控制台上：

```ts
import { Directive, Input } from '@angular/core';
@Directive({
  selector: '[appIfNot]'
})
export class IfNotDirective {
  constructor() { }
  @Input() set appIfNot(value: boolean) {
    console.log(`appIfNot value is ${value}`);
  }
}
```

1.  如果现在点击**Visibility On**和**Visibility Off**按钮，您应该看到值的变化并反映在控制台上，如下所示：![图 2.5 - 控制台日志显示 appIfNot 指令值的更改](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.05_B15150.jpg)

图 2.5 - 控制台日志显示 appIfNot 指令值的更改

1.  现在，我们将朝着根据值为 `false` 和 `true` 显示和隐藏内容的实际实现前进，为此，我们首先需要将 `TemplateRef` 服务和 `ViewContainerRef` 服务注入到 `if-not.directive.ts` 的构造函数中。让我们按照以下方式添加这些内容：

```ts
import { Directive, Input, TemplateRef, ViewContainerRef } from '@angular/core';
@Directive({
  selector: '[appIfNot]'
})
export class IfNotDirective {
  constructor(private templateRef: TemplateRef<any>,   private viewContainerRef: ViewContainerRef) { }
  @Input() set appIfNot(value: boolean) {
    console.log(`appIfNot value is ${value}`);
  }
}
```

1.  最后，我们可以添加逻辑来根据`appIfNot`输入的值添加/删除 DOM 中的内容，如下所示：

```ts
...
export class IfNotDirective {
  constructor(private templateRef: TemplateRef<any>,   private viewContainerRef: ViewContainerRef) { }
  @Input() set appIfNot(value: boolean) {
    if (value === false) {
      this.viewContainerRef.      createEmbeddedView(this.templateRef);
    } else {
      this.viewContainerRef.clear()
    }
  }
}
```

## 它是如何工作的...

在 Angular 中，**结构指令**有多个特殊之处。首先，它们允许您操作 DOM 元素，即根据您的需求添加/删除/操作。此外，它们具有`*`前缀，该前缀绑定到 Angular 在幕后执行的所有魔法。例如，`*ngIf`和`*ngFor`都是结构指令，它们在幕后使用包含您绑定指令的内容的`<ng-template>`指令，并为您在`ng-template`的作用域中创建所需的变量/属性。在这个示例中，我们做同样的事情。我们使用`TemplateRef`服务来访问 Angular 在幕后为我们创建的包含应用`appIfNot`指令的**宿主元素**的`<ng-template>`指令。然后，根据指令作为输入提供的值，我们决定是将神奇的`ng-template`添加到视图中，还是清除`ViewContainerRef`服务以删除其中的任何内容。

## 另请参阅

+   Angular 结构指令微语法文档([`angular.io/guide/structural-directives#microsyntax`](https://angular.io/guide/structural-directives#microsyntax))

+   Angular 结构指令文档([`angular.io/guide/structural-directives`](https://angular.io/guide/structural-directives))

+   由 Rangle.io 创建结构指令([`angular-2-training-book.rangle.io/advanced-angular/directives/creating_a_structural_directive`](https://angular-2-training-book.rangle.io/advanced-angular/directives/creating_a_structural_directive))

# 如何同时使用*ngIf 和*ngSwitch

在某些情况下，您可能希望在同一个宿主上使用多个结构指令，例如`*ngIf`和`*ngFor`的组合。在这个示例中，您将学习如何做到这一点。

## 准备工作

我们将要处理的项目位于克隆存储库内的`chapter02/start_here/multi-structural-directives`中。

1.  在 VS Code 中打开项目。

1.  打开终端，并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，你应该会看到类似这样的东西：

![图 2.6-多结构指令应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.06_B15150.jpg)

图 2.6-多结构指令应用程序在 http://localhost:4200 上运行

现在我们的应用程序正在运行，让我们在下一节中看看这个食谱的步骤。

## 如何做…

1.  我们将首先将带有**桶中没有物品。添加一些水果！**文本的元素移入自己的`<ng-template>`元素，并给它一个名为`#bucketEmptyMessage`的模板变量。代码应该在`app.component.html`文件中如下所示：

```ts
…
<div class="content" role="main">
 ...
  <div class="page-section">
    <h2>Bucket <i class="material-icons">shopping_cart     </i></h2>
    <div class="fruits">
      <div class="fruits__item" *ngFor="let item of       bucket;">
        <div class="fruits__item__title">{{item.name}}        </div>
        <div class="fruits__item__delete-icon"         (click)="deleteFromBucket(item)">
          <div class="material-icons">delete</div>
        </div>
      </div>
    </div>
  </div>
  <ng-template #bucketEmptyMessage>
    <div class="fruits__no-items-msg">
      No items in bucket. Add some fruits!
    </div>
  </ng-template>
</div>
```

1.  请注意，我们将整个`div`移出了`.page-section` div。现在，我们将使用`ngIf-Else`语法根据桶的长度显示桶列表或空桶消息。让我们修改代码，如下所示：

```ts
...
<div class="content" role="main">
  ...
  <div class="page-section">
    <h2>Bucket <i class="material-icons">shopping_cart     </i></h2>
    <div class="fruits">
      <div *ngIf="bucket.length > 0; else       bucketEmptyMessage" class="fruits__item"       *ngFor="let item of bucket;">
        <div class="fruits__item__title">{{item.name}}        </div>
        <div class="fruits__item__delete-icon"         (click)="deleteFromBucket(item)">
          <div class="material-icons">delete</div>
        </div>
      </div>
    </div>
  </div>
...
</div>
```

一旦保存了上述代码，您会看到应用程序崩溃，并提到我们不能在一个元素上使用多个模板绑定。这意味着我们不能在一个元素上使用多个结构指令：

![图 2.7 - 控制台上的错误，显示我们不能在一个元素上使用多个指令](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.07_B15150.jpg)

图 2.7 - 控制台上的错误，显示我们不能在一个元素上使用多个指令

1.  现在，作为最后一步，让我们通过将带有`*ngFor="let item of bucket;"`的 div 包装在`<ng-container>`元素内，并在`<ng-container>`元素上使用`*ngIf`指令来解决这个问题，如下所示：

```ts
...
<div class="content" role="main">
  ...
  <div class="page-section">
    <h2>Bucket <i class="material-icons">shopping_cart     </i></h2>
    <div class="fruits">
      <ng-container *ngIf="bucket.length > 0; else       bucketEmptyMessage">
        <div class="fruits__item" *ngFor="let item         of bucket;">
          <div class="fruits__item__title">{{item.          name}}</div>
          <div class="fruits__item__delete-icon"           (click)="deleteFromBucket(item)">
            <div class="material-icons">delete</div>
          </div>
        </div>
      </ng-container>
    </div>
  </div>
</div>
```

## 工作原理…

由于我们不能在单个元素上使用两个结构指令，我们总是可以使用另一个 HTML 元素作为父元素来使用另一个结构指令。然而，这会向 DOM 添加另一个元素，并根据您的实现可能会导致元素层次结构出现问题。然而，`<ng-container>`是 Angular 核心中的一个神奇元素，它不会添加到 DOM 中。相反，它只是包装您应用于它的逻辑/条件，这使得我们可以很容易地在现有元素上添加`*ngIf`或`*ngSwitchCase`指令。

## 另请参阅

+   使用`<ng-container>`文档对兄弟元素进行分组（[`angular.io/guide/structural-directives#group-sibling-elements-with-ng-container`](https://angular.io/guide/structural-directives#group-sibling-elements-with-ng-container)）

# 增强自定义指令的模板类型检查

在这个食谱中，您将学习如何使用 Angular 最近版本引入的静态模板保护来改进自定义 Angular 指令模板的类型检查。我们将增强我们的`appHighlight`指令的模板类型检查，以便它只接受一组缩小的输入。

## 准备工作

我们要处理的项目位于克隆存储库中的`chapter02/start_here/enhanced-template-type-checking`中：

1.  在 VS Code 中打开项目。

1.  打开终端，并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器选项卡中打开应用程序，你应该看到类似这样的东西：

![图 2.8-增强模板类型检查应用程序正在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.08_B15150.jpg)

图 2.8-增强模板类型检查应用程序正在 http://localhost:4200 上运行

现在应用程序正在运行，让我们在下一节中看看这个配方的步骤。

## 如何做…

1.  首先，我们将尝试识别问题，这归结为能够将任何字符串作为`appHighlight`指令的`highlightColor`属性/输入的颜色。试一试。将`'#dcdcdc'`值作为输入，你会有一个破碎的高亮颜色，但没有任何错误：

```ts
...
<div class="content" role="main">
  ...
  <p class="text-content" appHighlight   [highlightColor]="'#dcdcdc'"   [highlightText]="searchText">
    ...
  </p>
</div>
```

1.  好吧，我们该怎么解决呢？通过向我们的`tsconfig.json`文件添加一些`angularCompileOptions`。我们将通过将名为`strictInputTypes`的标志添加为`true`来实现这一点。停止应用程序服务器，修改代码如下，并重新运行`ng serve`命令以查看更改：

```ts
{
  "compileOnSave": false,
  "compilerOptions": {
    ...
  },
  "angularCompilerOptions": {
    "strictInputTypes": true
  }
}
```

你应该看到类似这样的东西：

![图 2.9-strictInputTypes 帮助构建时错误不兼容类型](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.09_B15150.jpg)

图 2.9-strictInputTypes 帮助构建时错误不兼容类型

1.  好了，太棒了！Angular 现在识别出提供的`'#dcdcdc'`值不可分配给`HighlightColor`类型。但是，如果有人尝试提供`null`作为值会发生什么？还好吗？答案是否定的。我们仍然会有一个破碎的体验，但没有任何错误。为了解决这个问题，我们将为我们的`angularCompilerOptions`启用两个标志-`strictNullChecks`和`strictNullInputTypes`：

```ts
{
  "compileOnSave": false,
  "compilerOptions": {
    ...
  },
  "angularCompilerOptions": {
    "strictInputTypes": true,
    "strictNullChecks": true,
    "strictNullInputTypes": true
  }
}
```

1.  更新`app.component.html`文件，将`null`作为`[highlightColor]`属性的值，如下所示：

```ts
...
<div class="content" role="main">
  ...
  <p class="text-content" appHighlight   [highlightColor]="null" [highlightText]="searchText">
   ...
</div>
```

1.  停止服务器，保存文件，并重新运行`ng serve`，你会看到我们现在有另一个错误，如下所示：![图 2.10-使用 strictNullInputTypes 和 strictNullChecks 进行错误报告](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_2.10_B15150.jpg)

图 2.10-使用 strictNullInputTypes 和 strictNullChecks 进行错误报告

1.  现在，我们不再需要为更多情况设置如此多的标志，实际上我们只需要两个标志就可以为我们完成所有的魔术并覆盖大多数应用程序——`strictNullChecks`标志和`strictTemplates`标志：

```ts
{
  "compileOnSave": false,
  "compilerOptions": {
   ...
  },
  "angularCompilerOptions": {
    "strictNullChecks": true,
    "strictTemplates": true
  }
}
```

1.  最后，我们可以将`HighlightColor`枚举导入到我们的`app.component.ts`文件中。我们将在`AppComponent`类中添加一个`hColor`属性，并将其赋值为`HighlightColor`枚举中的一个值，如下所示：

```ts
import { Component } from '@angular/core';
import { HighlightColor } from './directives/highlight.directive';
@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  searchText = '';
  hColor: HighlightColor = HighlightColor.LightCoral;
}
```

1.  现在，我们将在`app.component.html`文件中使用`hColor`属性将其传递给`appHighlight`指令。这应该解决所有问题，并使**浅珊瑚色**成为我们指令的指定高亮颜色：

```ts
<div class="content" role="main">
...
  <p class="text-content" appHighlight   [highlightColor]="hColor" [highlightText]="searchText">
    ...
  </p>
</div>
```

## 另请参阅

+   Angular 结构指令文档（[`angular.io/guide/structural-directives`](https://angular.io/guide/structural-directives)）

+   Angular 文档中的模板类型检查（[`angular.io/guide/template-typecheck#template-type-checking`](https://angular.io/guide/template-typecheck#template-type-checking)）

+   在 Angular 文档中排除模板错误（[`angular.io/guide/template-typecheck#troubleshooting-template-errors`](https://angular.io/guide/template-typecheck#troubleshooting-template-errors)）
