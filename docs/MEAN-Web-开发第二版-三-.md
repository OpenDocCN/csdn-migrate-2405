# MEAN Web 开发第二版（三）

> 原文：[`zh.annas-archive.org/md5/F817AFC272941F1219C1F4494127A431`](https://zh.annas-archive.org/md5/F817AFC272941F1219C1F4494127A431)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Angular 简介

MEAN 拼图的最后一块当然是 Angular。回到 2009 年，当开发人员 Miško Hevery 和 Adam Abrons 在构建他们的 JSON 作为平台服务时，他们注意到常见的 JavaScript 库并不够用。他们丰富的 Web 应用程序的性质引发了对更有结构的框架的需求，以减少冗余工作并保持项目代码有序。他们放弃了最初的想法，决定专注于开发他们的框架，将其命名为 AngularJS，并在开源许可下发布。这个想法是弥合 JavaScript 和 HTML 之间的差距，并帮助推广单页面应用程序的开发。在接下来的几年里，AngularJS—现在被称为 Angular—成为 JavaScript 生态系统中最受欢迎的框架之一，并彻底改变了前端开发世界。然而，在过去的几年里，发生了一些重大的范式转变。因此，当由谷歌赞助的团队决定开发 Angular 的下一个版本时，他们引入了一整套新的想法。在本章中，我们将涵盖以下主题：

+   介绍 TypeScript

+   介绍 Angular 2

+   理解 Angular 2 的构建块

+   安装和配置 TypeScript 和 Angular 2

+   创建和组织 Angular 2 应用程序

+   利用 Angular 的组件架构

+   实现`Authentication`组件

# 介绍 Angular 2

AngularJS 是一个前端 JavaScript 框架，旨在使用类似 MVC 的架构构建单页面应用程序。Angular 的方法是通过特殊属性扩展 HTML 的功能，将 JavaScript 逻辑与 HTML 元素绑定在一起。AngularJS 扩展 HTML 的能力允许通过客户端模板化进行更清晰的 DOM 操作，并实现了无缝同步的双向数据绑定，使模型和视图之间无缝同步。AngularJS 还通过 MVC 和依赖注入改进了应用程序的代码结构和可测试性。AngularJS 1 是一个很棒的框架，但它是基于 ES5 的概念构建的，随着新的 ES2015 规范带来的巨大改进，团队不得不重新思考整个方法。

## 从 Angular 1.x 到 Angular 2.x

如果您已经熟悉 Angular 1，转向 Angular 2 可能看起来是一个很大的步骤。然而，Angular 团队确保保留了 Angular 1 的优点，同时利用 ES2015 的新功能，并保持了通向改进框架的更清晰的路径。以下是从 Angular 1 所做的更改的快速总结：

+   **语法**：Angular 2 依赖于以前称为 ES6 的新 ECMAScript 规范，现在更名为 ES2015。然而，该规范仍在不断发展，浏览器支持仍然不足。为了解决这个问题，Angular 2 团队决定使用 TypeScript。

+   **TypeScript**：TypeScript 是 ES2015 的超集，这意味着它允许您编写强类型的 ES2015 代码，稍后将根据您的需求和平台支持编译为 ES5 或 ES2015 源代码。Angular 2 在其文档和代码示例中大力推动 TypeScript 的使用，我们也会这样做。不过，不用担心；尽管 TypeScript 可能看起来广泛而可怕，但在本章结束时，您将能够使用它。

+   **模块**：Angular 1 引入了一个模块化架构，需要使用`angular#module()`自定义方法。然而，ES2015 引入了一个类似于 Node.js 中使用的内置模块系统。因此，Angular 2 模块更容易创建和使用。

+   **控制器**：Angular 1 主要关注控制器。在本书的第一个版本中，本章主要关注 Angular 1 的 MVC 方法，但在 Angular 2 中，基本构建块是组件。这种转变也代表了 JavaScript 生态系统的更大转变，特别是关于 Web 组件。

+   **作用域**：著名的`$scope`对象现在已经过时。在 Angular 2 中，组件模型更清晰、更可读。一般来说，ES2015 中引入类的概念及其在 TypeScript 中的支持允许更好的设计模式。

+   **装饰器**：装饰器是 TypeScript 中实现的一种设计特性，可能会在 ES2016（ES7）中实现。装饰器允许开发人员注释类和成员，以添加功能或数据，而不扩展实体。Angular 2 依赖装饰器来实现某些功能，您将在本章后面处理它们。

+   **依赖注入**：Angular 1 非常强调依赖注入范式。Angular 2 简化了依赖注入，现在支持多个注入器而不是一个。

所有这些特性标志着 Angular 和 JavaScript 的新时代，一切都始于 TypeScript。

# TypeScript 简介

TypeScript 是由微软创建的一种类型化编程语言，它使用了 C＃、Java 和现在的 ES2015 的面向对象基础。用 TypeScript 编写的代码会被转译成 ES3、ES5 或 ES2015 的 JavaScript 代码，并可以在任何现代 Web 浏览器上运行。它也是 ES2015 的超集，因此基本上任何 JavaScript 代码都是有效的 TypeScript 代码。其背后的想法是创建一个强类型的编程语言，用于大型项目，可以让大型团队更好地沟通其软件组件之间的接口。由于 TypeScript 中的许多特性已经在 ES2015 中实现，我们将介绍一些基本特性，这些特性是我们需要的，但在当前规范中没有得到。

## 类型

类型是每种编程语言的重要部分，包括 JavaScript。不幸的是，静态类型在 ES2015 中没有被引入；然而，TypeScript 支持基本的 JavaScript 类型，并允许开发人员创建和使用自己的类型。

### 基本类型

类型可以是 JavaScript 原始类型，如下面的代码所示：

```js
let firstName: string = "John";
let lastName = 'Smith';
let height: number = 6;
let isDone: boolean = false;
```

此外，TypeScript 还允许您使用数组：

```js
var numbers:number[] = [1, 2, 3];
var names:Array<string> = ['Alice', 'Helen', 'Claire'];
```

然后，这两种方式都被转译成熟悉的 JavaScript 数组声明。

### 任意类型

`any`类型表示任何自由形式的 JavaScript 值。`any`的值将通过转译器进行最小的静态类型检查，并支持作为 JavaScript 值的所有操作。可以访问`any`值上的所有属性，并且`any`值也可以作为带有参数列表的函数调用。实际上，`any`是所有类型的超类型，每当 TypeScript 无法推断类型时，将使用`any`类型。您可以显式或隐式地使用`any`类型：

```js
var x: any;
var y;
```

## 接口

由于 TypeScript 是关于保持项目结构的，语言的重要部分是接口。接口允许您塑造对象并保持代码的稳固和清晰。类可以实现接口，这意味着它们必须符合接口中声明的属性或方法。接口还可以继承自其他接口，这意味着它们的实现类将能够实现扩展的接口。一个示例的 TypeScript 接口将类似于这样：

```js
interface IVehicle {
  wheels: number;
  engine: string;
  drive();
}
```

在这里，我们有一个`IVehicle`接口，有两个属性和一个方法。一个实现类会是这样的：

```js
class Car implements IVehicle  {
  wheels: number;
  engine: string;

  constructor(wheels: number, engine: string) {
    this.wheels = wheels;
    this.engine = engine;
  }

  drive() {
    console.log('Driving...');
  }
}
```

正如您所看到的，`Car`类实现了`IVehicle`接口，并遵循了其设置的结构。

### 注意

接口是 TypeScript 的一个强大特性，也是面向对象编程的重要部分。建议您继续阅读有关它们的内容：[`www.typescriptlang.org/docs/handbook/interfaces.html`](https://www.typescriptlang.org/docs/handbook/interfaces.html)。

## 装饰器

虽然对于新的 ES7 规范来说，它仍处于提案阶段，但 Angular 2 在装饰器上有很大的依赖。装饰器是一种特殊类型的声明，可以附加到各种实体上，比如类、方法或属性。装饰器为开发人员提供了一种可重用的方式来注释和修改类和成员。装饰器使用 `@decoratorName` 的形式，其中 `decoratorName` 参数必须是一个函数，在运行时将被调用以装饰实体。一个简单的装饰器如下所示：

```js
function Decorator(target: any) {

}
@Decorator
class MyClass {

}
```

在运行时，装饰器将使用 `MyClass` 构造函数填充目标参数执行。此外，装饰器也可以带有参数，如下所示：

```js
function DecoratorWithArgs(options: Object) {
  return (target: Object) => {

  }
}

@DecoratorWithArgs({ type: 'SomeType' })
class MyClass {

}
```

这种模式也被称为装饰器工厂。装饰器可能看起来有点奇怪，但一旦我们深入了解 Angular 2，你就会开始理解它们的强大。

### 总结

TypeScript 已经存在多年，并且由一个非常强大的团队开发。这意味着我们仅仅触及了它无尽的功能和能力的表面。然而，这个介绍将为我们提供进入 Angular 2 这个伟大框架所需的技能和知识。

# Angular 2 架构

Angular 2 的目标很简单：以一种可管理和可扩展的方式将 HTML 和 JavaScript 结合起来，以构建客户端应用程序。为此，Angular 2 使用了基于组件的方法，支持实体，如服务和指令，在运行时注入到组件中。这种方法一开始可能有点奇怪，但它允许我们保持关注点的清晰分离，并通常保持更清晰的项目结构。为了理解 Angular 2 的基础知识，请看下面的图：

![Angular 2 架构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_07_01.jpg)

上图展示了一个由两个组件组成的 Angular 2 应用程序的简单架构。中心实体是组件。每个组件都通过其模板执行数据绑定和事件处理，以向用户呈现交互式用户界面。服务用于执行任何其他任务，比如加载数据、执行计算等。然后组件消耗这些服务并委托这些任务。指令是组件模板的渲染指令。为了更好地理解这一点，让我们深入了解一下。

## Angular 2 模块

Angular 2 应用通常是模块化的应用程序。这意味着 Angular 2 应用程序由多个模块组成，每个模块通常都是专门用于单个任务的一段代码。事实上，整个框架都是以模块化的方式构建的，允许开发人员只导入他们需要的功能。幸运的是，Angular 2 使用了我们之前介绍过的 ES2015 模块语法。我们的应用程序也将由自定义模块构建，一个示例应用程序模块如下所示：

```js
import { NgModule }       from '@angular/core';
import { CommonModule }   from '@angular/common';
import { RouterModule }   from '@angular/router';

import { AppComponent }       from './app.component';
import { AppRoutes }       from './app.routes';

@NgModule({
  imports: [
    CommonModule,
    RouterModule.forRoot(AppRoutes),
  ],
  declarations: [
    AppComponent
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

如你所见，我们使用 `@NgModule` 装饰器来创建应用程序模块，该模块使用应用程序组件和路由来启动我们的应用程序。为了更好地理解这一点，让我们来看看 Angular 2 应用程序的第一个和最重要的构建块：组件。

## Angular 2 组件

组件是 Angular 2 应用程序的基本构建块。它的工作是控制用户界面的一个专用部分，通常称为视图。大多数应用程序至少包含一个根应用程序组件，通常还包含多个控制不同视图的组件。组件通常被定义为一个常规的 ES2015 类，带有一个 `@Component` 装饰器，用于将其定义为组件并包含组件元数据。然后将组件类导出为一个模块，可以在应用程序的其他部分导入和使用。一个简单的应用程序组件如下所示：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<h1>I AM AN APPLICATION COMPONENT</h1>'
})
export class AppComponent { 	}
```

注意我们如何从 `@angular/core` 模块库中导入 `@Component` 装饰器，然后使用它来定义我们的组件 DOM 选择器和我们想要使用的模板。最后，我们导出一个名为 `AppComponent` 的类。组件是视图管理的一方，另一方是模板。

## Angular 2 模板

模板由组件用于呈现组件视图。它们由基本的 HTML 与 Angular 专用的注解组合而成，告诉组件如何呈现最终视图。在前面的例子中，你可以看到一个简单的模板直接传递给了 `AppComponent` 类。然而，你也可以将模板保存在外部模板文件中，并将组件更改为如下所示：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  templateUrl: 'app.template.html'
})
export class AppComponent { 	}
```

如你所见，我们当前的模板是静态的，所以为了创建更有用的模板，现在是时候讨论数据绑定了。

## Angular 2 数据绑定

Angular 最大的特点之一是其复杂的数据绑定能力。如果你习惯于在框架之外工作，你就知道在视图和数据模型之间管理数据更新是一种噩梦。幸运的是，Angular 的数据绑定为你提供了一种简单的方式来管理组件类和渲染视图之间的绑定。

### 插值绑定

将数据从组件类绑定到模板的最简单方法称为插值。插值使用双大括号语法将类属性的值与模板绑定。这种机制的一个简单例子如下：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<h1>{{title}}</h1>'
})
export class AppComponent {
  title = 'MEAN Application';
}
```

注意我们如何在模板 HTML 中绑定了 `AppComponent` 类的 `title` 属性。

### 属性绑定

单向数据绑定的另一个例子是属性绑定，它允许你将 HTML 元素的属性值与组件属性值或任何其他模板表达式绑定。这是使用方括号来完成的，如下所示：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<button [disabled]="isButtonDisabled">My Button</button>'
})
export class AppComponent {
  isButtonDisabled = true;
}
```

在这个例子中，Angular 会将按钮呈现为禁用状态，因为我们将 `isButtonDisabled` 属性设置为 `true`。

### 事件绑定

为了使你的组件响应从视图生成的 DOM 事件，Angular 2 为你提供了事件绑定的机制。要将 DOM 事件绑定到组件方法，你只需要在圆括号内设置事件名称，如下例所示：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<button (click)="showMessage()">Show Message</button>'
})
export class AppComponent {
  showMessage() {
    alert('This is a message!')
  }
}
```

在这个例子中，视图按钮的点击事件将调用我们的 `AppComponent` 类内的 `showMessage()` 方法。

### 双向绑定

到目前为止，我们只讨论了单向数据绑定，其中视图调用组件函数或组件改变视图。然而，当处理用户输入时，我们需要以一种无缝的方式进行双向数据绑定。这可以通过将 `ngModel` 属性添加到你的输入 HTML 元素并将其绑定到组件属性来完成。为了做到这一点，我们需要使用圆括号和方括号的组合语法，如下例所示：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<h1>Hello {{name}}</h1><br><input [(ngModel)]="name">'
})
export class AppComponent {
  name = ''
}
```

在这个例子中，用户将看到一个标题元素，它将根据输入实时更新。输入双向绑定了名称属性，因此对输入值的每次更改都将更新到 `AppComponent` 类并呈现到视图中。我们在这里使用的 `ngModel` 属性被称为指令，因此自然而然地，现在是时候讨论指令了。

## Angular 2 指令

Angular 的基本操作是使用一组通常是指令的指令将我们的动态模板转换为视图。有几种类型的指令，但最基本和令人惊讶的是组件。`@Component` 装饰器实际上通过向其添加模板来扩展了 `@Directive` 装饰器。还记得之前例子中的选择器属性吗？如果你在另一个组件内使用这个选择器作为标签，它将呈现我们的组件内部。但这只是一种指令的类型；另一种是我们在之前例子中使用的 `ngModel` 指令。总而言之，我们有三种类型的指令。

### 属性指令

属性指令改变 DOM 元素的行为或外观。我们将这些指令作为 HTML 属性应用于要更改的 DOM 元素上。Angular 2 包含了几个预定义的属性指令，例如以下内容：

+   `ngClass`：为元素绑定单个或多个类的方法

+   `ngStyle`：为元素绑定单个或多个内联样式的方法

+   `ngModel`：为表单元素创建双向数据绑定

这只是一些例子，但您应该记住，您可以并且应该编写自己的自定义指令。

### 结构指令

结构指令通过移除和添加 DOM 元素来改变我们应用程序的 DOM 布局。Angular 2 包含了三个您应该了解的主要结构指令：

+   `ngIf`：提供一种根据条件添加或移除元素的方法

+   `ngFor`：提供一种根据对象列表创建元素副本的方法

+   `ngSwitch`：提供一种根据属性值从元素列表中显示单个元素的方法

所有结构指令都使用一种称为 HTML5 模板的机制，它允许我们的 DOM 保留一个 HTML 模板，而不使用模板标签进行渲染。当我们使用这些指令时，这会产生一个我们将讨论的后果。

### 组件指令

正如之前所述，每个组件基本上都是一个指令。例如，假设我们有一个名为`SampleComponent`的组件：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'sample-component',
  template: '<h1>I'm a component</h1>'
})
export class SampleComponent {

}
```

我们可以在`AppComponent`类中将其作为指令使用，如下所示：

```js
import { Component } from '@angular/core';
import { SampleComponent } from 'sample.component';

@Component({
  selector: 'mean-app',
  template: '<sample-component></sample-component>',
  directives: [SampleComponent]
})
export class AppComponent {

}
```

请注意我们如何在`AppComponent`类中使用`sample-component`标签并包含我们的`SampleComponent`模块在指令列表中。

总之，对于许多 Angular 1 开发人员来说，指令曾经是一个令人恐惧的概念，但现在它们变得简单、易于理解和有趣。在本书的后面，您将学习如何使用本节中介绍的大部分概念。

## Angular 2 服务

服务是 Angular 2 的一个重要部分。它们基本上只是应用程序中单一目的或功能所需的类。由于我们希望保持组件的清晰并专注于用户体验，服务几乎包含了其他所有内容。例如，任何数据管理、日志记录、应用程序配置或其他不属于组件的功能都将作为服务实现。值得注意的是，Angular 2 服务并没有什么特别之处；它们只是具有定义功能的普通类。它们之所以特别，是因为我们可以使用一种称为依赖注入的机制将这些服务提供给组件。

## Angular 2 依赖注入

依赖注入是一种软件设计模式，由软件工程师马丁·福勒（Martin Fowler）推广。依赖注入背后的主要原则是软件开发架构中的控制反转。为了更好地理解这一点，让我们来看一下以下的`notifier`示例：

```js
const Notifier = function() {
  this.userService = new UserService();
};

Notifier.prototype.notify = function() {
  const user = this.userService.getUser();

  if (user.role === 'admin') {
    alert('You are an admin!');
  } else {
    alert('Hello user!');
  }
};
```

我们的`Notifier`类创建了一个`userService`的实例，当调用`notify()`方法时，它会根据用户角色发出不同的消息。现在这样做可能效果很好，但当您想要测试您的`Notifier`类时会发生什么呢？您将在测试中创建一个`Notifier`实例，但您将无法传递一个模拟的`userService`对象来测试`notify`方法的不同结果。依赖注入通过将创建`userService`对象的责任移交给`Notifier`实例的创建者来解决了这个问题，无论是另一个对象还是一个测试。这个创建者通常被称为注入器。这个示例的一个经过修订的、依赖注入的版本将如下所示：

```js
const Notifier = function(userService) {
  this.userService = userService;
};

Notifier.prototype.notify = function() {
  const user = this.userService.getUser();

  if (user.role === 'admin') {
    alert('You are an admin!');
  } else {
    alert('Hello user!');
  }
};
```

现在，每当您创建`Notifier`类的实例时，注入器将负责将`userService`对象注入到构造函数中，从而使得在构造函数之外控制`Notifier`实例的行为成为可能，这种设计通常被描述为控制反转。

### 在 Angular 2 中使用依赖注入

在 Angular 2 中，依赖注入用于将服务注入到组件中。服务是在构造函数中注入到组件中的，如下所示：

```js
import { Component } from '@angular/core';
import { SomeService } from '../users/services/some.service';

@Component({
  selector: 'some-component',
  template: 'Hello Services',
 providers: [SomeService]
})
export class SomeComponent {
  user = null;
  constructor (private _someService: SomeService) {
    this.user = _someService.user;
  }
}
```

当 Angular 2 创建组件类的实例时，它将首先请求一个注入器来解析所需的服务以调用构造函数。如果注入器包含服务的先前实例，它将提供它；否则，注入器将创建一个新实例。为此，您需要为组件注入器提供服务提供程序。这就是为什么我们在`@Component`装饰器中添加`providers`属性。此外，我们可以在组件树的任何级别注册提供程序，一个常见的模式是在应用程序启动时在根级别注册提供程序，这样服务的相同实例将在整个应用程序组件树中可用。

## Angular 2 路由

在我们着手实现应用程序之前，我们最后一个主题将是导航和路由。使用 Web 应用程序，用户期望一定类型的 URL 路由。为此，Angular 团队创建了一个名为组件路由器的模块。组件路由器解释浏览器 URL，然后在其定义中查找并加载组件视图。支持现代浏览器的历史 API，路由器将响应来自浏览器 URL 栏或用户交互的任何 URL 更改。让我们看看它是如何工作的。

### 设置

由于 Angular 2 团队专注于模块化方法，您需要单独加载路由文件 - 无论是从本地文件还是使用 CDN。此外，您还需要在主 HTML 文件的头部设置`<base href="/">`标签。但现在不用担心这些。我们将在下一节中处理这些更改。

### 路由

每个应用程序将有一个路由器，因此当发生 URL 导航时，路由器将查找应用程序内部的路由配置，以确定要加载哪个组件。为了配置应用程序路由，Angular 提供了一个特殊的数组类，称为`Routes`，其中包括 URL 和组件之间的映射列表。这种机制的示例如下：

```js
import { Routes } from '@angular/router';
import { HomeComponent } from './home.component';

export const HomeRoutes: Routes = [{
  path: '',
  component: HomeComponent,
}];
```

### 路由出口

组件路由器使用分层组件结构，这意味着每个由组件路由器装饰和加载的组件都可以配置子路径。因此，加载根组件并在主应用程序标签中呈现其视图；然而，当加载子组件时，它们将如何以及在哪里呈现？为了解决这个问题，路由器模块包括一个名为`RouterOutlet`的指令。要呈现您的子组件，您只需在父组件的模板中包含`RouterOutlet`指令。一个示例组件如下：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<h1>Application Title</h1>
    <br>
 <router-outlet></router-outlet>'
})
export class AppComponent { ... }
```

请注意，`router-outlet`标签将被替换为您的子组件的视图。

### 路由链接

在我们配置应用程序路由之后，我们将能够通过更改浏览器 URL 或使用`RouterLink`指令来生成指向应用程序内部链接的锚标签来浏览我们的应用程序。`RouterLink`指令使用链接参数数组，路由器将稍后解析为与组件映射匹配的 URL。带有`RouterLink`指令的示例锚标签如下：

```js
<a [routerLink]="['/about']">Some</a>
```

### 总结

随着我们在本章的进展，我们已经了解了 TypeScript 和 Angular 2。我们现在已经涵盖了我们在 MEAN 应用程序中创建 Angular 应用程序所需的一切。所以让我们开始设置我们的项目。

# 项目设置

为了在我们的项目中使用 Angular，我们需要安装 TypeScript 和 Angular。我们需要使用 TypeScript 转译器将我们的 TypeScript 文件转换为有效的 ES5 或 ES6 JavaScript 文件。此外，由于 Angular 是一个前端框架，安装它需要在应用程序的主页面中包含 JavaScript 文件。这可以通过各种方式完成，最简单的方式是下载你需要的文件并将它们存储在`public`文件夹中。另一种方法是使用 Angular 的 CDN 并直接从 CDN 服务器加载文件。虽然这两种方法都简单易懂，但它们都有一个严重的缺陷。加载单个第三方 JavaScript 文件是可读和直接的，但当你开始向项目中添加更多的供应商库时会发生什么？更重要的是，你如何管理你的依赖版本？

所有这些问题的答案都是 NPM！NPM 将允许我们在开发应用程序时安装所有依赖项并运行 TypeScript 转译器。为了做到这一点，你需要修改你的`package.json`文件，如下所示：

```js
{
  "name": "MEAN",
  "version": "0.0.7",
 "scripts": {
 "tsc": "tsc",
 "tsc:w": "tsc -w",
 "app": "node server",
 "start": "concurrently \"npm run tsc:w\" \"npm run app\" ",
 "postinstall": "typings install"
 },
  "dependencies": {
 "@angular/common": "2.1.1",
 "@angular/compiler": "2.1.1",
 "@angular/core": "2.1.1",
 "@angular/forms": "2.1.1",
 "@angular/http": "2.1.1",
 "@angular/platform-browser": "2.1.1",
 "@angular/platform-browser-dynamic": "2.1.1",
 "@angular/router": "3.1.1",
    "body-parser": "1.15.2",
 "core-js": "2.4.1",
    "compression": "1.6.0",
    "connect-flash": "0.1.1",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
    "passport": "0.3.2",
    "passport-facebook": "2.1.1",
    "passport-google-oauth": "1.0.0",
    "passport-local": "1.0.0",
    "passport-twitter": "1.0.4",
 "reflect-metadata": "0.1.8",
 "rxjs": "5.0.0-beta.12",
 "systemjs": "0.19.39",
 "zone.js": "0.6.26"
  },
  "devDependencies": {
 "concurrently": "3.1.0",
 "traceur": "0.0.111",
    "typescript": "2.0.3",
    "typings": "1.4.0"
  }
}
```

在我们的新`package.json`文件中，我们做了一些事情；首先，我们添加了我们项目的 Angular 依赖，包括一些支持库：

+   **CoreJS**：这将为我们提供一些 ES6 polyfills

+   **ReflectMetadata**：这将为我们提供一些元数据反射 polyfill

+   **Rx.JS**：这是一个我们以后会使用的响应式框架

+   **SystemJS**：这将帮助加载我们的应用程序模块

+   **Zone.js**：这允许创建不同的执行上下文区域，并被 Angular 库使用

+   **Concurrently**：这将允许我们同时运行 TypeScript 转译器和我们的服务器

+   **Typings**：这将帮助我们下载预定义的外部库的 TypeScript 定义

在顶部，我们添加了一个 scripts 属性，其中我们定义了希望 npm 为我们运行的不同脚本。例如，我们有一个脚本用于安装第三方库的类型定义，另一个用于运行名为`tsc`的 TypeScript 编译器的脚本，一个名为`app`的脚本用于运行我们的节点服务器，以及一个名为`start`的脚本，使用并发工具同时运行这两个脚本。

接下来，我们将配置 TypeScript 编译器的运行方式。

## 配置 TypeScript

为了配置 TypeScript 的工作方式，我们需要在应用程序的根目录下添加一个名为`tsconfig.json`的新文件。在你的新文件中，粘贴以下 JSON：

```js
{
  "compilerOptions": {
    "target": "es5",
    "module": "system",
    "moduleResolution": "node",
    "sourceMap": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "removeComments": false,
    "noImplicitAny": false
  },
  "exclude": [
    "node_modules",
    "typings/main",
    "typings/main.d.ts"
  ]
}
```

在我们的`tsconfig.json`文件中，我们配置了 TypeScript 编译器：

+   将我们的 TypeScript 代码编译成 ES5 代码

+   将我们的模块编译成系统模块模式

+   使用 Node 进行模块解析

+   生成源映射

+   包括装饰器并发出它们的元数据

+   保留注释

+   取消任何隐式声明的错误

+   不包括`node_modules`文件夹和类型文件

当我们运行我们的应用程序时，TypeScript 将默认使用`tsconfig.json`配置文件。接下来，你需要在应用程序的根目录下添加一个名为`typings.json`的新文件。在你的新文件中，粘贴以下 JSON：

```js
{
  "globalDependencies": {
  "core-js": "registry:dt/core-js#0.0.0+20160914114559",
    "jasmine": "registry:dt/jasmine#2.5.0+20161025102649",
    "socket.io-client": "registry:dt/socket.io-client#1.4.4+20160317120654",
    "node": "registry:dt/node#6.0.0+20161102143327"
  }
}
```

正如你所看到的，我们已经添加了所有我们需要的第三方库，以便让 TypeScript 转译器正确编译我们的代码。完成后，继续安装你的新依赖：

```js
$ npm install

```

我们需要的所有包都将与我们需要的外部类型定义一起安装，以支持 TypeScript 编译。现在我们已经安装了新的包并配置了我们的 TypeScript 实现，是时候设置 Angular 了。

### 注意

建议你继续阅读 Typings 的官方文档[`github.com/typings/typings`](https://github.com/typings/typings)。

## 配置 Express

要开始使用 Angular，你需要在我们的主 EJS 视图中包含新的 JavaScript 库文件。因此，我们将使用`app/views/index.ejs`文件作为主应用程序页面。然而，NPM 将所有依赖项安装在`node_module`文件夹中，这对我们的客户端不可访问。为了解决这个问题，我们将不得不修改我们的`config/express.js`文件如下：

```js
const path = require('path'),
const config = require('./config'),
const express = require('express'),
const morgan = require('morgan'),
const compress = require('compression'),
const bodyParser = require('body-parser'),
const methodOverride = require('method-override'),
const session = require('express-session'),
const flash = require('connect-flash'),
const passport = require('passport');

module.exports = function() {
  const app = express();

  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.use(session({
    saveUninitialized: true,
    resave: true,
    secret: config.sessionSecret
  }));

  app.set('views', './app/views');
  app.set('view engine', 'ejs');

  app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());

  app.use('/', express.static(path.resolve('./public')));
 app.use('/lib', express.static(path.resolve('./node_modules')));

  require('../app/routes/users.server.routes.js')(app);
  require('../app/routes/index.server.routes.js')(app);

  return app;
};
```

这里的一个重大变化涉及创建一个指向我们`node_modules`文件夹的`/lib`静态路由。当我们在这里时，我们还切换了用户和索引路由的顺序。当我们开始处理 Angular 的路由机制时，这将非常方便。在这方面，我们还需要做一件事，那就是确保我们的 Express 应用程序在接收到未定义路由时始终返回主应用程序视图。这是为了处理浏览器初始请求使用的 URL 是由 Angular 路由器生成的，而不受我们的 Express 配置支持的情况。为此，返回到`app/routes/index.server.routes.js`文件，并进行如下更改：

```js
module.exports = function(app) {
  const index = require('../controllers/index.server.controller');

  app.get('/*', index.render);
};
```

现在，我们已经配置了 TypeScript 和 Express，是时候设置 Angular 了，但在我们这样做之前，让我们稍微谈谈我们的应用程序结构。

## 重新构建应用程序

正如你可能记得的来自第三章，*构建 Express Web 应用程序*，你的应用程序结构取决于你的应用程序的复杂性。我们之前决定对整个 MEAN 应用程序使用水平方法；然而，正如我们之前所述，MEAN 应用程序可以以各种方式构建，而 Angular 应用程序结构是一个不同的话题，经常由社区和 Angular 开发团队讨论。有许多用于不同目的的原则，其中一些有点复杂，而其他一些则提供了更简单的方法。在本节中，我们将介绍一个推荐的结构。随着从 Angular 1 到 Angular 2 的转变，这个讨论现在变得更加复杂。对我们来说，最简单的方法是从我们 Express 应用程序的`public`文件夹开始，作为 Angular 应用程序的根文件夹，以便每个文件都可以静态地使用。

根据其复杂性，有几种选项可以结构化应用程序。简单的应用程序可以具有水平结构，其中实体根据其类型排列在文件夹中，并且主应用程序文件放置在应用程序的根文件夹中。这种类型的示例应用程序结构可以在以下截图中看到：

![重新构建应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_07_02.jpg)

正如你所看到的，这是一个非常舒适的解决方案，适用于具有少量实体的小型应用程序。然而，你的应用程序可能更复杂，具有多种不同的功能和更多的实体。这种结构无法处理这种类型的应用程序，因为它会混淆每个应用程序文件的行为，将会有一个文件过多的臃肿文件夹，并且通常会非常难以维护。为此，有一种不同的方法来以垂直方式组织文件。垂直结构根据其功能上下文定位每个文件，因此不同类型的实体可以根据其在功能或部分中的角色进行排序。这类似于我们在第三章中介绍的垂直方法，*构建 Express Web 应用程序*。然而，不同之处在于只有 Angular 的逻辑单元将具有独立的模块文件夹结构，通常包括组件和模板文件。Angular 应用程序垂直结构的示例可以在以下截图中看到：

![重新构建应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_07_03.jpg)

如你所见，每个模块都有自己的文件夹结构，这使你可以封装每个组件。我们还使用了我们在第三章中介绍的文件命名约定，*构建 Express Web 应用程序*。

现在你知道了命名和结构化应用程序的基本最佳实践，让我们继续创建应用程序模块。

## 创建应用程序模块

首先，清空`public`文件夹的内容，并在其中创建一个名为`app`的文件夹。在你的新文件夹中，创建一个名为`app.module.ts`的文件。在你的文件中，添加以下代码：

```js
import { NgModule }       from '@angular/core';
import { BrowserModule }  from '@angular/platform-browser';

import { AppComponent }       from './app.component';

@NgModule({
  imports: [
    BrowserModule
  ],
  declarations: [
    AppComponent
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

如你所见，我们基本上只是创建了一个声明应用程序组件并将其用于引导的简单模块。接下来我们需要创建应用程序组件。

## 创建应用程序组件

在你的`public/app`文件夹中，创建一个名为`app.component.ts`的新文件。在你的文件中，添加以下代码：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'mean-app',
  template: '<h1>Hello World</h1>',
})
export class AppComponent {}
```

如你所见，我们基本上只是创建了最简单的组件。接下来我们将学习如何引导我们的`AppModule`类。

## 引导应用程序模块

要引导你的应用程序模块，转到你的`app`文件夹并创建一个名为`bootstrap.ts`的新文件。在你的文件中，添加以下代码：

```js
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from './app.module';

platformBrowserDynamic().bootstrapModule(AppModule);
```

基本上，这段代码使用浏览器平台模块来为浏览器引导应用程序模块。一旦我们配置好这些，就是时候学习如何使用 SystemJS 模块加载器加载我们的引导代码了。

## 启动你的 Angular 应用程序

要使用 SystemJS 作为我们的模块加载器，我们将在`public`文件夹中创建一个名为`systemjs.config.js`的新文件。在你的新文件中，粘贴以下代码：

```js
(function(global) {
  var packages = {
    app: {
      main: './bootstrap.js',
      defaultExtension: 'js'
    }
  };

  var map = {
    '@angular': 'lib/@angular',
    'rxjs': 'lib/rxjs'
  };

  var ngPackageNames = [
    'common',
    'compiler',
    'core',
    'forms',
    'http',
    'router',
    'platform-browser',
    'platform-browser-dynamic',
  ];

  ngPackageNames.forEach(function(pkgName) {	
    packages['@angular/' + pkgName] = { main: '/bundles/' + pkgName + '.umd.js', defaultExtension: 'js' };
  });

  System.config({
    defaultJSExtensions: true,
    transpiler: null,
    packages: packages,
    map: map
  });
})(this);
```

在这个文件中，我们告诉 SystemJS 关于我们的应用程序包以及从哪里加载 Angular 和 Rx 模块。然后我们描述了每个 Angular 包的主文件；在这种情况下，我们要求它加载每个包的 UMD 文件。然后我们使用`System.config`方法来配置 SystemJS。最后，我们重新访问我们的`app/views/index.ejs`文件并进行更改，如下所示：

```js
<!DOCTYPE html>
<html>
<head>
  <title><%= title %></title>
 <base href="/">
</head>
<body>
  <mean-app>
    <h1>Loading...</h1>
  </mean-app>

 <script src="img/shim.min.js"></script>
 <script src="img/zone.js"></script>
 <script src="img/Reflect.js"></script>
 <script src="img/system.js"></script>

 <script src="img/systemjs.config.js"></script>
 <script>
 System.import('app').catch(function(err){ console.error(err); });
 </script>
</body>
</html>
```

如你所见，我们直接从`node_modules`包文件夹中加载我们的模块文件，并包括我们的 SystemJS 配置文件。最后一个脚本告诉 SystemJS 加载我们在配置文件中定义的应用程序包。

### 注意

要了解更多关于 SystemJS 的信息，建议你访问官方文档[`github.com/systemjs/systemjs`](https://github.com/systemjs/systemjs)。

现在你所要做的就是在命令行中调用以下命令来运行你的应用程序：

```js
$ npm start

```

当你的应用程序正在运行时，使用浏览器打开你的应用程序 URL，地址为`http://localhost:3000`。你应该看到一个标题标签显示`Hello World`。恭喜！你已经创建了你的第一个 Angular 2 模块和组件，并成功地引导了你的应用程序。接下来，我们将重构应用程序的身份验证部分并创建一个新的身份验证模块。

# 管理身份验证

管理 Angular 应用程序的身份验证是一个复杂的问题。问题在于，虽然服务器保存了关于经过身份验证的用户的信息，但 Angular 应用程序并不知道这些信息。一个解决方案是使用一个服务并向服务器询问身份验证状态；然而，这个解决方案存在缺陷，因为所有的 Angular 组件都必须等待响应返回，导致不一致和开发开销。这可以通过使用高级的 Angular 路由对象来解决；然而，一个更简单的解决方案是让 Express 应用程序直接在 EJS 视图中渲染`user`对象，然后使用 Angular 服务来提供该对象。

## 渲染用户对象

要渲染经过身份验证的`user`对象，你需要进行一些更改。让我们从更改`app/controllers/index.server.controller.js`文件开始，如下所示：

```js
exports.render = function(req, res) {
  const user = (!req.user) ? null : {
    _id: req.user.id,
    firstName: req.user.firstName,
    lastName: req.user.lastName
  };

  res.render('index', {
    title: 'Hello World',
    user: JSON.stringify(user)
  });
};
```

接下来，转到你的`app/views/index.ejs`文件并进行以下更改：

```js
<!DOCTYPE html>
<html>
<head>
  <title><%= title %></title>
  <base href="/">
</head>
<body>
  <mean-app>
    <h1>Loading...</h1>
  </mean-app>

 <script type="text/javascript">
 window.user = <%- user || 'null' %>;
 </script>

  <script src="img/shim.min.js"></script>
  <script src="img/zone.js"></script>
  <script src="img/Reflect.js"></script>
  <script src="img/system.js"></script>

  <script src="img/systemjs.config.js"></script>

  <script>
    System.import('app').catch(function(err){ console.error(err); });
  </script>
</body>
</html>
```

这将在您的主视图应用程序中以 JSON 表示形式呈现用户对象。当 Angular 应用程序启动时，身份验证状态将已经可用。如果用户已经通过身份验证，`user`对象将变为可用；否则，`user`对象将为 Null。

## 修改用户服务器控制器

为了支持我们的身份验证重构，我们需要确保我们的用户服务器控制器能够处理 Angular 服务请求。为此，您需要更改您的`app/controllers/users.server.controller.js`文件中的代码如下：

```js
const User = require('mongoose').model('User'),
  passport = require('passport');

const getErrorMessage = function(err) {
  const message = '';

  if (err.code) {
    switch (err.code) {
      case 11000:
      case 11001:
      message = 'Username already exists';
      break;
      default:
      message = 'Something went wrong';
    }
  } else {
    for (let errName in err.errors) {
      if (err.errors[errName].message) message = err.errors[errName].message;
    }
  }

  return message;
};

exports.signin = function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err || !user) {
      res.status(400).send(info);
    } else {
      // Remove sensitive data before login
      user.password = undefined;
      user.salt = undefined;

      req.login(user, function(err) {
        if (err) {
          res.status(400).send(err);
        } else {
          res.json(user);
        }
      });
    }
  })(req, res, next);
};

exports.signup = function(req, res) {
  const user = new User(req.body);
  user.provider = 'local';

  user.save((err) => {
    if (err) {
      return res.status(400).send({
        message: getErrorMessage(err)
      });
    } else {
      // Remove sensitive data before login
      user.password = undefined;
      user.salt = undefined;

      req.login(user, function(err) {
        if (err) {
          res.status(400).send(err);
        } else {
          res.json(user);
        }
      });
    }
  });
};

exports.signout = function(req, res) {
  req.logout();
  res.redirect('/');
};

exports.saveOAuthUserProfile = function(req, profile, done) {
  User.findOne({
    provider: profile.provider,
    providerId: profile.providerId
  }, function(err, user) {
    if (err) {
      return done(err);
    } else {
      if (!user) {
        const possibleUsername = profile.username ||
        ((profile.email) ? profile.email.split('@')[0] : '');

        User.findUniqueUsername(possibleUsername, null,
        function(availableUsername) {
          profile.username = availableUsername;

          user = new User(profile);

          user.save((err) => {
            if (err) {
              const message = _this.getErrorMessage(err);

              req.flash('error', message);
              return res.redirect('/signup');
            }

            return done(err, user);
          });
        });
      } else {
        return done(err, user);
      }
    }
  });
};
```

我们基本上只是将身份验证逻辑封装在两个可以接受和响应 JSON 对象的方法中。现在让我们继续并按照以下方式更改`app/routes/users.server.routes.js`目录：

```js
const users = require('../../app/controllers/users.server.controller'),
  passport = require('passport');

module.exports = function(app) {
  app.route('/api/auth/signup').post(users.signup);
  app.route('/api/auth/signin').post(users.signin);
  app.route('/api/auth/signout').get(users.signout);

  app.get('/api/oauth/facebook', passport.authenticate('facebook', {
    failureRedirect: '/signin'
  }));
  app.get('/api/oauth/facebook/callback', passport.authenticate('facebook', {
    failureRedirect: '/signin',
    successRedirect: '/'
  }));

  app.get('/api/oauth/twitter', passport.authenticate('twitter', {
     failureRedirect: '/signin'
  }));
  app.get('/api/oauth/twitter/callback', passport.authenticate('twitter', {
    failureRedirect: '/signin',
    successRedirect: '/'
  }));

  app.get('/api/oauth/google', passport.authenticate('google', {
    failureRedirect: '/signin',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email'
    ],
  }));
  app.get('/api/oauth/google/callback', passport.authenticate('google', {
    failureRedirect: '/signin',
    successRedirect: '/'
  }));

};
```

注意我们删除了用于渲染身份验证视图的路由。更重要的是，看看我们为所有路由添加了`/api`前缀的方式。将所有路由放在一个前缀下是一个很好的做法，因为我们希望 Angular 路由器能够拥有不干扰我们服务器路由的路由。现在我们的服务器端准备好了，是时候创建我们的 Angular 身份验证模块了。

## 创建身份验证模块

现在我们已经为我们的 Angular 应用程序奠定了基础，我们可以继续并将我们的身份验证逻辑重构为一个统一的身份验证模块。为此，我们将首先在我们的`public/app`文件夹内创建一个名为`authentication`的新文件夹。在我们的新文件夹中，创建一个名为`authentication.module.ts`的文件，并添加以下代码：

```js
import { NgModule }       from '@angular/core';
import { FormsModule }    from '@angular/forms';
import { RouterModule } from '@angular/router';

import { AuthenticationRoutes } from './authentication.routes';
import { AuthenticationComponent } from './authentication.component';
import { SigninComponent } from './signin/signin.component';
import { SignupComponent } from './signup/signup.component';

@NgModule({
  imports: [
    FormsModule,
    RouterModule.forChild(AuthenticationRoutes),
  ],
  declarations: [
    AuthenticationComponent,
    SigninComponent,
    SignupComponent,
  ]
})
export class AuthenticationModule {}
```

我们的模块由三个组件组成：

+   一个身份验证组件

+   一个注册组件

+   一个登录组件

我们还包括了一个身份验证路由配置和 Angular 的 Forms 模块来支持我们的登录和注册表单。让我们开始实现基本的身份验证组件。

### 创建身份验证组件

我们将首先创建我们的身份验证组件层次结构。然后，我们将把我们的服务器登录和注册视图转换为 Angular 模板，将身份验证功能添加到`AuthenticationService`中，并重构我们的服务器逻辑。让我们首先在我们的`public/app/authentication`文件夹内创建一个名为`authentication.component.ts`的文件。在新文件中，粘贴以下代码：

```js
import { Component } from '@angular/core';
import { SigninComponent } from './signin/signin.component';
import { SignupComponent } from './signup/signup.component';

@Component({
  selector: 'authentication',
  templateUrl: 'app/authentication/authentication.template.html',
})
export class AuthenticationComponent { }
```

在这段代码中，我们实现了我们的新身份验证组件。我们首先导入了身份验证服务和注册和登录组件，这些组件我们还没有创建。另一个需要注意的是，这次我们为我们的组件使用了外部模板文件。接下来，我们将为我们的身份验证模块创建路由配置。

### 配置身份验证路由

为此，在我们的`public/app/authentication`文件夹内创建一个名为`authentication.routes.ts`的新文件。在新文件中，粘贴以下代码：

```js
import { Routes } from '@angular/router';

import { AuthenticationComponent } from './authentication.component';
import { SigninComponent } from './signin/signin.component';
import { SignupComponent } from './signup/signup.component';

export const AuthenticationRoutes: Routes = [{
  path: 'authentication',
  component: AuthenticationComponent,
  children: [
    { path: 'signin', component: SigninComponent },
    { path: 'signup', component: SignupComponent },
  ],
}];
```

如您所见，我们创建了一个具有`authentication`父路由和`signin`和`signup`组件两个子路由的新`Routes`实例。接下来，我们将在我们的组件文件夹内创建名为`authentication.template.html`的模板文件。在新文件中，粘贴以下代码：

```js
<div>
  <a href="/api/oauth/google">Sign in with Google</a>
  <a href="/api/oauth/facebook">Sign in with Facebook</a>
  <a href="/api/oauth/twitter">Sign in with Twitter</a>
  <router-outlet></router-outlet>
</div>
```

注意我们在代码中使用了`RouterOutlet`指令。这是我们的子组件将被渲染的地方。我们将继续创建这些子组件。

### 创建登录组件

要实现`signin`组件，请在您的`public/app/authentication`文件夹内创建一个名为`signin`的新文件夹。在您的新文件夹中，创建一个名为`signin.component.ts`的新文件，并添加以下代码：

```js
import { Component } from '@angular/core';
import { Router } from '@angular/router';

import { AuthenticationService } from '../authentication.service';

@Component({
  selector: 'signin',
  templateUrl: 'app/authentication/signin/signin.template.html'
})
export class SigninComponent {
  errorMessage: string;
  credentials: any = {};

  constructor (private _authenticationService: AuthenticationService, private _router: Router) {	}

  signin() {
    this._authenticationService.signin(this.credentials).subscribe(result  => this._router.navigate(['/']),
      error =>  this.errorMessage = error );
  }
}
```

注意我们的`signin`组件如何使用身份验证服务来执行`signin`操作。不用担心，我们将在下一节中实现这一点。接下来，您需要在与您的组件相同的文件夹中创建一个名为`signin.template.html`的文件。在您的新文件中，添加以下代码：

```js
<form (ngSubmit)="signin()">
  <div>
    <label>Username:</label>
    <input type="text" [(ngModel)]="credentials.username" name="username">
  </div>
  <div>
    <label>Password:</label>
    <input type="password" [(ngModel)]="credentials.password" name="password">
  </div>
  <div>
    <input type="submit" value="Sign In">
  </div>
  <span>{{errorMessage}}</span>
</form>
```

我们刚刚创建了一个新的组件来处理我们的身份验证登录操作！注册组件看起来会非常相似。

### 创建注册组件

要实现注册组件，请在您的`public/app/authentication`文件夹内创建一个名为`signup`的新文件夹。在您的新文件夹内，创建一个名为`signup.component.ts`的新文件，并包含以下代码：

```js
import { Component } from '@angular/core';
import { Router } from '@angular/router';

import { AuthenticationService } from '../authentication.service';

@Component({
  selector: 'signup',
  templateUrl: 'app/authentication/signup/signup.template.html'
})
export class SignupComponent {
  errorMessage: string;
  user: any = {};

  constructor (private _authenticationService: 
    AuthenticationService,
    private _router: Router) {}

  signup() {
    this._authenticationService.signup(this.user)
    .subscribe(result  => this._router.navigate(['/']),
    error =>  this.errorMessage = error);
  }
}
```

请注意我们的注册组件如何使用身份验证服务来执行`注册`操作。接下来，您需要在与您的组件相同的文件夹中创建一个名为`signup.template.html`的文件。在您的新文件中，添加以下代码：

```js
<form (ngSubmit)="signup()">
  <div>
  <label>First Name:</label>
    <input type="text" [(ngModel)]="user.firstName" name="firstName">
  </div>
  <div>
    <label>Last Name:</label>
    <input type="text" [(ngModel)]="user.lastName" name="lastName">
  </div>
  <div>
    <label>Email:</label>
    <input type="text" [(ngModel)]="user.email" name="email">
  </div>
  <div>
    <label>Username:</label>
    <input type="text" [(ngModel)]="user.username" name="username">
  </div>
  <div>
    <label>Password:</label>
    <input type="password" [(ngModel)]="user.password" name="password">
  </div>
  <div>
    <input type="submit" value="Sign up" />
  </div>
  <span>{{errorMessage}}</span>
</form>
```

现在我们已经有了我们的身份验证组件，让我们回过头来处理身份验证服务。

### 创建身份验证服务

为了支持我们的新组件，我们需要创建一个身份验证服务，以为它们提供所需的功能。为此，请在您的`public/app/authentication`文件夹内创建一个名为`authentication.service.ts`的新文件。在您的新文件中，粘贴以下代码：

```js
import 'rxjs/Rx';
import { Injectable } from '@angular/core';
import { Http, Response, Headers, RequestOptions } from '@angular/http';
import { Observable } from 'rxjs/Observable';

@Injectable()
export class AuthenticationService {
  public user = window['user'];

  private _signinURL = 'api/auth/signin';
  private _signupURL = 'api/auth/signup';

  constructor (private http: Http) {

  }
  isLoggedIn(): boolean {
    return (!!this.user);
  }

  signin(credentials: any): Observable<any> {
    let body = JSON.stringify(credentials);
    let headers = new Headers({ 'Content-Type': 'application/json' });
    let options = new RequestOptions({ headers: headers });

    return this.http.post(this._signinURL, body, options)
    .map(res => this.user = res.json())
    .catch(this.handleError)
  }

  signup(user: any): Observable<any> {
    let body = JSON.stringify(user);
    let headers = new Headers({ 'Content-Type': 'application/json' });
    let options = new RequestOptions({ headers: headers });

    return this.http.post(this._signupURL, body, options)
    .map(res => this.user = res.json())
    .catch(this.handleError)
  }

  private handleError(error: Response) {
    console.error(error);
    return Observable.throw(error.json().message || 'Server error');
  }
}
```

请注意我们如何使用`@Injectable`装饰器装饰了`AuthenticationService`类。虽然在这种情况下不需要，但用这种装饰器装饰您的服务是一个好习惯。原因是，如果您想要用另一个服务来注入一个服务，您将需要使用这个装饰器，所以为了统一起见，最好是保险起见，装饰所有的服务。另一个需要注意的是我们如何从窗口对象中获取我们的用户对象。

我们还为我们的服务添加了三种方法：一个处理登录的方法，另一个处理注册的方法，以及一个用于错误处理的方法。在我们的方法内部，我们使用 Angular 提供的 HTTP 模块来调用我们的服务器端点。在下一章中，我们将进一步阐述这个模块，但与此同时，您需要知道的是，我们只是用它来向服务器发送 POST 请求。为了完成 Angular 部分，我们的应用程序将需要修改我们的应用程序模块，并添加一个简单的主页组件。

## 创建主页模块

为了扩展我们的简单示例，我们需要一个主页组件，它将为我们的基本根提供视图，并为已登录和未登录的用户呈现不同的信息。为此，请在您的`public/app`文件夹内创建一个名为`home`的文件夹。然后，在此文件夹内创建一个名为`home.module.ts`的文件，其中包含以下代码：

```js
import { NgModule }       from '@angular/core';
import { CommonModule }   from '@angular/common';
import { RouterModule } from '@angular/router';

import { HomeRoutes } from './home.routes';
import { HomeComponent } from './home.component';

@NgModule({
  imports: [
    CommonModule,
    RouterModule.forChild(HomeRoutes),
  ],
  declarations: [
    HomeComponent,
  ]
})
export class HomeModule {}
```

正如您可能已经注意到的，我们的模块只导入了一个新的主页组件和路由配置。让我们继续创建我们的主页组件。

### 创建主页组件

接下来，我们将创建我们的主页组件。为此，请转到您的`public/app/home`文件夹，并创建一个名为`home.component.ts`的新文件，其中包含以下代码：

```js
import { Component } from '@angular/core';
import { AuthenticationService } from '../authentication/authentication.service';

@Component({
  selector: 'home',
  templateUrl: './app/home/home.template.html'
})
export class HomeComponent {
  user: any;

  constructor (private _authenticationService: AuthenticationService) {
    this.user = _authenticationService.user;
  }
}
```

正如您所看到的，这只是一个简单的组件，它注入了身份验证服务，并用于为组件提供用户对象。接下来，我们需要创建我们的主页组件模板。为此，请转到您的`public/app/home`文件夹，并创建一个名为`home.template.html`的文件，其中包含以下代码：

```js
<div *ngIf="user">
  <h1>Hello {{user.firstName}}</h1>
  <a href="/api/auth/signout">Signout</a>
</div>

<div *ngIf="!user">
  <a [routerLink]="['/authentication/signup']">Signup</a>
  <a [routerLink]="['/authentication/signin']">Signin</a>
</div>
```

这个模板的代码很好地演示了我们之前讨论过的一些主题。请注意我们在本章前面讨论过的`ngIf`和`routerLink`指令的使用。

### 配置主页路由

为了完成我们的模块，我们需要为我们的主页组件创建一个路由配置。为此，请在您的`public/app/home`文件夹内创建一个名为`home.routes.ts`的新文件。在您的新文件中，粘贴以下代码：

```js
import { Routes } from '@angular/router';
import { HomeComponent } from './home.component';

export const HomeRoutes: Routes = [{
  path: '',
  component: HomeComponent,
}];
```

正如您所看到的，这只是一个简单的组件路由。为了完成我们的实现，我们需要稍微修改我们的应用程序模块。

## 重构应用程序模块

为了包含我们的身份验证和主页组件模块，我们需要修改我们的`app.module.ts`文件如下：

```js
import { NgModule }       from '@angular/core';
import { BrowserModule }  from '@angular/platform-browser';
import { RouterModule }   from '@angular/router';
import { HttpModule } from '@angular/http';

import { AppComponent }       from './app.component';
import { AppRoutes }       from './app.routes';

import { HomeModule } from './home/home.module';
import { AuthenticationService } from './authentication/authentication.service';
import { AuthenticationModule } from './authentication/authentication.module';

@NgModule({
  imports: [
    BrowserModule,
    HttpModule,
 AuthenticationModule,
 HomeModule,
 RouterModule.forRoot(AppRoutes),
  ],
  declarations: [
    AppComponent
  ],
  providers: [
    AuthenticationService
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }

```

正如您所看到的，这对我们的应用程序模块来说是一个相当大的改变。首先，我们导入了 HTTP 模块和我们的新主页和身份验证模块，以及我们的新应用程序路由配置。我们在`providers`属性中注入了身份验证服务，以便它对我们所有的子模块都可用。我们需要做的最后一件事就是实现我们的应用程序路由配置。

### 配置应用程序路由

配置我们的应用程序路由，我们需要在`public/app`文件夹内创建一个名为`app.routes.ts`的新文件。在新文件中，粘贴以下代码：

```js
import { Routes } from '@angular/router';

export const AppRoutes: Routes = [{
  path: '**',
  redirectTo: '/',
}];
```

正如你所看到的，我们的应用程序由一个非常简单的单一配置组成，它将任何未知的路由请求重定向到我们的主页组件。

就是这样。您的应用程序已经准备好使用了！您需要做的就是在命令行中调用以下命令来运行它：

```js
$ npm start

```

当您的应用程序正在运行时，请使用浏览器打开您的应用程序 URL，地址为`http://localhost:3000`。您应该会看到两个链接，用于注册和登录。尝试使用它们，看看会发生什么。尝试刷新您的应用程序，看看它如何保持其状态和路由。

# 总结

在本章中，您了解了 TypeScript 的基本原理。您学习了 Angular 的构建模块，并了解了它们如何适用于 Angular 2 应用程序的架构。您还学会了如何使用 NPM 安装前端库以及如何结构化和引导您的应用程序。您发现了 Angular 的实体以及它们如何协同工作。您还使用了 Angular 的路由器来配置您的应用程序路由方案。在本章的末尾，我们利用了所有这些知识来重构我们的身份验证模块。在下一章中，您将把迄今为止学到的所有内容连接起来，创建您的第一个 MEAN CRUD 模块。


# 第八章：创建一个 MEAN CRUD 模块

在之前的章节中，您学习了如何设置每个框架以及如何将它们全部连接在一起。在本章中，您将实现 MEAN 应用程序的基本操作构建模块，即 CRUD 模块。CRUD 模块由一个基本实体和创建、读取、更新和删除实体实例的基本功能组成。在 MEAN 应用程序中，您的 CRUD 模块是从服务器端 Express 组件和一个 Angular 客户端模块构建的。在本章中，我们将涵盖以下主题：

+   设置 Mongoose 模型

+   创建 Express 控制器

+   连接 Express 路由

+   创建和组织 Angular 模块

+   理解 Angular 表单

+   介绍 Angular`http`客户端

+   实现 Angular 模块服务

+   实现 Angular 模块组件

# 介绍 CRUD 模块

CRUD 模块是 MEAN 应用程序的基本构建模块。每个 CRUD 模块由支持 Express 和 Angular 功能的两个结构组成。Express 部分是建立在 Mongoose 模型、Express 控制器和 Express 路由文件之上的。Angular 模块稍微复杂，包含一组模板和一些 Angular 组件、服务和路由配置。在本章中，您将学习如何将这些组件组合起来，以构建一个示例的`Article`CRUD 模块。本章的示例将直接从前几章中的示例继续，因此请从第七章 *Angular 简介*中复制最终示例，然后从那里开始。

# 设置 Express 组件

让我们从模块的 Express 部分开始。首先，您将创建一个 Mongoose 模型，用于保存和验证您的文章。然后，您将继续创建处理模块业务逻辑的 Express 控制器。最后，您将连接 Express 路由，以生成控制器方法的 RESTful API。我们将从 Mongoose 模型开始。

## 创建 Mongoose 模型

Mongoose 模型将由四个简单的属性组成，代表我们的`Article`实体。让我们从在`app/models`文件夹中创建 Mongoose 模型文件开始；创建一个名为`article.server.model.js`的新文件，其中包含以下代码片段：

```js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ArticleSchema = new Schema({
  created: {
    type: Date,
    default: Date.now
  },
  title: {
    type: String,
    default: '',
    trim: true,
    required: 'Title cannot be blank'
  },
  content: {
    type: String,
    default: '',
    trim: true
  },
  creator: {
    type: Schema.ObjectId,
    ref: 'User'
  }
});

mongoose.model('Article', ArticleSchema);
```

您应该熟悉这段代码片段，所以让我们快速浏览一下这个模型。首先，您包含了您的模型依赖项，然后使用 Mongoose 的`Schema`对象创建了一个新的`ArticleSchema`。`ArticleSchema`定义了四个模型字段：

+   `created`：这是一个日期字段，表示文章创建的时间

+   `title`：这是一个字符串字段，表示文章标题；请注意如何使用了必需的验证，以确保所有文章都有标题

+   `content`：这是一个字符串字段，表示文章内容

+   `creator`：这是一个表示创建文章的用户的引用对象

最后，您注册了`Article`Mongoose 模型，以便在`Articles`Express 控制器中使用它。接下来，您需要确保您的应用程序正在加载模型文件，因此返回到`config/mongoose.js`文件，并进行以下更改：

```js
const config = require('./config');
const mongoose = require('mongoose');

module.exports = function() {
  const db = mongoose.connect(config.db);

  require('../app/models/user.server.model');
  require('../app/models/article.server.model');

  return db;
};
```

这将加载您的新模型文件，并确保您的应用程序可以使用您的`Article`模型。一旦配置了模型，您就可以创建您的`Articles`控制器。

## 设置 Express 控制器

Express 控制器负责在服务器端管理与文章相关的功能。它旨在为 MongoDB 文章文档提供基本的 CRUD 操作。要开始编写 Express 控制器，请转到您的`app/controllers`文件夹，并创建一个名为`articles.server.controller.js`的新文件。在您新创建的文件中，添加以下依赖项：

```js
const mongoose = require('mongoose');
const Article = mongoose.model('Article');
```

在前面的代码行中，你基本上只包含了你的`Article` mongoose 模型。现在，在开始创建 CRUD 方法之前，建议你为验证和其他服务器错误创建一个错误处理方法。

### Express 控制器的错误处理方法

为了处理 Mongoose 错误，最好编写一个简单的错误处理方法，它将负责从 Mongoose 错误对象中提取简单的错误消息，并将其提供给你的控制器方法。回到你的`app/controllers/articles.server.controller.js`文件，并添加以下代码行：

```js
function getErrorMessage (err) {
  if (err.errors) {
    for (let errName in err.errors) {
      if (err.errors[errName].message) return err.errors[errName].message;
    }
  } else {
    return 'Unknown server error';
  }
};
```

`getErrorMessage()`方法接收 Mongoose 错误对象作为参数，然后遍历错误集合并提取第一个消息。这样做是因为你不希望一次向用户展示多个错误消息。现在你已经设置好了错误处理，是时候编写你的第一个控制器方法了。

### Express 控制器的`create()`方法

Express 控制器的`create()`方法将提供创建新文章文档的基本功能。它将使用 HTTP 请求体作为文档的 JSON 基对象，并使用模型的`save()`方法将其保存到 MongoDB。要实现`create()`方法，请将以下代码添加到你的`app/controllers/articles.server.controller.js`文件中：

```js
exports.create = function(req, res) {
  const article = new Article(req.body);
  article.creator = req.user;

  article.save((err) => {
    if (err) {
      return res.status(400).send({
        message: getErrorMessage(err)
      });
    } else {
      res.status(200).json(article);
    }
  });
};
```

让我们来看一下`create()`方法的代码。首先，你使用 HTTP 请求体创建了一个新的`Article`模型实例。接下来，你将经过身份验证的`passport`用户添加为文章的`creator`。最后，你使用 Mongoose 实例的`save()`方法来保存文章文档。在`save()`回调函数中，值得注意的是你要么返回一个错误响应和适当的 HTTP 错误代码，要么返回新的`article`对象作为 JSON 响应。一旦你完成了`create()`方法，你将继续实现读取操作。读取操作包括两个方法：一个是检索文章列表的方法，另一个是检索特定文章的方法。让我们从列出文章集合的方法开始。

### Express 控制器的`list()`方法

Express 控制器的`list()`方法将提供检索现有文章列表的基本功能。它将使用模型的`find()`方法来检索文章集合中的所有文档，然后输出这个列表的 JSON 表示。要实现`list()`方法，请将以下代码添加到你的`app/controllers/articles.server.controller.js`文件中：

```js
exports.list = function(req, res) {
  Article.find().sort('-created').populate('creator', 'firstName lastName fullName').exec((err, articles) => {
    if (err) {
      return res.status(400).send({
        message: getErrorMessage(err)
      });
    } else {
      res.status(200).json(articles);
    }
  });
};
```

在这个控制器方法中，注意你如何使用 Mongoose 的`find()`函数来获取文章文档的集合，虽然我们可以添加一些 MongoDB 查询，但现在我们将检索集合中的所有文档。接下来，注意文章集合是如何使用`created`属性进行排序的。然后，你可以看到 Mongoose 的`populate()`方法是如何用来向`articles`对象的`creator`属性添加一些用户字段的。在这种情况下，你填充了`creator`用户对象的`firstName`、`lastName`和`fullName`属性。

CRUD 操作的其余部分涉及对单个现有文章文档的操作。当然，你可以在每个方法中实现对文章文档的检索，基本上重复这个逻辑。然而，Express 路由器有一个很好的特性用于处理路由参数，所以在实现 Express CRUD 功能的其余部分之前，你首先要学习如何利用路由参数中间件来节省一些时间和代码冗余。

### Express 控制器的`read()`中间件

Express 控制器的 read() 方法将提供从数据库中读取现有文章文档的基本功能。由于您正在编写一种类似 RESTful API 的东西，因此这种方法的常见用法将通过将文章的 ID 字段作为路由参数来处理。这意味着您发送到服务器的请求将在其路径中包含一个 `articleId` 参数。

幸运的是，Express 路由器提供了 `app.param()` 方法来处理路由参数。该方法允许您为包含 `articleId` 路由参数的所有请求附加一个中间件。然后中间件本身将使用提供的 `articleId` 来查找适当的 MongoDB 文档，并将检索到的 `article` 对象添加到请求对象中。这将允许所有操作现有文章的控制器方法从 Express 请求对象中获取 `article` 对象。为了更清晰，让我们实现路由参数中间件。转到您的 `app/controllers/articles.server.controller.js` 文件并追加以下代码行：

```js
exports.articleByID = function(req, res, next, id) {
  Article.findById(id).populate('creator', 'firstName lastName fullName').exec((err, article) => {
    if (err) return next(err);
    if (!article) return next(new Error('Failed to load article ' + id));

    req.article = article;
    next();
  });
};
```

如您所见，中间件函数签名包含所有 Express 中间件参数和一个 `id` 参数。然后使用 `id` 参数查找文章，并使用 `req.article` 属性引用它。请注意，Mongoose 模型的 `populate()` 方法用于向 `article` 对象的 `creator` 属性添加一些用户字段。在这种情况下，您填充了 `creator` 用户对象的 `firstName`、`lastName` 和 `fullName` 属性。

当您连接 Express 路由时，您将学习如何将 `articleByID()` 中间件添加到不同的路由，但现在让我们添加 Express 控制器的 `read()` 方法，它将返回一个 `article` 对象。要添加 `read()` 方法，请将以下代码行追加到您的 `app/controllers/articles.server.controller.js` 文件中：

```js
exports.read = function(req, res) {
  res.status(200).json(req.article);
};
```

相当简单，不是吗？那是因为您已经在 `articleByID()` 中间件中处理了获取 `article` 对象的问题，所以现在您所需做的就是以 JSON 表示形式输出 `article` 对象。我们将在接下来的部分连接中间件和路由，但在此之前，让我们完成实现 Express 控制器的 CRUD 功能。

### Express 控制器的 update() 方法

Express 控制器的 update() 方法将提供更新现有文章文档的基本操作。它将使用现有的 `article` 对象作为基础对象，然后使用 HTTP 请求体更新 `title` 和 `content` 字段。它还将使用模型的 `save()` 方法将更改保存到数据库。要实现 `update()` 方法，请转到您的 `app/controllers/articles.server.controller.js` 文件并追加以下代码行：

```js
exports.update = function(req, res) {
  const article = req.article;

  article.title = req.body.title;
  article.content = req.body.content;

  article.save((err) => {
    if (err) {
      return res.status(400).send({
        message: getErrorMessage(err)
      });
    } else {
      res.status(200).json(article);
    }
  });
};
```

如您所见，`update()` 方法还假设您已经在 `articleByID()` 中间件中获取了 `article` 对象。因此，您所需做的就是更新 `title` 和 `content` 字段，保存文章，然后以 JSON 表示形式输出更新后的 `article` 对象。如果出现错误，它将使用您之前编写的 `getErrorMessage()` 方法和 HTTP 错误代码输出适当的错误消息。剩下要实现的最后一个 CRUD 操作是 `delete()` 方法；所以让我们看看如何向 Express 控制器添加一个简单的 `delete()` 方法。

### Express 控制器的 delete() 方法

Express 控制器的 delete() 方法将提供删除现有文章文档的基本操作。它将使用模型的 `remove()` 方法从数据库中删除现有文章。要实现 `delete()` 方法，请转到您的 `app/controllers/articles.server.controller.js` 文件并追加以下代码行：

```js
exports.delete = function(req, res) {
  const article = req.article;

  article.remove((err) => {
    if (err) {
      return res.status(400).send({
        message: getErrorMessage(err)
      });
    } else {
      res.status(200).json(article);
    }
  });
};
```

同样，您可以看到`delete()`方法也利用了已经获取的`article`对象，通过`articleByID()`中间件。因此，您所需做的就是调用 Mongoose 模型的`remove()`方法，然后输出已删除的`article`对象作为 JSON 表示。如果出现错误，它将使用您之前编写的`getErrorMessage()`方法输出适当的错误消息和 HTTP 错误代码。

恭喜！您刚刚完成了实现 Express 控制器的 CRUD 功能。在继续连接调用这些方法的 Express 路线之前，让我们花点时间来实现两个授权中间件。

### 实施身份验证中间件

在构建 Express 控制器时，您可能已经注意到大多数方法要求用户进行身份验证。例如，如果`req.user`对象未分配，`create()`方法将无法操作。虽然您可以在方法内部检查此分配，但这将强制您一遍又一遍地实施相同的验证代码。相反，您可以使用 Express 中间件链来阻止未经授权的请求执行您的控制器方法。您应该实施的第一个中间件将检查用户是否已经认证。由于这是一个与身份验证相关的方法，最好将其实施在 Express`users`控制器中，因此转到`app/controllers/users.server.controller.js`文件，并追加以下代码行：

```js
exports.requiresLogin = function(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).send({
      message: 'User is not logged in'
    });
  }

  next();
};
```

`requiresLogin()`中间件使用 Passport 启动的`req.isAuthenticated()`方法来检查用户当前是否已经认证。如果发现用户确实已登录，它将调用链中的下一个中间件；否则，它将以身份验证错误和 HTTP 错误代码进行响应。这个中间件很棒，但如果您想检查特定用户是否被授权执行某个操作，您需要实施一个特定于文章的授权中间件。

### 实施授权中间件

在您的 CRUD 模块中，有两种方法可以编辑现有的文章文档。通常，`update()`和`delete()`方法应该受限，以便只有创建文章的用户才能使用它们。这意味着您需要授权对这些方法的任何请求，以验证当前文章是否正在被其创建者编辑。为此，您需要向`Articles`控制器添加一个授权中间件，因此转到`app/controllers/articles.server.controller.js`文件，并追加以下代码行：

```js
exports.hasAuthorization = function(req, res, next) {
    if (req.article.creator.id !== req.user.id) {
        return res.status(403).send({
            message: 'User is not authorized'
        });
    }

    next();
};
```

`hasAuthorization()`中间件使用`req.article`和`req.user`对象来验证当前用户是否是当前文章的创建者。该中间件还假定它仅对包含`articleId`路由参数的请求执行。现在，您已经将所有方法和中间件放置好，是时候连接启用它们的路线了。

## 连接 Express 路线

在我们开始连接 Express 路线之前，让我们快速回顾一下 RESTful API 的架构设计。RESTful API 提供了一个连贯的服务结构，代表了您可以在应用程序资源上执行的一组操作。这意味着 API 使用预定义的路由结构以及 HTTP 方法名称，以提供 HTTP 请求的上下文。虽然 RESTful 架构可以以不同的方式应用，但 RESTful API 通常遵守一些简单的规则：

+   每个资源的基本 URI，在我们的情况下是`http://localhost:3000/articles`

+   一个数据结构，通常是 JSON，传递到请求体中

+   使用标准的 HTTP 方法（例如，`GET`，`POST`，`PUT`和`DELETE`）

使用这三条规则，您将能够正确地路由 HTTP 请求以使用正确的控制器方法。因此，您的文章 API 将包括五条路线：

+   `GET http://localhost:3000/articles`：这将返回一系列文章

+   `POST http://localhost:3000/articles`：这将创建并返回新文章

+   `GET http://localhost:3000/articles/:articleId`：这将返回单个现有文章

+   `PUT http://localhost:3000/articles/:articleId`：这将更新并返回单个现有文章

+   `DELETE http://localhost:3000/articles/:articleId`：这将删除并返回单篇文章

您可能已经注意到，这些路由已经有了相应的控制器方法。甚至已经实现了`articleId`路由参数中间件，因此剩下的就是实现 Express 路由。为此，请转到`app/routes`文件夹，并创建一个名为`articles.server.routes.js`的新文件。在您新创建的文件中，粘贴以下代码片段：

```js
const users = require('../../app/controllers/users.server.controller');
const articles = require('../../app/controllers/articles.server.controller');

module.exports = function(app) {
  app.route('/api/articles')
     .get(articles.list)
     .post(users.requiresLogin, articles.create);

  app.route('/api/articles/:articleId')
     .get(articles.read)
     .put(users.requiresLogin, articles.hasAuthorization, articles.update)
     .delete(users.requiresLogin, articles.hasAuthorization, articles.delete);

  app.param('articleId', articles.articleByID);
};
```

在上述代码片段中，您做了几件事。首先，您需要了`users`和`articles`控制器，然后使用 Express 的`app.route()`方法来定义 CRUD 操作的基本路由。您使用 Express 路由方法将每个控制器方法与特定的 HTTP 方法进行了连接。您可能还注意到`POST`方法如何使用`users.requiresLogin()`中间件，因为用户需要在创建新文章之前登录。同样，`PUT`和`DELETE`方法使用了`users.requiresLogin()`和`articles.hasAuthorization()`中间件，因为用户只能编辑和删除他们创建的文章。最后，您使用了`app.param()`方法来确保具有`articleId`参数的每个路由将首先调用`articles.articleByID()`中间件。接下来，您需要配置 Express 应用程序以加载您的新`Article`模型和路由文件。

## 配置 Express 应用程序

为了使用您的新的 Express 资源，您必须配置 Express 应用程序以加载您的路由文件。为此，请返回到您的`config/express.js`文件并进行更改，如下所示：

```js
const path = require('path');
const config = require('./config');
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');

module.exports = function() {
  const app = express();

  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.use(session({
    saveUninitialized: true,
    resave: true,
    secret: config.sessionSecret
  }));

  app.set('views', './app/views');
  app.set('view engine', 'ejs');

  app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());

  app.use('/', express.static(path.resolve('./public')));
  app.use('/lib', express.static(path.resolve('./node_modules')));

  require('../app/routes/users.server.routes.js')(app);  
  require('../app/routes/articles.server.routes.js')(app);
  require('../app/routes/index.server.routes.js')(app);

  return app;
}; 
```

就是这样；您的文章的 RESTful API 已经准备就绪！接下来，您将学习如何简单地使用`HTTP`客户端让您的 Angular 组件与其通信。

# 使用 HTTP 客户端

在第七章中，*Angular 简介*，我们提到`http`客户端作为 Angular 2 应用程序与后端 API 之间通信的手段。由于 REST 架构结构良好，因此很容易为我们的 Angular 模块实现一个服务，并通过 API 提供给我们的组件，以便与服务器通信。为此，Angular http 客户端利用 Observable 模式来处理其异步性质，因此在继续之前，最好快速回顾一下这个强大的模式。

## 响应式编程和 Observables

在编程中，我们大多数情况下期望事情按顺序运行，所有指令都按顺序发生。然而，从一开始，Web 应用程序开发就遭受了缺乏同步性的问题。当处理数据时，特别是在我们的情况下，从服务器检索到的数据时，这是一个特别大的问题。为了解决这个问题，创建了各种不同的模式，现在我们主要使用回调和 Promise 模式。回调在大部分 JavaScript 的生命周期中都是首选，而最近，Promise 开始受到一些关注。然而，Promise 的寿命很短。更准确地说，Promise 可以设置，但只能延迟一次，但我们的数据可能随着时间的推移而改变，所以我们需要创建更多的 Promise。举个例子，假设我们想跟踪对文本字段所做的所有更改并实现“撤销”功能；为此，我们可以使用回调来处理文本更改事件，然后记录所有更改并对其进行处理。这可能看起来很简单，但如果我们有数百个对象，或者如果我们的文本字段值是以编程方式更改的呢？这只是一个非常简单的例子，但这种情况在现代应用程序开发中以各种方式重复出现，为了解决这个问题，出现了一种新的方法论，称为响应式编程。您可能听说过响应式编程，也可能没有，但最容易理解它的方法是意识到它主要是跟踪随时间变化的异步数据，它通过使用 Observables 来实现这一点。Observables 是可以被一个或多个观察者观察的数据流。Observable 会随着时间发出值，并通过新值、错误或完成事件通知“订阅”的观察者。这种机制的可视化表示可以在下图中看到：

![响应式编程和 Observables](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_08_01.jpg)

在这个图表中，您可以看到 Observables 不断发出值的变化，一个错误，另一个值的变化，然后在 Observable 完成其生命周期时发出完成事件。响应式编程可能看起来很复杂，但幸运的是，ReactiveX 库允许我们以非常简单的方式处理 Observables。

### 注意

建议您继续阅读有关响应式编程的内容，因为它正在迅速成为现代 Web 应用程序开发的主要方法。

# ReactiveX 库

Rx 库是一个跨平台库，它使用观察者模式来帮助开发人员管理随时间发生的异步数据更改。简而言之，ReactiveX 是一个允许我们创建和操作 Observable 对象的库。在 Angular 2 项目中，我们使用 RxJS 库，它基本上是 ReactiveX 库的 JavaScript 版本。如果您仔细观察前一章，您将看到我们已经设置了它，甚至在我们的身份验证服务中使用了它。我们通过使用`npm`安装它来实现这一点：

```js
...
"rxjs": "5.0.0-beta.12",
...

```

我们在实体中导入它如下：

```js
...
import 'rxjs/Rx';

```

我们不得不这样做是因为 Angular 团队选择广泛使用 Observables。我们第一次遇到它是在使用 http 客户端时。

## 使用 http 客户端

`http`模块为我们提供了与 RESTful 端点通信的标准化方式。要使用`http`客户端，我们需要将其导入并注入到我们的实体中，然后使用我们的`http`客户端实例执行不同的 HTTP 请求。在第七章中，我们展示了使用 http 客户端执行 POST 请求的简单示例，*Angular 简介*中我们在登录方法中使用了它：

```js
signin(credentials: any): Observable<any> {
      let body = JSON.stringify(credentials);
      let headers = new Headers({ 'Content-Type': 'application/json' });
      let options = new RequestOptions({ headers: headers });

  return this.http.post(this._signinURL, body, options)
                        .map(res => this.user = res.json())
                        .catch(this.handleError)
  }

```

正如您所看到的，我们创建了一个 JSON 字符串，并在调用`http`客户端的`post()`方法之前使用`RequestOptions`对象设置了请求头。`http`客户端方法返回一个 Observable 对象，跟踪 HTTP 响应对象。但是由于我们希望我们的服务提供数据，我们使用`map()`方法提取响应的 JSON 对象。

### 注意

我们需要使用`json()`方法，因为 Angular 遵循 HTTP 响应对象的 ES2015 规范。

请注意，我们还使用我们的`handleError()`方法捕获任何错误。那么我们如何使用从这个方法返回的 Observable 对象？如果您回顾一下我们的`signin`组件，您将能够看到我们如何使用我们的认证服务：

```js
signin() {
    this._authenticationService.signin(this.credentials).subscribe(
    result  => this._router.navigate(['/']), 
    error =>  this.errorMessage = error );
  }
}

```

在这个方法中，我们调用了认证服务的登录方法，然后订阅返回的 Observable。然后我们用第一个箭头函数处理任何值事件，用第二个箭头函数处理任何错误。这基本上是我们使用 HTTP 客户端的方式！

HTTP 客户端提供了各种方法来处理不同的 HTTP 请求：

+   `request(url, options)`: 这个方法允许我们执行由选项对象定义的任何 HTTP 请求。

+   `get()`: 这个方法执行一个`GET` HTTP 请求。

+   `post()`: 这个方法执行一个`POST` HTTP 请求。

+   `put()`: 这个方法执行一个`PUT` HTTP 请求。

+   `delete()`: 这个方法执行一个`DELETE` HTTP 请求。

所有这些方法都返回一个可订阅或可操作的响应 Observable 对象。

### 注意

一个重要的事情要注意的是，HTTP 客户端总是返回一个“冷”可观察对象。这意味着请求本身直到有人订阅可观察对象才会被发送。

在下一节中，您将学习如何使用`http`客户端与您的 Express API 进行通信。

# 实现 Angular 模块

您的 CRUD 模块的第二部分是 Angular 模块。这个模块将包含一个 Angular 服务，该服务将使用`http`客户端与 Express API 进行通信，一个包含四个子组件的 Angular 文章组件，这些子组件具有一组模板，为您的用户提供执行 CRUD 操作的界面。在开始创建您的 Angular 实体之前，让我们首先创建初始模块结构。转到您的应用程序的`public/app`文件夹，并创建一个名为`articles`的新文件夹。在这个新文件夹中，创建名为`articles.module.ts`的模块文件，并粘贴以下代码行：

```js
import { NgModule }       from '@angular/core';
import { CommonModule }   from '@angular/common';
import { FormsModule }    from '@angular/forms';
import { RouterModule } from '@angular/router';

import { ArticlesRoutes } from './articles.routes';
import { ArticlesComponent } from './articles.component';
import { CreateComponent } from './create/create.component';
import { ListComponent } from './list/list.component';
import { ViewComponent } from './view/view.component';
import { EditComponent } from './edit/edit.component';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    RouterModule.forChild(ArticlesRoutes),
  ],
  declarations: [
    ArticlesComponent,
    CreateComponent,
    ListComponent,
    ViewComponent,
    EditComponent,
  ]
})
export class ArticlesModule {}
```

正如您所看到的，我们只是从 Angular 包中导入了我们需要的模块，以及我们新模块的组件、服务和路由定义。接下来，我们创建了一个新的 Angular 模块，它作为子路由导入了 Angular 模块和我们的路由配置，然后声明了我们新模块的组件。现在，我们可以继续创建我们的主组件文件。为此，在您的`public/app`文件夹中创建一个名为`articles.component.ts`的文件，并粘贴以下代码行：

import { Component } from '@angular/core';

```js
import { ArticlesService } from './articles.service';

@Component({
  selector: 'articles',
  template: '<router-outlet></router-outlet>',
  providers: [ArticlesService]
})
export class ArticlesComponent {}

```

在这个文件中，我们导入了基本的 Angular 模块和我们即将创建的文章服务。然后我们创建了一个使用`router-outlet`并注入我们的服务的新组件。接下来，我们需要为我们的`articles`组件创建一个路由配置。为此，创建一个名为`articles.routes.ts`的文件，并粘贴以下代码行：

```js
import { Routes } from '@angular/router';

import { ArticlesComponent } from './articles.component';
import { CreateComponent } from './create/create.component';
import { ListComponent } from './list/list.component';
import { ViewComponent } from './view/view.component';
import { EditComponent } from './edit/edit.component';

export const ArticlesRoutes: Routes = [{
  path: 'articles',
  component: ArticlesComponent,
  children: [
    {path: '', component: ListComponent},
    {path: 'create', component: CreateComponent},
    {path: ':articleId', component: ViewComponent},
    {path: ':articleId/edit', component: EditComponent}
  ],
}];

```

正如您所看到的，我们简单地为我们的组件及其子组件创建了一个路由配置。这段代码应该很熟悉，因为它类似于我们在上一章中实现的认证路由。此外，在我们的更新和查看路径中，我们定义了一个 URL 参数，形式为冒号后跟我们的参数名称，这种情况下是`articleId`参数。

接下来，您需要在我们的应用程序模块配置中导入我们的文章模块。为此，返回到您的`public/app/app.module.ts`文件，并将其更改如下：

```js
import { NgModule }       from '@angular/core';
import { BrowserModule }  from '@angular/platform-browser';
import { FormsModule }    from '@angular/forms';
import { RouterModule }   from '@angular/router';
import { HttpModule, RequestOptions } from '@angular/http';
import { LocationStrategy, HashLocationStrategy } from '@angular/common';

import { AppComponent }       from './app.component';
import { AppRoutes }       from './app.routes';

import { HomeModule } from './home/home.module';
import { AuthenticationService } from './authentication/authentication.service';
import { AuthenticationModule } from './authentication/authentication.module';
import { ArticlesModule } from './articles/articles.module';

@NgModule({
  imports: [
    BrowserModule,
    HttpModule,
    FormsModule,
    AuthenticationModule,
    HomeModule,
    ArticlesModule,
    RouterModule.forRoot(AppRoutes),
  ],
  declarations: [
    AppComponent
  ],
  providers: [
    AuthenticationService
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

这就完成了我们新模块的配置。现在我们可以继续创建我们的模块实体。我们将从我们的模块服务开始。

## 创建 Angular 模块服务

为了使您的 CRUD 模块能够轻松与 API 端点通信，建议您使用一个单一的 Angular 服务，该服务将利用`http`客户端方法。为此，请转到您的`public/app/articles`文件夹，并创建一个名为`articles.service.ts`的新文件，其中包含以下代码行：

```js
import 'rxjs/Rx';
import {Observable} from 'rxjs/Observable';

import {Injectable} from '@angular/core';
import {Http, Headers, Request, RequestMethod, Response} from '@angular/http';

@Injectable()
export class ArticlesService {
  private _baseURL = 'api/articles';

  constructor (private _http: Http) {}

  create(article: any): Observable<any> {
    return this._http
      .post(this._baseURL, article)
      .map((res: Response) => res.json())
      .catch(this.handleError);
    }

  read(articleId: string): Observable<any> {
    return this._http
      .get(`${this._baseURL}/${articleId}`)
      .map((res: Response) => res.json())
      .catch(this.handleError);
  }

  update(article: any): Observable<any> {
    return this._http
      .put(`${this._baseURL}/${article._id}`, article)
      .map((res: Response) => res.json())
      .catch(this.handleError);
    }

  delete(articleId: any): Observable<any> {
    return this._http
      .delete(`${this._baseURL}/${articleId}`)
      .map((res: Response) => res.json())
      .catch(this.handleError);
  }  

  list(): Observable<any> {
    return this._http
      .get(this._baseURL)
      .map((res: Response) => res.json())
      .catch(this.handleError);
  }

  private handleError(error: Response) {
    return Observable.throw(error.json().message || 'Server error');
  }
}
```

让我们来回顾一下。首先，我们从 Angular 库中导入了`Observable`和`rxjs`库模块。您可能注意到我们导入了整个库，因为我们需要在 Observable 对象中使用各种操作符，例如`map()`方法。

接下来，我们从 Angular 库中导入了我们需要的模块，并使用`@Injectable`装饰器创建了我们的可注入服务。我们的服务有一个属性来保存我们的 API 基本 URL，并且有一个构造函数来注入 HTTP 客户端。它包含一个处理服务器错误的方法。我们的其他方法都很容易理解：

+   `create()`: 接受文章对象并使用 HTTP POST 请求将其发送到服务器

+   `read()`: 接受`文章 ID`字符串并使用 HTTP GET 请求向服务器请求文章对象

+   `update()`: 接受文章对象并使用 HTTP PUT 请求将其发送到服务器进行更新

+   `delete()`: 接受`文章 ID`字符串并尝试使用 HTTP DELETE 请求删除它

+   `list()`: 使用 HTTP GET 请求请求文章对象数组

注意我们如何将响应对象映射为只发送 JSON 对象，并且如何捕获任何错误以修改响应，以便我们的组件只需处理数据本身。

就是这样！我们的模块基础设施已经为我们的子组件准备好了。在接下来的章节中，您将能够看到我们如何利用之前的准备来轻松实现我们的实现。

## 实现创建子组件

我们的“创建”子组件将负责创建新文章。首先在`public/app/articles`文件夹内创建一个名为`create`的新文件夹。在此文件夹中，创建一个名为`create.component.ts`的新文件，并粘贴以下代码：

```js
import { Component } from '@angular/core';
import { Router } from '@angular/router';

import { ArticlesService } from '../articles.service';

@Component({
  selector: 'create',
  templateUrl: 'app/articles/create/create.template.html'
})
export class CreateComponent {
  article: any = {};
  errorMessage: string;

  constructor(private _router:Router,
        private _articlesService: ArticlesService) {}

  create() {
    this._articlesService
      .create(this.article)
      .subscribe(createdArticle => this._router.navigate(['/articles', createdArticle._id]),
               error =>  this.errorMessage = error);
  }
}

```

让我们来回顾一下。我们首先从 Angular 库中导入了我们需要的模块以及我们的`ArticlesService`。然后，我们创建了一个带有空文章和`errorMessage`对象的组件。注意我们的组件构造函数如何注入了`Router`和我们的`ArticlesService`服务。然后，我们创建了一个`create()`方法，该方法使用`ArticlesService`来创建一个新的文章对象。在我们的可观察订阅中，我们使用`Router`服务导航到我们的视图组件以及新创建的`文章 ID`。在出现错误的情况下，我们将组件的`errorMessage`属性设置为该消息。为了完成我们的子组件，我们需要创建其模板。

### 添加模板

`create`模板将为您的用户提供一个创建新文章的界面。它将包含一个 HTML 表单，并且将使用您组件的`create`方法来保存新文章。要创建您的模板，请转到`public/app/articles/create`文件夹，并创建一个名为`create.template.html`的新文件。在您的新文件中，粘贴以下代码片段：

```js
<h1>New Article</h1>
<form (ngSubmit)="create()" novalidate>
  <div>
    <label for="title">Title</label>
    <div>
      <input type="text" required [(ngModel)]="article.title" name="title" placeholder="Title">
    </div>
  </div>
  <div>
    <label for="content">Content</label>
    <div>
      <textarea type="text" required cols="30" rows="10" [(ngModel)]="article.content" name="content" placeholder="Content"></textarea>
    </div>
  </div>
  <div>
    <input type="submit">
  </div>

  <strong id="error">{{errorMessage}}</strong>
</form>

```

`create`模板包含一个简单的表单，其中包含两个文本输入字段和一个提交按钮。文本字段使用`ngModel`指令将用户输入绑定到我们组件的属性。还要注意在`form`元素中放置的`ngSubmit`指令。该指令告诉 Angular 在提交表单时调用特定的组件方法。在这种情况下，表单提交将执行您组件的`create()`方法。您应该注意到的最后一件事是表单末尾的错误消息，以防出现任何错误时会显示。接下来，我们将实现视图子组件。

## 实现视图子组件

我们的“查看”子组件将负责呈现单篇文章。我们的组件还将包含一组按钮，仅对文章创建者可见，这些按钮将允许创建者删除文章或导航到“编辑”路由。首先，在`public/app/articles`文件夹内创建一个名为`view`的新文件夹。在这个文件夹中，创建一个名为`view.component.ts`的新文件，并粘贴以下代码：

```js
import { Component } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { AuthenticationService } from '../../authentication/authentication.service';
import { ArticlesService } from '../articles.service';

@Component({
  selector: 'view',
  templateUrl: 'app/articles/view/view.template.html',
})
export class ViewComponent {
  user: any;
  article: any;
  paramsObserver: any;
  errorMessage: string;
  allowEdit: boolean = false;

  constructor(private _router:Router, 
        private _route: ActivatedRoute, 
        private _authenticationService: AuthenticationService, 
        private _articlesService: ArticlesService) {}

  ngOnInit() {
    this.user = this._authenticationService.user

    this.paramsObserver = this._route.params.subscribe(params => {
      let articleId = params['articleId'];

      this._articlesService
        .read(articleId)
        .subscribe(
          article => {
            this.article = article;
            this.allowEdit = (this.user && this.user._id === this.article.creator._id);
           },
          error => this._router.navigate(['/articles'])
        );
    });
  }

  ngOnDestroy() {
    this.paramsObserver.unsubscribe();
  }

  delete() {
    this._articlesService.delete(this.article._id).subscribe(deletedArticle => this._router.navigate(['/articles']),
                                 error => this.errorMessage = error);
  }
}
```

我们从 Angular 库中导入我们需要的模块以及我们的`ArticlesService`和`AuthenticationService`。然后，我们创建了一个具有文章属性、`currentUser`属性、`paramsObserver`属性、`allowEdit`标志和`errorMessage`属性的组件。请注意，我们的组件构造函数注入了`Router`、`RouteParams`和我们的`ArticlesService`和`AuthenticationService`服务。我们的构造函数还使用`AuthenticationService`实例设置了`currentUser`属性。在我们的`ngOnInit`方法中，当组件初始化时被调用，我们从路由参数中读取`文章 ID`参数，然后使用`ArticlesService`来获取现有的文章。我们使用`ActivatedRoute`来完成这个操作，它为我们提供了一个`params` Observable。我们在组件的`ngOnDestroy`方法中取消了对这个 Observable 的订阅。在我们的 Observable 订阅中，我们设置了组件的`article`属性，并确定当前用户是否可以编辑文章。在出现错误时，我们使用`Router`服务来导航回到我们的`List`路由。最后，我们实现了一个`delete()`方法，该方法使用`ArticlesService`来删除查看的文章并返回到文章列表。要完成我们的子组件，我们需要创建它的模板。

### 添加模板

“视图”模板将为用户提供一个界面来“查看”现有文章。您的模板还将包含一组按钮，仅对文章创建者可见，这些按钮将允许创建者删除文章或导航到“编辑”路由。要创建模板，请转到`public/app/articles/view`文件夹，并创建一个名为`view.template.html`的新文件。在新文件中，粘贴以下代码片段：

```js
<section *ngIf="article && article.creator">
  <h1>{{article.title}}</h1>

  <div *ngIf="allowEdit">
      <a [routerLink]="['/articles', article._id, 'edit']">edit</a>
      <button (click)="delete()">delete</button>
  </div>
  <small>
      <em>Posted on {{article.created}} by {{article.creator.fullName}}</em>
  </small>

  <p>{{article.content}}</p>
</section>
```

`view`模板包含一组简单的 HTML 元素，使用`双大括号`语法呈现文章信息。还要注意您如何使用`ngIf`指令，仅向文章的创建者呈现文章编辑链接和删除按钮。编辑链接将引导用户到`edit`子组件，而删除按钮将调用您的控制器的`delete()`方法。接下来，我们将实现我们的编辑组件。

## 实现编辑子组件

我们的“编辑”子组件将负责编辑现有文章。首先，在`public/app/articles`文件夹内创建一个名为`edit`的新文件夹。在这个文件夹中，创建一个名为`edit.component.ts`的新文件，并粘贴以下代码：

```js
import { Component } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';

import { ArticlesService } from '../articles.service';

@Component({
  selector: 'edit',
  templateUrl: 'app/articles/edit/edit.template.html'
})
export class EditComponent {
  article: any = {};
  errorMessage: string;
  paramsObserver: any;

  constructor(private _router:Router, 
        private _route: ActivatedRoute, 
        private _articlesService: ArticlesService) {}

  ngOnInit() {
    this.paramsObserver = this._route.params.subscribe(params => {
      let articleId = params['articleId'];

      this._articlesService.read(articleId).subscribe(article => {
                                this.article = article;
                               },
                              error => this._router.navigate(['/articles']));
    });
  }

  ngOnDestroy() {
    this.paramsObserver.unsubscribe();
  }

  update() {
    this._articlesService.update(this.article).subscribe(savedArticle => this._router.navigate(['/articles', savedArticle._id]),
                                  error =>  this.errorMessage = error);
  }
}
```

再次，我们从 Angular 库中导入我们需要的模块以及我们的`ArticlesService`。然后，我们创建了一个具有文章属性和`errorMessage`属性的组件。在我们的构造函数中，我们从路由参数中读取`文章 ID`，然后使用`ArticlesService`来获取现有的文章。在我们的 Observable 订阅中，我们设置了组件的文章属性，并在出现错误时，我们使用`Router`服务来导航回到我们的 List 路由。最后，我们实现了一个`update()`方法，该方法使用`ArticlesService`来更新查看的文章并返回到 View 路由。要完成我们的子组件，我们需要创建它的模板。

### 添加模板

`edit` 模板将为用户提供一个界面来更新现有文章。它将包含一个 HTML 表单，并使用你的组件的 `update()` 方法来保存更新后的文章。要创建这个模板，转到 `public/app/articles/edit` 文件夹并创建一个名为 `edit.template.html` 的新文件。在你的新文件中，粘贴以下 HTML 代码：

```js
<h1>Edit Article</h1>
<form (ngSubmit)="update()" novalidate>
    <div>
        <label for="title">Title</label>
        <div>
            <input type="text" required [(ngModel)]="article.title" name="title" placeholder="Title">
        </div>
    </div>
    <div>
        <label for="content">Content</label>
        <div>
            <textarea type="text" required cols="30" rows="10" [(ngModel)]="article.content" name="content" placeholder="Content"></textarea>
        </div>
    </div>
    <div>
        <input type="submit" value="Update">
    </div>

    <strong>{{errorMessage}}</strong>
</form>
```

`edit` 模板包含一个简单的表单，其中有两个文本输入字段和一个提交按钮。文本字段使用 `ngModel` 指令将用户输入绑定到组件的 `article` 属性。还要注意在 `form` 元素中放置的 `ngSubmit` 指令。这次，该指令告诉 Angular 表单提交应执行组件的 `update()` 方法。你应该注意到的最后一件事是表单末尾的错误消息，在编辑错误的情况下会显示出来。我们的最终子组件是我们的 List 子组件。

## 实现 List 子组件

我们的 "List" 子组件将负责呈现文章列表。我们将首先在 `public/app/articles` 文件夹内创建一个名为 `list` 的新文件夹。在这个文件夹中，创建一个名为 `list.component.ts` 的新文件，并粘贴以下代码：

```js
import { Component } from '@angular/core';
import { ArticlesService } from '../articles.service';

@Component({
  selector: 'list',
  templateUrl: 'app/articles/list/list.template.html'
})
export class ListComponent{
  articles: any;
  errorMessage: string;

  constructor(private _articlesService: ArticlesService) {}

  ngOnInit() {
    this._articlesService.list().subscribe(articles  => this.articles = articles);
  }
}
```

我们首先从 Angular 库中导入我们需要的模块以及我们的 `ArticlesService`。然后，我们创建了一个具有 articles 属性和 errorMessage 属性的组件。注意我们组件的构造函数如何注入 `ArticlesService` 并使用它来获取文章列表。在我们的 Observables 订阅中，我们设置了组件的 articles 属性。现在我们只剩下实现组件的模板了。

### 添加模板

`list` 模板将为用户提供一个查看现有文章列表的界面。我们的模板将使用 `ngFor` 指令来呈现一系列 HTML 元素，每个元素代表一篇文章。如果没有现有的文章，视图将提供用户导航到 `create` 路由。要创建你的视图，转到 `public/app/articles/list` 文件夹并创建一个名为 `list.template.html` 的新文件。在你的新文件中，粘贴以下代码片段：

```js
<h1>Articles</h1>
<ul>
  <li *ngFor="let article of articles">
    <a [routerLink]="['/articles', article._id]">{{article.title}}</a>
    <br>
    <small>{{article.created}}/{{article.creator.fullName}}</small>
    <p>{{article.content}}</p>
  </li>
</ul>

<div *ngIf="articles && articles.length === 0">
  No articles yet, why don't you <a [routerLink]="['/articles/create']">create one</a>? 
</div>
```

`list` 模板包含一组简单的重复的 HTML 元素，代表文章列表。它使用 `ngFor` 指令为集合中的每篇文章复制列表项并显示每篇文章的信息。然后我们使用 `routerLink` 链接到单篇文章视图。还要注意我们如何使用 `ngIf` 指令来要求用户在没有现有文章的情况下创建一篇新文章。

通过实现你的 Angular 子组件，你实际上完成了你的第一个 CRUD 模块！现在剩下的就是向用户提供到我们新路由的链接。

# 总结

要完成我们的实现，最好是向用户提供到你的新 CRUD 模块路由的链接。为此，转到你的 `public/app/home/home.template.html` 文件并进行更改，如下所示：

```js
<div *ngIf="user">
  <h1>Hello {{user.firstName}}</h1>
  <a href="/api/auth/signout">Signout</a>
  <ul>
    <li><a [routerLink]="['/articles']">List Articles</a></li>
 <li><a [routerLink]="['/articles/create']">Create Article</a></li>
 </ul>
</div>

<div *ngIf="!user">
  <a [routerLink]="['/authentication/signup']">Signup</a>
  <a [routerLink]="['/authentication/signin']">Signin</a>
</div>

```

这个改变将只在用户登录时向用户显示到新的 `Articles` 组件路由的链接，并在用户未登录时隐藏它。就是这样！一切都准备就绪，可以测试你的新的 CRUD 模块了。使用命令行工具导航到 MEAN 应用程序的根文件夹，然后运行你的应用程序：

```js
$ npm start

```

当你的应用程序运行时，使用浏览器导航到 `http://localhost:3000`。你会看到注册和登录链接；尝试登录并观察主页视图的变化。然后，尝试导航到 `http://localhost:3000/articles` URL，并查看 `list` 组件如何建议你创建一个新文章。继续创建一个新文章，并尝试使用之前创建的组件编辑和删除它。你的 CRUD 模块应该是完全可操作的。

# 总结

在本章中，您学习了如何构建您的第一个 CRUD 模块。您首先定义了 Mongoose 模型和 Express 控制器，并学习了如何实现每个 CRUD 方法。您还使用 Express 中间件对控制器方法进行了授权。然后，您为模块方法定义了一个 RESTful API。您还学习了一些关于响应式编程和观察者模式的知识。您使用 HTTP 客户端与您的 API 进行通信。然后，您创建了您的 Angular 组件并实现了 Angular CRUD 功能。在连接 MEAN 应用程序的四个部分并创建您的第一个 CRUD 模块之后，在下一章中，您将使用 Socket.io 来实现服务器和客户端应用程序之间的实时连接。
