# Angular 学习手册第二版（二）

> 原文：[`zh.annas-archive.org/md5/6C06861E49CB1AD699C8CFF7BAC7E048`](https://zh.annas-archive.org/md5/6C06861E49CB1AD699C8CFF7BAC7E048)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：在我们的组件中实现属性和事件

到目前为止，我们有机会俯瞰新的 Angular 生态系统中组件的概述，它们的角色是什么，它们的行为如何，以及开始构建我们自己的组件来表示小部件和功能块所需的工具是什么。此外，TypeScript 证明是这项努力的完美伴侣，因此我们似乎拥有了进一步探索 Angular 为创建公开属性和发出事件所带来的可能性的一切所需的一切。

在本章中，我们将：

+   发现我们可以使用的所有语法可能性来绑定内容

我们的模板

+   为我们的组件创建公共 API，以便我们可以从它们的属性和事件处理程序中受益

+   看看如何在 Angular 中实现数据绑定

+   通过视图封装来减少 CSS 管理的复杂性

# 更好的模板语法

在第一章 *在 Angular 中创建我们的第一个组件*中，我们看到了如何在我们的组件中嵌入 HTML 模板，但我们甚至没有触及 Angular 模板开发的表面。正如我们将在本书中看到的，模板实现与 Shadow DOM 设计原则紧密耦合，并且它为我们在视图中以声明方式绑定属性和事件带来了大量的语法糖，以简化任务。

简而言之，Angular 组件可以公开一个公共 API，允许它们与其他组件或容器进行通信。这个 API 可能包括输入属性，我们用它来向组件提供数据。它还可以公开输出属性，我们可以将事件监听器绑定到它，从而及时获取有关组件状态变化的信息。

让我们看看 Angular 是如何通过快速简单的示例来解决将数据注入和注出我们的组件的问题的。请关注这些属性背后的哲学。我们将有机会在稍后看到它们的实际应用。

# 使用输入属性进行数据绑定

让我们重新审视定时器组件的功能，这是我们在第一章中已经看到的

*在 Angular 中创建我们的第一个组件*，让我们假设我们希望我们的组件具有可配置的属性，以便我们可以增加或减少倒计时时间：

```ts
<timer [seconds]="25"></timer>
```

请注意大括号之间的属性。这告诉 Angular 这是一个输入属性。模拟`timer`组件的类将包含一个`seconds`属性的 setter 函数，该函数将根据该值的变化来更新自己的倒计时持续时间。我们可以注入一个数据变量或一个实际的硬编码值，如果这样的值是文本字符串，则必须在双引号内用单引号括起来。

有时我们会看到这种语法，用于将数据注入到组件的自定义属性中，而在其他时候，我们将使用这种括号语法使原生 HTML 属性对组件字段具有响应性，就像这样：

```ts
<h1 [hidden]="hideMe">
 This text will not be visible if 'hideMe' is true
</h1>
```

# 在绑定表达式时的一些额外语法糖

Angular 团队已经为我们的组件指令和 DOM 元素提供了一些快捷方式，用于执行常见的转换，比如调整属性和类名或应用样式。在这里，我们有一些在属性中声明性地定义绑定时的时间节省示例：

```ts
<div [attr.hidden]="isHidden">...</div>
<input [class.is-valid]="isValid">
<div [style.width.px]="myWidth"></div>
```

在第一种情况下，如果`isHidden`表达式评估为`true`，`div`将启用隐藏属性。除了布尔值之外，我们还可以绑定任何其他数据类型，比如字符串值。在第二种情况下，如果`isValid`表达式评估为`true`，`is-valid`类名将被注入到 class 属性中。在我们的第三个例子中，`div`将具有一个样式属性，显示出一个以像素为单位设置的`width`属性的值，该值由`myWidth`表达式设置。您可以在 Angular 速查表（[`angular.io/guide/cheatsheet`](https://angular.io/cheatsheet)）中找到更多这种语法糖的例子，该速查表可在官方 Angular 网站上找到。

# 使用输出属性进行事件绑定

假设我们希望我们的计时器组件在倒计时结束时通知我们，以便我们可以执行组件范围之外的其他操作。我们可以通过输出属性实现这样的功能：

```ts
<timer (countdownComplete)="onCountdownCompleted()"></timer>
```

注意大括号之间的属性。这告诉 Angular，这样的属性实际上是一个输出属性，将触发我们绑定到它的事件处理程序。在这种情况下，我们将希望在包装此组件的容器对象上创建一个`onCountownCompleted`事件处理程序。

顺便说一句，驼峰命名不是巧合。这是 Angular 中应用于所有输出和输入属性名称的命名约定。

我们将找到与我们已知的交互事件映射的输出属性，例如`click`，`mouseover`，`mouseout`，`focus`等等：

```ts
<button (click)="doSomething()">click me</button>
```

# 输入和输出属性的作用

掌握前面章节中详细介绍的概念的最佳方法是实践。在第一章中，我们学习了如何使用 Webpack 或 Angular-CLI 从头开始构建应用程序。由于 Angular-CLI 被认为是设置项目的标准方式，让我们只使用它，并通过输入以下内容来创建一个新项目：

```ts
ng new InputOutputDemo
```

此时，我们有一个完全可用的项目，可以通过输入`ng serve`轻松启动。

让我们快速回顾一下 Angular 项目的结构，这样我们就知道如何处理我们即将创建的所有新构造。以下文件特别值得关注：

+   `main.ts`：这个文件引导我们的应用程序。

+   `app/app.module.ts`：这个文件声明了我们的根模块，任何新的构造都必须添加到这个模块的 declarations 属性中，或者您需要为这些未来的构造添加一个专门的模块。通常建议为我们的新构造拥有一个专门的模块。

在前面的项目列表中，我们提到了*根模块*的概念。我们提到这个概念是为了提醒自己关于 Angular 模块的一般情况。Angular 模块包含一堆彼此相关的构造。您可以通过使用`@NgModule`装饰器来识别 Angular 模块；模块本身只是一个普通的类。`@NgModule`装饰器以对象字面量作为输入，并且在这个对象字面量中注册属于模块的一切。

如前面的项目列表中所述，为我们的新构造添加一个专门的模块被认为是一个良好的做法，所以让我们这样做：

```ts
@NgModule({
 declarations: []
})
export class InputModule {}
```

此时，我们将`declarations`属性数组留空。一旦声明了我们的组件，我们将把它添加到该数组中。

这个模块目前还不属于应用程序，但它需要在根模块中注册。打开`app.module.ts`文件，并将新创建的模块添加到`import`数组中，就像这样：

```ts
@NgModule({
 declarations: [AppComponent],
 imports: [ BrowserModule,
      InputModule
 ],
 providers: [], bootstrap: [AppComponent] })
export  class  AppModule { }
```

让我们剥离我们在第一章中看到的定时器示例，*在 Angular 中创建我们的第一个组件*，并讨论一个更简单的例子。让我们看一下`TimerComponent`文件，并用以下组件类替换其内容：

```ts
import { Component } from '@angular/core';

@Component({
 selector : 'countdown-timer',
 template : '<h1>Time left: {{seconds}}</h1>'
})
export class CountdownTimerComponent {
 seconds: number = 25;
 intervalId: any;

 constructor() {
 this.intervalId = setInterval(() => this.tick(), 1000);
 }

 private tick(): void {
 if(--this.seconds < 1) {
 clearInterval(this.intervalId);
 }
 }
} 
```

太棒了！我们刚刚定义了一个简单但非常有效的倒计时组件，它将从 25 秒倒数到 0（你看到上面的`seconds`字段了吗？TypeScript 支持在声明时初始化成员）。一个简单的`setInterval()`循环执行一个名为`tick()`的自定义私有函数，它减少秒数的值直到达到零，此时我们只需清除间隔。

然而，现在我们只需要在某个地方嵌入这个组件，所以让我们创建另一个组件，除了作为前一个组件的 HTML 包装主机之外，没有其他功能。在同一个文件中，在`CountdownTimerComponent`类之后创建这个新组件：

```ts
@Component({
 selector: 'timer',
 template: '<countdown-timer></countdown-timer>'
})
export class TimerComponent {}
```

按照之前的承诺，我们还将把我们新创建的组件添加到它所属的模块的`declarations`数组中，就像这样：

```ts
@NgModule({
 declarations: [CountdownTimerComponent, TimerComponent]
})
export class InputModule {}
```

首先这样做的原因是确保这些组件可以相互使用，就像`CountdownTimerComponent`在`TimerComponent`的模板中使用的情况一样。

在 Angular 中，组件基本上是带有视图模板的指令。我们还可以找到没有视图的指令，它们基本上为宿主元素添加新功能，或者它们只是作为不带 UI 的自定义元素包装其他元素。或者，它们通过 API 为其他组件提供更多功能。

我们将在下一章和整本书中详细探讨指令。你一定想知道为什么我们创建了这个没有实现的主机或父`TimerComponent`组件。很快，我们将为它增加一些更多的功能，但现在让我们将其用作初始化组件树的概念验证。

# 声明式设置自定义值

你可能会同意，设置自定义倒计时器的功能会很好，对吧？输入属性证明是实现这一点的一个很好的方式。为了利用这个功能，我们将不得不调整文件顶部的`import`语句。

```ts
import { Component, Input } from '@angular/core';

@Component({
 selector: 'countdown-timer',
 template: '<h1>Time left: {{ seconds }}</h1>'
})
export class CountdownTimerComponent {
  @Input() seconds : number;
 intervalId;
 // rest of the implementation remains the same
}
```

你可能已经注意到，我们不再初始化`seconds`字段了，现在它被一个属性装饰器修饰（就像我们在第三章中看到的那样，*介绍 TypeScript*）。我们刚刚开始定义我们组件的 API。

属性命名区分大小写。Angular 强制执行的约定是对组件输入和输出属性都应用驼峰命名法，正如我们很快将看到的那样。

接下来，我们只需要在容器组件的模板中添加所需的属性：

```ts
@Component({
 selector: 'timer',
 template: `
 <div class="container text-center">
 <countdown-timer [seconds]="25"></countdown-timer>
 </div>`
})
```

请注意，我们根本没有更新`TimerComponent`。我们只更新了它的`CountdownComponent`子组件。然而，它全新的 API 可以在任何最终将其包含在自己模板中作为子组件的组件中使用，因此我们可以从模板中声明性地设置其属性，或者甚至可以从`TimerComponent`控制器类中的属性中以命令方式绑定值。

当使用`@Input()`标记类属性时，我们可以配置在 HTML 中实例化组件时希望该属性具有的名称。为此，我们只需要在装饰器签名中引入我们选择的名称，就像这样：`@Input('name_of_the_property')`。无论如何，这种做法是不鼓励的，因为在组件 API 中公开与其控制器类中定义的属性名称不同的属性名称只会导致混淆。

# 通过自定义事件在组件之间进行通信

现在我们的子组件正在被其父组件配置，如何

我们可以实现从子组件到父组件的通信吗？这就是自定义事件发挥作用的地方！为了创建适当的事件绑定，我们只需要在组件中配置一个输出属性，并将事件处理程序函数附加到它上面。

为了触发自定义事件，我们需要引入`EventEmitter`，以及`@Output`装饰器，其功能与我们学到的关于`@Input`装饰器完全相反：

```ts
import { Component, Input, Output, EventEmitter } from '@angular/core';
```

`EventEmitter`是 Angular 的内置事件总线。简而言之，`EventEmitter`类支持发出`Observable`数据并订阅`Observer`消费者对数据更改。它的简单接口基本上包括两种方法，`emit()`和`subscribe()`，因此可以用于触发自定义事件以及同步和异步地监听事件。我们将在第七章中更详细地讨论 Observables，*使用 Angular 进行异步数据服务*。目前，我们可以通过`EventEmitter`API 来生成事件，组件中托管我们发出事件的组件可以观察并附加事件处理程序。这些事件通过使用`@Input()`装饰器注释的任何属性在组件范围之外获得可见性。

以下代码显示了一个实际的实现，从前面的例子中跟进：

```ts
@Component({
 selector : 'countdown-timer',
 template : '<h1>Time left: {{ seconds }}</h1>'
})
export class CountdownTimerComponent {
 @Input() seconds : number;
 intervalId: any;
  @Output() complete: EventEmitter<any> = new EventEmitter();
 constructor() {
 this.intervalId = setInterval( () => this.tick(), 1000 );
 }

 private tick(): void {
 if(--this.seconds < 1) {
 clearTimeout(this.intervalId);
 // an event is emitted upon finishing the countdown
      this.complete.emit(null);
 }
 }
}
```

一个名为`complete`的新属性被方便地注释为`EventEmitter`类型，并立即初始化。稍后，我们将访问它的`emit`方法，以便在倒计时结束时生成一个自定义事件。`emit()`方法需要一个任意类型的必需参数，因此我们可以向事件订阅者发送数据值（如果不需要，则为 null）。

现在，我们只需要设置我们的宿主组件，以便它将监听此完成事件或输出属性，并订阅一个事件处理程序：

```ts
@Component({
 selector : 'timer',
 template : `
 <div class="container text-center">
 <img src="assets/img/timer.png" />
 <countdown-timer [seconds]="25"
                 (complete)="onCountdownCompleted()">
 </countdown-timer>`
})
export class TimerComponent {
 onCountdownCompleted(): void {
 alert('Time up !')
 }
}
```

为什么是`complete`而不是`onComplete`？Angular 支持另一种语法形式，称为规范形式，用于输入和输出属性。在输入属性的情况下，一个属性表示为`[seconds]`可以表示为`bind-seconds`，无需使用括号。关于输出属性，这些可以表示为`on-complete`而不是`(complete)`。这就是为什么我们从不在输出属性名称前加上`on`前缀，因为这将出现在输出属性上，比如`on-complete`，如果我们最终决定在我们的项目中更喜欢规范语法形式。

我们已经学会了如何使用组件的输入数据。数据将驻留在容器中，组件将在容器模板内呈现。这意味着组件可以通过我们输入的方式突然访问容器的数据：

```ts
<component [property]="propertyOnContainer">
```

在组件方面，代码如下所示：

```ts
@Component({
 selector : 'component'
})
export class Component {
  @Input() property;
}
```

我们还学习了输出，也就是如何从组件向容器进行通信。为了实现这一点，我们在组件上添加了另一个属性，如下所示：

```ts
<component (event)="methodOnContainer()" [property]="propertyOnContainer">
```

在组件方面，我们将使用一个名为`Output`的装饰器，如下所示：

```ts
@Component({
 selector : 'component'
})
export class Component {
  @Output() event = new EventEmitter<any>();
}
```

并积极调用绑定的方法，我们会输入：

```ts
event.emit();
```

接下来要学习的是如何从组件传递数据到容器。

# 通过自定义事件发出数据

既然我们知道如何从组件 API 发出自定义事件，为什么不再进一步，将数据信号发送到组件范围之外呢？我们已经讨论过`EventEmitter<T>`类的`emit()`事件在其签名中接受由`T`注释表示的任何给定数据。让我们扩展我们的示例以通知倒计时的进度。为什么我们要这样做呢？基本上，我们的组件在屏幕上显示一个可视倒计时，但我们可能希望以编程方式观察倒计时的进度，以便在倒计时结束或达到某一点时采取行动。

让我们用另一个输出属性更新我们的计时器组件，与之匹配

原始的并在每次迭代`seconds`属性时发出自定义事件，

如下所示：

```ts
class CountdownTimerComponent {
 @Input() seconds: number;
  @Output() complete: EventEmitter<any> = new EventEmitter();
 @Output() progress: EventEmitter<number> = new EventEmitter();
 intervalId;

 constructor() {
 this.intervalId = setInterval(() => this.tick(), 1000);
 }

 private tick(): void {
 if(--this.seconds < 1) {
 clearTimeout(this.intervalId);
      this.complete.emit(null);
 }
    this.progress.emit(this.seconds);
 }
}
```

现在，让我们重建主机组件的模板，以反映倒计时的实际进度。我们已经通过显示倒计时来做到这一点，但这是由`CountdownTimerComponent`在内部处理的功能。现在，我们将在该组件之外跟踪倒计时：

```ts
@Component({
 selector: 'timer',
 template: `
 <div class="container text-center">
 <countdown-timer [seconds]="25"
                 (progress)="timeout = $event"
                 (complete)="onCountdownCompleted()" >
 </countdown-timer>
 <p *ngIf="timeout < 10">
 Beware! Only
 <strong>{{ timeout }} seconds</strong>
 </p>
 </div>` 
})
export class TimerComponent {
 timeout: number;
 onCountdownCompleted(): void {
 alert('Time up')
 }
}
```

我们利用这一轮更改来将超时值正式化为主机组件的属性。这使我们能够在我们的自定义事件处理程序中将新值绑定到该属性，就像我们在前面的示例中所做的那样。我们不是将事件处理程序方法绑定到(`progress`)处理程序，而是引用`$event`保留变量。它是指向`progress output`属性的有效负载的指针，反映了我们在执行`this.progress.emit(this.seconds)`时传递给`emit()`函数的值。简而言之，`$event`是`CountdownTimerComponent`内`this.seconds`所假定的值。通过将这样的值分配给模板中的`timeout`类属性，我们还更新了模板中插入的段落中表达的绑定。当`timeout`小于`10`时，此段落将变为可见。

```ts
<countdown-timer [seconds]="25"
           (progress)="timeout = $event"
           (complete)="onCountdownCompleted()">
</countdown-timer>
```

在本节中，我们看到了如何从组件发送数据到容器。基本上有两种方法：

+   将`$event`分配给容器属性

+   使用`$event`作为函数参数调用容器方法

第一个版本就是我们所演示的：

```ts
<countdown [seconds]="25" (progress)="timeout = $event" >
</countdown>
```

组件调用它如下：

```ts
progress.emit(data);
```

第二个版本是对前面示例的小改写：

```ts
<countdown [seconds]="25" (progress)="onProgress($event)">
</countdown>
```

我们会以与组件相同的方式调用它，但不同之处在于我们需要声明一个容器方法`onProgress`，这样`timeout`属性就会以这种方式设置：

```ts
onProgress(data) {
 this.timeout = data;
}
```

# 模板中的本地引用

我们之前已经看到了如何使用双大括号语法通过数据插值将数据绑定到我们的模板。除此之外，我们经常会在属于我们组件或甚至常规 HTML 控件的元素中看到以井号（`#`）为前缀的命名标识符。这些引用标识符，即本地名称，用于在我们的模板视图中引用标记为它们的组件，然后以编程方式访问它们。它们也可以被组件用来引用虚拟 DOM 中的其他元素并访问其属性。

在前一节中，我们看到了如何通过`progress`事件订阅倒计时的进度。但是，如果我们能深入检查组件，或者至少是它的公共属性和方法，并在不必监听`progress`事件的情况下读取`seconds`属性在每个滴答间隔中的值，那该多好啊？好吧，给组件本身设置一个本地引用将打开其公共外观的大门。

让我们在`TimerComponent`模板中标记我们的`CountdownTimerComponent`实例，使用一个名为`#counter`的本地引用。从那一刻起，我们将能够直接访问组件的公共属性，比如`seconds`，甚至在模板的其他位置绑定它。这样，我们甚至不需要依赖`progress`事件发射器或`timeout`类字段，甚至可以操纵这些属性的值。这在下面的代码中显示：

```ts
@Component({
 selector: 'timer',
 template: `
 <div class="container text-center">
 <countdown-timer [seconds]="25"
 (complete)="onCountdownCompleted()"
                 #counter >
 </countdown-timer>
 <p>
 <button class="btn btn-default"
 (click)="counter.seconds = 25">
 reset
 </button>
 </p>
 <p *ngIf="counter.seconds < 10">
 Beware, only !
 <strong>{{ counter.seconds }} seconds</strong>
 </p>
 </div>`
})
export class TimerComponent {
 // timeout: any /* No longer required */
 onCountdownCompleted(): void {
 alert('Time up'); 
 }
}
```

# 输入和输出属性的替代语法

除了`@Input()`和`@Output()`装饰器之外，还有一种替代语法，我们可以通过`@Component`装饰器来定义组件的`input`和`output`属性。它的元数据实现通过`inputs`和`outputs`属性名称分别提供对这两个功能的支持。

因此，`CountdownTimerComponent`的 API 可以这样实现：

```ts
@Component({
 selector : 'countdown-timer',
 template : '<h1>Time left: {{seconds}}</h1>',
  inputs : ['seconds'],
  outputs : ['complete','progress']
})
export class CountdownTimerComponent {
  seconds: number;
 intervalId;
  complete: EventEmitter<any> = new EventEmitter();
 progress: EventEmitter<any> = new EventEmitter();
 // And so on..
}
```

总的来说，这种语法是不鼓励的，仅出于参考目的而包含在这里。首先，我们通过在两个地方定义 API 端点的名称来重复代码，增加了重构代码时出错的风险。另外，通常惯例是尽量保持装饰器的实现尽可能简洁，以提高可读性。

我强烈建议您坚持使用`@Input`和`@Output`装饰器。

# 从组件类配置我们的模板

组件元数据还支持一些设置，有助于简化模板管理和配置。另一方面，Angular 利用了 Web 组件的 CSS 封装功能。

# 内部和外部模板

随着应用程序的规模和复杂性的增长，我们的模板也可能会增长，承载其他组件和更大的 HTML 代码块。将所有这些代码嵌入到我们的组件类定义中将变得繁琐和不愉快，而且也很容易出错。为了防止这种情况发生，我们可以利用`templateUrl`属性，指向一个包含我们组件 HTML 标记的独立 HTML 文件。

回到我们之前的例子，我们可以重构`TimerComponent`类的`@Component`装饰器，指向一个包含我们模板的外部 HTML 文件。在我们的`timer.component.ts`文件所在的工作区中创建一个名为`timer.component.html`的新文件，并用我们在`TimerComponent`类中配置的相同 HTML 填充它：

```ts
<div class="container text-center">
 <countdown [seconds]="25"
 (complete)="onCountdownCompleted()"
 #counter >
 </countdown>
 <p>
 <button class="btn btn-default"
 (click)="counter.seconds = 25">
 Reset countdown to 25 seconds
 </button>
 </p>
 <p *ngIf="counter.seconds < 10">
 Beware only !
 <strong>{{ seconds }} seconds</strong> left
 </p>
</div>
```

现在，我们可以修改`@Component`装饰器，指向该文件，而不是在装饰器元数据中定义 HTML：

```ts
@Component({
 selector: 'timer',
 templateUrl: './timer.component.html'
})
export class TimerComponent {
 // Class follows below
}
```

外部模板遵循 Angular 中的某种约定，由最流行的 Angular 编码风格指南强制执行，即与它们所属的组件共享相同的文件名，包括我们可能附加到组件文件名的任何前缀或后缀。在第六章中探索组件命名约定时，我们将看到这一点，*使用 Angular 组件构建应用程序*。这样，更容易识别，甚至可以使用 IDE 的内置模糊查找工具搜索，哪个 HTML 文件实际上是特定组件的模板。

在哪种情况下创建独立模板而不是将模板标记保留在组件内？这取决于模板的复杂性和大小。在这种情况下，常识将是您最好的顾问。

# 封装 CSS 样式

为了更好地封装我们的代码并使其更具重用性，我们可以在组件内定义 CSS 样式。这些内部样式表是使我们的组件更具共享性和可维护性的好方法。有三种不同的方法来定义我们组件的 CSS 样式。

# styles 属性

我们可以通过组件装饰器中的`styles`属性为我们的 HTML 元素和类名定义样式，如下所示：

```ts
@Component({
 selector : 'my-component',
 styles : [`
 p {
 text-align: center;
 }
 table {
 margin: auto;
 }
 `]
})
export class ExampleComponent {}
```

此属性将接受一个字符串数组，每个字符串包含 CSS 规则，并在我们启动应用程序时将这些规则嵌入到文档的头部以应用于模板标记。我们可以将样式规则内联为一行，也可以利用 ES2015 模板字符串来缩进代码并使其更可读，就像前面的示例中所示。

# styleUrls 属性

就像`styles`一样，`styleUrls`也会接受一个字符串数组，尽管每个字符串都代表一个外部样式表的链接。这个属性也可以与`styles`属性一起使用，根据需要定义不同的规则集：

```ts
@Component({
 selector: 'my-component',
 styleUrls: ['path/to/my-stylesheet.css'], // use this
 styles : [
 `
 p { text-align : center; }
 table { margin: auto; }
 `
 ]  // and this at the same time
})
export class MyComponent {}
```

# 内联样式表

我们还可以将样式规则附加到模板本身，无论是内联模板还是通过`templateUrl`参数提供的模板：

```ts
@Component({
 selector: 'app',
 template: `
 <style> p { color : red; } </style>
 <p>I am a red paragraph </p>
 `
})
export class AppComponent {}
```

# 管理视图封装

所有前面的部分（`styles`，`styleUrls`和内联样式表）都将受到 CSS 特异性的通常规则的约束（[`developer.mozilla.org/en/docs/Web/CSS/Specificity`](https://developer.mozilla.org/en/docs/Web/CSS/Specificity)）。在支持 Shadow DOM 的浏览器上，由于作用域样式，CSS 管理和特异性变得轻而易举。CSS 样式适用于组件中包含的元素，但不会超出其边界。

此外，Angular 将嵌入这些样式表到文档的头部，因此它们可能会影响我们应用程序的其他元素。为了防止这种情况发生，我们可以设置不同级别的视图封装。

简而言之，封装是 Angular 需要在组件内管理 CSS 作用域的方式，适用于支持阴影 DOM 的浏览器和不支持它的浏览器。为此，我们利用`ViewEncapsulation enum`，它可以采用以下任何值：

+   模拟：这是默认选项，基本上是通过在特定选择器下沙盒化 CSS 规则来模拟阴影 DOM 中的本地作用域。推荐使用此选项，以确保我们的组件样式不会受到站点上其他现有库的影响。

+   本地：使用渲染器的本地阴影 DOM 封装机制，仅适用于支持阴影 DOM 的浏览器。

+   无：不提供模板或样式封装。样式将按原样注入到文档的头部。

让我们看一个实际的例子。首先，将`ViewEncapsulation enum`导入脚本，然后创建一个模拟值的封装属性。然后，让我们为倒计时文本创建一个样式规则，以便任何`<h1> (!)`标签都呈现为深红色：

```ts
import {
 Component,
 EventEmitter, 
 Input,
 Output, 
 ViewEncapsulation
} from '@angular/core';
@Component({
 selector: 'countdown-timer',
 template: '<h1>Time left: {{seconds}}</h1>',
 styles: ['h1 { color: #900}'],
 encapsulation: ViewEncapsulation.Emulated 
})
export class CountdownTimerCoponent { 
 // Etc
}
```

现在，点击浏览器的开发工具检查器，并检查生成的 HTML，以发现 Angular 如何将 CSS 注入到页面的`<head>`块中。刚刚注入的样式表已经被沙盒化，以确保我们在组件设置中以非常不具体的方式定义的全局 CSS 规则仅适用于由`CountdownTimerComponent`组件专门作用域的匹配元素。

我们建议您尝试不同的值，并查看 CSS 代码如何注入到文档中。您将立即注意到每种变化提供的隔离等级不同。

# 总结

本章引导我们了解了 Angular 中为组件创建强大 API 的选项，这样我们就可以在组件之间提供高水平的互操作性，通过分配静态值或管理绑定来配置其属性。我们还看到了一个组件如何可以作为另一个子组件的宿主组件，实例化前者的自定义元素在其自己的模板中，为我们的应用程序中更大的组件树奠定了基础。输出参数为我们提供了所需的交互层，通过将我们的组件转换为事件发射器，使它们可以以一种不可知的方式与任何可能最终托管它们的父组件进行通信。模板引用为我们的自定义元素创建了引用的途径，我们可以以声明性的方式从模板内部使用它们的属性和方法。我们还讨论了如何将组件的 HTML 模板隔离在外部文件中，以便于将来的维护，以及如何对我们想要绑定到组件的任何样式表执行相同的操作，以防我们不想将组件样式内联绑定。对 Angular 中处理视图封装的内置功能的概述为我们提供了一些额外的见解，让我们了解了如何可以从每个组件的角度受益于 Shadow DOM 的 CSS 封装，以及在不支持时如何进行 polyfill。

在 Angular 中，我们仍然有很多关于模板管理的东西要学习，主要是关于你在使用 Angular 过程中会广泛使用的两个概念。我指的是指令和管道，在第五章中我们将对其进行详细介绍，《使用管道和指令增强我们的组件》。


# 第五章：通过管道和指令增强我们的组件

在之前的章节中，我们构建了几个组件，借助输入和输出属性在屏幕上呈现数据。我们将利用本章的知识，通过使用指令和管道，将我们的组件提升到一个新的水平。简而言之，管道为我们提供了在模板中绑定的信息进行解析和转换的机会，而指令允许我们进行更有野心的功能，我们可以访问宿主元素的属性，并绑定我们自己的自定义事件监听器和数据绑定。

在本章中，我们将：

+   全面了解 Angular 的内置指令

+   探讨如何使用管道来优化我们的数据输出

+   看看如何设计和构建我们自己的自定义管道和指令

+   利用内置对象来操作我们的模板

+   将所有前述主题和更多内容付诸实践，以构建一个完全交互式的待办事项表

# Angular 中的指令

Angular 将指令定义为没有视图的组件。事实上，组件是具有关联模板视图的指令。之所以使用这种区别，是因为指令是 Angular 核心的一个重要部分，每个指令（普通指令和组件指令）都需要另一个存在。指令基本上可以影响 HTML 元素或自定义元素的行为和显示其内容。

# 核心指令

让我们仔细研究一下框架的核心指令，然后您将在本章后面学习如何构建自己的指令。

# NgIf

正如官方文档所述，`ngIf`指令根据表达式删除或重新创建 DOM 树的一部分。如果分配给`ngIf`指令的表达式求值为`false`，则该元素将从 DOM 中移除。否则，元素的克隆将重新插入 DOM 中。我们可以通过利用这个指令来增强我们的倒计时器，就像这样：

```ts
<timer> [seconds]="timeout"></timer>
<p *ngIf="timeout === 0">Time up!</p>
```

当我们的计时器达到 0 时，将在屏幕上呈现显示“时间到！”文本的段落。您可能已经注意到了在指令前面加上的星号。这是因为 Angular 将标有`ngIf`指令的 HTML 控件（以及其所有 HTML 子树，如果有的话）嵌入到`<ng-template>`标记中，稍后将用于在屏幕上呈现内容。涵盖 Angular 如何处理模板显然超出了本书的范围，但让我们指出，这是 Angular 提供的一种语法糖，作为其他更冗长的基于模板标记的语法的快捷方式。

也许您想知道使用`*ngIf="conditional"`在屏幕上呈现一些 HTML 片段与使用`[hidden]="conditional"`有什么区别。前者将克隆并注入模板化的 HTML 片段到标记中，在条件评估为`false`时从 DOM 中删除它，而后者不会从 DOM 中注入或删除任何标记。它只是设置带有该 DOM 属性的已存在的 HTML 片段的可见性。

# NgFor

`ngFor`指令允许我们遍历集合（或任何其他可迭代对象），并将其每个项目绑定到我们选择的模板，我们可以在其中定义方便的占位符来插入项目数据。每个实例化的模板都作用域限定在外部上下文中，我们可以访问其他绑定。假设我们有一个名为`Staff`的组件：它具有一个名为 employees 的字段，表示一个`Employee`对象数组。我们可以这样列出这些员工和职位：

```ts
<ul>
 <li *ngFor="let employee of employees">
 Employee {{ employee.name }}, {{ employee.position }}
 </li>
</ul>
```

正如我们在提供的示例中看到的，我们将从每次循环中获取的可迭代对象中的每个项目转换为本地引用，以便我们可以轻松地在我们的模板中绑定这个项目。需要强调的是，表达式以关键字`let`开头。

该指令观察底层可迭代对象的更改，并将根据项目在集合中添加、删除或重新排序而添加、删除或排序呈现的模板。

# 高级循环

除了只循环列表中的所有项目之外，还可以跟踪其他可用属性。每个属性都可以通过在声明项目后添加另一个语句来使用：

```ts
<div *ngFor="let items of items; let property = property">{{ item }}</div>
```

**First/last**，这是一个布尔值，用于跟踪我们是否在循环中的第一个或最后一个项目上，如果我们想要以不同的方式呈现该项目。可以通过以下方式访问它：

```ts
<div *ngFor="let item of items; let first = first">
 <span [ngClass]="{ 'first-css-class': first, 'item-css-class' : !first }">
 {{ item }}
 </span>
</div>
```

**Index**，是一个数字，告诉我们我们在哪个索引上；它从 0 开始。

**Even/odd**是一个布尔值，指示我们是否在偶数或奇数索引上。

**TrackBy**，要解释`trackBy`做什么，让我们首先谈谈它试图解决的问题。问题是，`*ngFor`指向的数据可能会发生变化，元素可能会被添加或删除，甚至整个列表可能会被替换。对于添加/删除元素的天真方法是对所有这些元素在 DOM 树上进行创建/删除。如果使用相同的天真方法来显示新列表而不是我们用来显示这个旧列表，那将是非常昂贵和缓慢的。Angular 通过将 DOM 元素保存在内存中来处理这个问题，因为创建是昂贵的。在内部，Angular 使用称为对象标识的东西来跟踪列表中的每个项目。然而，`trackBy`允许您从对象标识更改为项目上的特定属性。默认的对象标识在大多数情况下都很好，但是如果您开始遇到性能问题，请考虑更改`*ngFor`应查看的项目的属性，如下所示：

```ts
@Component({
 template : `
 <*ngFor="let item of items; trackBy: trackFunction">{{ item }}</div>
 `
})
export class SomeComponent {
 trackFunction(index, item) {
 return item ? item.id : undefined;
 }
}
```

# Else

Else 是 Angular 4.0 的一个新构造，并且是一个简写，可以帮助您处理条件语句。想象一下，如果您有以下内容：

```ts
<div *ngIf="hero">
 {{ hero.name }}
</div>
<div *ngIf="!hero">
 No hero set
</div>
```

我们在这里的用例非常清楚；如果我们设置了一个人，那么显示它的名字，否则显示默认文本。我们可以使用`else`以另一种方式编写这个：

```ts
<div *ngIf="person; else noperson">{{person.name}}</div>
<div #noperson>No person set</div>
```

这里发生的是我们如何定义我们的条件：

```ts
person; else noperson
```

我们说如果`person`已设置，那么继续，如果没有显示模板`noperson`。 `noperson`也可以应用于普通的 HTML 元素以及`ng-template`。

# 应用样式

在您的标记中应用样式有三种方法：

+   插值

+   NgStyle

+   NgClass

# 插值

这个版本是关于使用花括号并让它们解析应该应用什么类/类。您可以编写一个看起来像这样的表达式：

```ts
<div class="item {{ item.selected ? 'selected' : ''}}"
```

这意味着如果您的项目具有选定的属性，则应用 CSS 类 selected，否则应用空字符串，即没有类。虽然在许多情况下这可能足够，但它也有缺点，特别是如果需要应用多个样式，因为有多个需要检查的条件。

插值表达式在性能方面被认为是昂贵的，通常是不鼓励使用的。

# NgStyle

正如你可能已经猜到的那样，这个指令允许我们通过评估自定义对象或表达式来绑定 CSS 样式。我们可以绑定一个对象，其键和值映射 CSS 属性，或者只定义特定属性并将数据绑定到它们：

```ts
<p [ngStyle]="{ 'color': myColor, 'font-weight': myFontWeight }">
 I am red and bold
</p>
```

如果我们的组件定义了`myColor`和`myFontWeight`属性，分别具有`red`和`bold`的值，那么文本的颜色和粗细将相应地改变。该指令将始终反映组件内所做的更改，我们还可以传递一个对象，而不是按属性基础绑定数据：

```ts
<p [ngStyle]="myCssConfig">I am red and bold</p>
```

# NgClass

与`ngStyle`类似，`ngClass`允许我们以一种方便的声明性语法在 DOM 元素中定义和切换类名。然而，这种语法有其自己的复杂性。让我们看看这个例子中可用的三种情况：

```ts
<p [ngClass]="{{myClassNames}}">Hello Angular!</p>
```

例如，我们可以使用字符串类型，这样如果`myClassNames`包含一个由空格分隔的一个或多个类的字符串，所有这些类都将绑定到段落上。

我们也可以使用数组，这样每个元素都会被添加。

最后但同样重要的是，我们可以使用一个对象，其中每个键对应于由布尔值引用的 CSS 类名。标记为`true`的每个键名将成为一个活动类。否则，它将被移除。这通常是处理类名的首选方式。

`ngClass`还有一种替代语法，格式如下：

```ts
[ngClass]="{ 'class' : boolean-condition, 'class2' : boolean-condition-two }"
```

简而言之，这是一个逗号分隔的版本，在条件为`true`时将应用一个类。如果有多个条件为`true`，则可以应用多个类。如果在更现实的场景中使用，它会看起来像这样：

```ts
<span [ngClass] ="{
 'light' : jedi.side === 'Light',
 'dark' : jedi.side === 'Dark'
}">
{{ jedi.name }}
</span>
```

生成的标记可能如下，如果`jedi.side`的值为`light`，则将 CSS 类 light 添加到 span 元素中：

```ts
<span class="light">Luke</span>
```

# NgSwitch、ngSwitchCase 和 ngSwitchDefault

`ngSwitch`指令用于根据显示每个模板所需的条件在特定集合内切换模板。实现遵循几个步骤，因此在本节中解释了三个不同的指令。

`ngSwitch`将评估给定的表达式，然后切换和显示那些带有`ngSwitchCase`属性指令的子元素，其值与父`ngSwitch`元素中定义的表达式抛出的值匹配。需要特别提到带有`ngSwitchDefault`指令属性的子元素。该属性限定了当其`ngSwitchCase`兄弟元素定义的任何其他值都不匹配父条件表达式时将显示的模板。

我们将在一个例子中看到所有这些：

```ts
<div [ngSwitch]="weatherForecaseDay">
 <ng-template ngSwitchCase="today">{{weatherToday}}</ng-template>
 <ng-template ngSwitchCase="tomorrow">{{weatherTomorrow}}</ng-template>
 <ng-template ngSwitchDefault>
 Pick a day to see the weather forecast
 <ng-template>
</div>
```

父`[ngSwitch]`参数评估`weatherForecastDay`上下文变量，每个嵌套的`ngSwitchCase`指令将针对其进行测试。我们可以使用表达式，但我们希望将`ngSwitchCase`包装在括号中，以便 Angular 可以正确地将其内容评估为上下文变量，而不是将其视为文本字符串。

`NgPlural`和`NgPluralCase`的覆盖范围超出了本书的范围，但基本上提供了一种方便的方法来呈现或删除与开关表达式匹配的模板 DOM 块，无论是严格的数字还是字符串，类似于`ngSwitch`和`ngSwitchWhen`指令的方式。

# 使用管道操作模板绑定

因此，我们看到了如何使用指令根据我们的组件类管理的数据来呈现内容，但是还有另一个强大的功能，我们将在日常实践中充分利用 Angular。我们正在谈论管道。

管道允许我们在视图级别过滤和引导我们表达式的结果，以转换或更好地显示我们绑定的数据。它们的语法非常简单，基本上由管道符号分隔的要转换的表达式后面跟着管道名称（因此得名）：

```ts
@Component({
 selector: 'greeting',
 template: 'Hello {{ name | uppercase }}'
})
export class GreetingComponent{ name: string; }
```

在前面的例子中，我们在屏幕上显示了一个大写的问候语。由于我们不知道名字是大写还是小写，所以我们通过在视图级别转换名称的值来确保一致的输出。管道是可链式的，Angular 已经内置了各种管道类型。正如我们将在本章中进一步看到的，我们还可以构建自己的管道，以在内置管道不足以满足需求的情况下对数据输出进行精细调整。

# 大写/小写管道

大写/小写管道的名称就是它的含义。就像之前提供的示例一样，这个管道可以将字符串输出设置为大写或小写。在视图中的任何位置插入以下代码，然后自行检查输出：

```ts
<p>{{ 'hello world' | uppercase}}</p>  // outputs HELLO WORLD
<p>{{ 'wEIrD hElLo' | lowercase}}</p>  // outputs weird hello
```

# 小数、百分比和货币管道

数值数据可以有各种各样的类型，当涉及到更好的格式化和本地化输出时，这个管道特别方便。这些管道使用国际化 API，因此只在 Chrome 和 Opera 浏览器中可靠。

# 小数管道

小数管道将帮助我们使用浏览器中的活动区域设置定义数字的分组和大小。其格式如下：

```ts
number_expression | number[:digitInfo[:locale]]
```

在这里，`number_expression`是一个数字，`digitInfo`的格式如下：

```ts
{minIntegerDigits}.{minFractionDigits}-{maxFractionDigits}
```

每个绑定对应以下内容：

+   `minIntegerDigits`：要使用的整数位数的最小数字。默认为 1。

+   `minFractionDigits`：分数后的最小数字位数。默认为 0。

+   `maxFractionDigits`：分数后的最大数字位数。默认为 3。

请记住，每个数字和其他细节的可接受范围将取决于您的本地国际化实现。让我们尝试通过创建以下组件来解释这是如何工作的：

```ts
import { Component, OnInit } from  '@angular/core'; @Component({ selector:  'pipe-demo', template: ` <div>{{ no  |  number }}</div>   <!-- 3.141 --> <div>{{ no  |  number:'2.1-5' }}</div> <! -- 03.14114 --> <div>{{ no  |  number:'7.1-5' }}</div> <!-- 0,000,003.14114 -->
 <div>{{ no  |  number:'7.1-5':'sv' }}</div> <!-- 0 000 003,14114 -->
 ` }) export  class  PipeDemoComponent { no:  number  =  3.1411434344; constructor() { } }
```

这里有一个四种不同表达式的示例，展示了我们如何操作数字、分数以及区域设置。在第一种情况下，我们除了使用`number`管道之外没有给出任何指令。在第二个示例中，我们指定了要显示的小数位数和数字，通过输入`number: '2.1-5'`。这意味着我们在分数标记的左侧显示两个数字，右侧显示 5 个数字。因为左侧只有 3 个数字，我们需要用零来填充。右侧我们只显示 5 位小数。在第三个示例中，我们指示它显示 7 个数字在分数标记的左侧，右侧显示 5 个数字。这意味着我们需要在左侧填充 6 个零。这也意味着千位分隔符被添加了。我们的第四个示例演示了区域设置功能。我们看到显示的结果是千位分隔符的空格字符，小数点的逗号。

不过有一件事要记住；要使区域设置起作用，我们需要在根模块中安装正确的区域设置。原因是 Angular 只有从一开始就设置了 en-US 区域设置。不过添加更多区域设置非常容易。我们需要将以下代码添加到`app.module.ts`中：

```ts
import { BrowserModule } from  '@angular/platform-browser'; import { NgModule } from  '@angular/core'; import { AppComponent } from  './app.component'; import { PipeDemoComponent } from  "./pipe.demo.component"; 
import { registerLocaleData } from  '@angular/common'; import localeSV from '@angular/common/locales/sv'; 
registerLocaleData(localeSV**);** 
@NgModule({
  declarations: [ AppComponent, PipeDemoComponent ],
 imports: [ BrowserModule
 ],
 providers: [], bootstrap: [AppComponent] })
export  class  AppModule { }
```

# 百分比管道

百分比管道将数字格式化为本地百分比。除此之外，它继承自数字管道，以便我们可以进一步格式化输出，以提供更好的整数和小数大小和分组。它的语法如下：

```ts
number_expression | percent[:digitInfo[:locale]]
```

# 货币管道

这个管道将数字格式化为本地货币，支持选择货币代码，如美元的 USD 或欧元的 EUR，并设置我们希望货币信息显示的方式。它的语法如下：

```ts
number_expression | currency[:currencyCode[:display[:digitInfo[:locale]]]]
```

在前面的语句中，`currencyCode`显然是 ISO 4217 货币代码，而`display`是一个字符串

可以是`code`，假设值为`symbol`或`symbol-narrow`。值`symbol-narrow`指示是否使用货币符号（例如，$）。值`symbol`指示在输出中使用货币代码（例如 USD）。与小数和百分比管道类似，我们可以通过`digitInfo`值格式化输出，还可以根据区域设置格式化。

在下面的示例中，我们演示了所有三种形式：

```ts
import { Component, OnInit } from  '@angular/core'; 
@Component({ selector:  'currency-demo', template: ` <p>{{ 11256.569  |  currency:"SEK":'symbol-narrow':'4.1-2' }}</p> <!--kr11,256.57 --> <p>{{ 11256.569  |  currency:"SEK":'symbol':'4.1-3' }}</p> <!--SEK11,256.569 --> <p>{{ 11256.569  |  currency:"SEK":'code' }}</p> <!--SEK11,256.57 --> `
})
export  class  CurrencyDemoComponent { constructor() { } }  
```

# 切片管道

这个管道的目的相当于`Array.prototype.slice()`和`String.prototype.slice()`在减去集合列表、数组或字符串的子集（切片）时所起的作用。它的语法非常简单，遵循与前述`slice()`方法相同的约定：

```ts
expression | slice: start[:end]
```

基本上，我们配置一个起始索引，我们将从中开始切片项目数组或字符串的可选结束索引，当省略时，它将回退到输入的最后索引。

开始和结束参数都可以取正值和负值，就像 JavaScript 的`slice()`方法一样。请参考 JavaScript API 文档，了解所有可用场景的详细情况。

最后但并非最不重要的是，请注意，在操作集合时，返回的列表始终是副本，即使所有元素都被返回。

# 日期管道

你一定已经猜到了，日期管道根据请求的格式将日期值格式化为字符串。格式化输出的时区将是最终用户机器的本地系统时区。它的语法非常简单：

```ts
date_expression | date[:format[:timezone[:locale]]]
```

表达式输入必须是一个日期对象或一个数字（自 UTC 纪元以来的毫秒数）。格式参数是高度可定制的，并接受基于日期时间符号的各种变化。为了我们的方便，一些别名已经被提供为最常见的日期格式的快捷方式：

+   '中等'：这相当于'yMMMdjms'（例如，对于 en-US，Sep 3, 2010, 12:05:08 PM）

+   '短'：这相当于'yMdjm'（例如，9/3/2010, 12:05 PM

对于 en-US）

+   'fullDate'：这相当于'yMMMMEEEEd'（例如，对于 en-US，Friday, September 3, 2010）

+   '长日期'：这相当于'yMMMMd'（例如，September 3, 2010）

+   '中等日期'：这相当于'yMMMd'（例如，对于 en-US，Sep 3, 2010）

+   '短日期'：这相当于'yMd'（例如，对于 en-US，9/3/2010）

+   '中等时间'：这相当于'jms'（例如，对于 en-US，12:05:08 PM）

+   '短时间'：这相当于'jm'（例如，对于 en-US，12:05 PM）

+   json 管道

# JSON 管道

JSON 可能是定义中最直接的管道；它基本上以对象作为输入，并以 JSON 格式输出它：

```ts
import { Component } from  '@angular/core'; 
@Component({
  selector:  'json-demo', template: ` {{ person | json **}}** 
 **<!--{ "name": "chris", "age": 38, "address": { "street": "Oxford Street", "city": "London" }** } --> `
})
export  class  JsonDemoComponent { person  = { name:  'chris', age:  38, address: { street:  'Oxford Street', city:  'London' }
 }

 constructor() { } }  
```

使用 Json 管道的输出如下：{ "name": "chris", "age": 38, "address": { "street": "Oxford Street", "city": "London" } }。这表明管道已将单引号转换为双引号，从而生成有效的 JSON。那么，我们为什么需要这个？一个原因是调试；这是一个很好的方式来查看复杂对象包含什么，并将其漂亮地打印到屏幕上。正如您从前面的字段'person'中看到的，它包含一些简单的属性，但也包含复杂的'address'属性。对象越深，json 管道就越好。

# i18n 管道

作为 Angular 对提供强大国际化工具集的坚定承诺的一部分，已经提供了一组针对常见 i18n 用例的管道。本书将只涵盖两个主要的管道，但很可能在将来会发布更多的管道。请在完成本章后参考官方文档以获取更多信息。

# i18nPlural 管道

`i18nPlural`管道有一个简单的用法，我们只需评估一个数字值与一个对象映射不同的字符串值，根据评估的结果返回不同的字符串。这样，我们可以根据数字值是零、一、二、大于*N*等不同的情况在我们的模板上呈现不同的字符串。语法如下：

```ts
expression | i18nPlural:mapping[:locale]
```

让我们看看这在你的组件类上的一个数字字段`jedis`上是什么样子的：

```ts
<h1> {{ jedis | i18nPlural:jediWarningMapping }} </h1>
```

然后，我们可以将这个映射作为我们组件控制器类的一个字段：

```ts
export class i18DemoComponent {
 jedis: number = 11;
 jediWarningMapping: any = {
 '=0': 'No jedis',
 '=1' : 'One jedi present',
 'other' : '# jedis in sight'
 }
}
```

我们甚至通过在字符串映射中引入`'#'`占位符来绑定表达式中评估的数字值。当找不到匹配的值时，管道将回退到使用键`'other'`设置的映射。

# i18nSelect 管道

`i18nSelect`管道类似于`i18nPlural`管道，但它评估的是一个字符串值。这个管道非常适合本地化文本插值或根据状态变化提供不同的标签，例如。例如，我们可以回顾一下我们的计时器，并以不同的语言提供 UI：

```ts
<button (click)="togglePause()">
 {{ languageCode | i18nSelect:localizedLabelsMap }}
</button>
```

在我们的控制器类中，我们可以填充`localizedLabelsMap`，如下所示：

```ts
export class TimerComponent {
 languageCode: string ='fr';
 localizedLabelsMap: any = {
 'en' : 'Start timer',
 'es' : 'Comenzar temporizador',
 'fr' : 'Demarrer une sequence',
 'other' : 'Start timer' 
 }
}
```

重要的是要注意，我们可以在除了本地化组件之外的用例中使用这个方便的管道，而是根据映射键和类似的东西提供字符串绑定。与`i18nPlural`管道一样，当找不到匹配的值时，管道将回退到使用`'other'`键设置的映射。

# 异步管道

有时，我们管理可观察数据或仅由组件类异步处理的数据，并且我们需要确保我们的视图及时反映信息的变化，一旦可观察字段发生变化或异步加载在视图渲染后完成。异步管道订阅一个可观察对象或承诺，并返回它发出的最新值。当发出新值时，异步管道标记组件以检查更改。我们将在第七章中返回这个概念，*使用 Angular 进行异步数据服务*。

# 将所有内容放在任务列表中

现在你已经学会了所有的元素，可以让你构建完整的组件，是时候把所有这些新知识付诸实践了。在接下来的页面中，我们将构建一个简单的任务列表管理器。在其中，我们将看到一个包含我们需要构建的待办事项的任务表。

我们还将直接从可用任务的积压队列中排队任务。这将有助于显示完成所有排队任务所需的时间，并查看我们工作议程中定义了多少任务。

# 设置我们的主 HTML 容器

在构建实际组件之前，我们需要先设置好我们的工作环境，为此，我们将重用在上一个组件中使用的相同的 HTML 样板文件。请将您迄今为止所做的工作放在一边，并保留我们在以前的示例中使用的`package.json`、`tsconfig.json`、`typings.json`和`index.html`文件。如果需要的话，随时重新安装所需的模块，并替换我们`index.html`模板中的 body 标签的内容：

```ts
<nav class="navbar navbar-default navbar-static-top">
 <div class="container">
 <div class="navbar-header">
 <strong class="navbar-brand">My Tasks</strong>
 </div>
 </div>
</nav>
<tasks></tasks>
```

简而言之，我们刚刚更新了位于我们新的`<tasks>`自定义元素上方的标题布局的标题，该元素替换了以前的`<timer>`。您可能希望更新`app.module.ts`文件，并确保将任务作为一个可以在我们模块之外可见的组件，输入到`exports`关键数组中：

```ts
@NgModule({
  declarations : [ TasksComponent ],
 imports : [ ],
 providers : [],
  exports : [ TasksComponent ]
})
export class TaskModule{}
```

让我们在这里强调一下，到目前为止，应用程序有两个模块：我们的根模块称为`AppModule`和我们的`TaskModule`。我们的根模块应该像这样导入我们的`TaskModule`：

```ts
@NgModule({
 imports : [
 BrowserModule,
    TaskModule
 ]
})
export class AppModule {}
```

# 使用 Angular 指令构建我们的任务列表表格

创建一个空的 `tasks.ts` 文件。您可能希望使用这个新创建的文件从头开始构建我们的新组件，并在其中嵌入我们将在本章后面看到的所有伴随管道、指令和组件的定义。

现实生活中的项目从未以这种方式实现，因为我们的代码必须符合“一个类，一个文件”的原则，利用 ECMAScript 模块将事物粘合在一起。第六章，*使用 Angular 组件构建应用程序*，将向您介绍构建 Angular 应用程序的一套常见最佳实践，包括组织目录树和不同元素（组件、指令、管道、服务等）的可持续方式。相反，本章将利用`tasks.ts`将所有代码包含在一个中心位置，然后提供我们现在将涵盖的所有主题的鸟瞰视图，而无需在文件之间切换。请记住，这实际上是一种反模式，但出于教学目的，我们将在本章中最后一次采用这种方法。文件中声明元素的顺序很重要。如果出现异常，请参考 GitHub 中的代码存储库。

在继续我们的组件之前，我们需要导入所需的依赖项，规范我们将用于填充表格的数据模型，然后搭建一些数据，这些数据将由一个方便的服务类提供。

让我们首先在我们的`tasks.ts`文件中添加以下代码块，导入我们在本章中将需要的所有标记。特别注意我们从 Angular 库中导入的标记。我们已经介绍了组件和输入，但其余的内容将在本章后面进行解释：

```ts
import { 
 Component,
 Input,
 Pipe,
 PipeTransform,
 Directive,
 OnInit,
 HostListener
 } from '@angular/core';
```

已经导入了依赖标记，让我们在导入的代码块旁边定义我们任务的数据模型：

```ts
/// Model interface
interface Task {
 name: string;
 deadline: Date;
 queued: boolean;
 hoursLeft: number;
}
```

`Task`模型接口的架构非常容易理解。每个任务都有一个名称，一个截止日期，一个字段用于通知需要运送多少单位，以及一个名为`queued`的布尔字段，用于定义该任务是否已被标记为在下一个会话中完成。

您可能会惊讶我们使用接口而不是类来定义模型实体，但当实体模型不需要实现方法或在构造函数或 setter/getter 函数中进行数据转换时，这是完全可以的。当后者不需要时，接口就足够了，因为它以简单且更轻量的方式提供了我们需要的静态类型。

现在，我们需要一些数据和一个服务包装类，以集合`Task`对象的形式提供这样的数据。在这里定义的`TaskService`类将起到作用，因此请在`Task`接口之后立即将其附加到您的代码中：

```ts
/// Local Data Service
class TaskService {
 public taskStore: Array<Task> = [];
 constructor() {
 const tasks = [
 {
 name : 'Code and HTML table',
 deadline : 'Jun 23 2015',
 hoursLeft : 1
 }, 
 {
 name : 'Sketch a wireframe for the new homepage',
 deadline : 'Jun 24 2016',
 hoursLeft : 2
 }, 
 {
 name : 'Style table with bootstrap styles',
 deadline : 'Jun 25 2016',
 hoursLeft : 1
 }
 ];

 this.taskStore = tasks.map( task => {
 return {
 name : task.name,
 deadline : new Date(task.deadline),
 queued : false,
 hoursLeft : task.hoursLeft 
 };
 })
 }
}
```

这个数据存储相当简单明了：它公开了一个`taskStore`属性，返回一个符合`Task`接口的对象数组（因此受益于静态类型），其中包含有关名称、截止日期和时间估计的信息。

现在我们有了一个数据存储和一个模型类，我们可以开始构建一个 Angular 组件，该组件将使用这个数据源来呈现我们模板视图中的任务。在您之前编写的代码之后插入以下组件实现：

```ts
/// Component classes
// - Main Parent Component
@Component({
 selector : 'tasks',
 styleUrls : ['tasks.css'],
 templateUrl : 'tasks.html'
})
export class TaskComponent {
 today: Date;
 tasks: Task[];
 constructor() {
 const TasksService: TaskService = new TasksService();
 this.tasks = tasksService.taskStore;
 this.today = new Date();
 }
}
```

正如您所见，我们通过引导函数定义并实例化了一个名为`TasksComponent`的新组件，选择器为`<tasks>`（我们在填充主`index.html`文件时已经包含了它，记得吗？）。这个类公开了两个属性：今天的日期和一个任务集合，它将在组件视图中的表中呈现，我们很快就会看到。为此，在其构造函数中实例化了我们之前创建的数据源，并将其映射到作为`Task`对象类型的模型数组，由任务字段表示。我们还使用 JavaScript 内置的`Date`对象的实例初始化了 today 属性，其中包含当前日期。

正如您所见，组件选择器与其控制器类命名不匹配。我们将在本章末深入探讨命名约定，作为第六章《使用 Angular 组件构建应用程序》的准备工作。

现在让我们创建样式表文件，其实现将非常简单明了。在我们的组件文件所在的位置创建一个名为`tasks.css`的新文件。然后，您可以使用以下样式规则填充它：

```ts
h3, p {
 text-align : center;
}

table {
 margin: auto;
 max-width: 760px;
}
```

这个新创建的样式表非常简单，以至于它可能看起来有点多余作为一个独立的文件。然而，在我们的示例中，这是展示组件元数据的`styleUrls`属性功能的好机会。

关于我们的 HTML 模板，情况大不相同。这一次，我们也不会在组件中硬编码我们的 HTML 模板，而是将其指向外部 HTML 文件，以更好地管理我们的呈现代码。请在与我们的主要组件控制器类相同的位置创建一个 HTML 文件，并将其保存为`tasks.html`。创建完成后，使用以下 HTML 片段填充它：

```ts
<div class="container text-center">
 <img src="assets/img/task.png" alt="Task" />
 <div class="container">
 <h4>Tasks backlog</h4>
 <table class="table">
 <thead>
 <tr>
 <th> Task ID</th>
 <th>Task name</th>
 <th>Deliver by</th>
 <th></th>
 <th>Actions</th>
 </tr>
 </thead>
 <tbody>
 <tr *ngFor="let task of tasks; let i = index">
 <th scope="row">{{i}}</th>
 <td>{{ task.name | slice:0:35 }}</td>
 <span [hidden]="task.name.length < 35">...</span>
 </td>
 <td>
 {{ task.deadline | date:'fullDate' }}
 <span *ngIf="task.deadline < today" 
 class="label label-danger">
 Due
 </span>
 </td>
 <td class="text-center">
 {{ task.hoursLeft }}
 </td>
 <td>[Future options...]</td>
 </tbody>
 </table>
</div> 

```

基本上，我们正在创建一个基于 Bootstrap 框架的具有整洁样式的表格。然后，我们使用始终方便的`ngFor`指令渲染所有任务，提取并显示我们在本章早些时候概述`ngFor`指令时解释的集合中每个项目的索引。

请看我们如何通过管道格式化任务名称和截止日期的输出，以及如何方便地显示（或不显示）省略号来指示文本是否超过了我们为名称分配的最大字符数，方法是将 HTML 隐藏属性转换为绑定到 Angular 表达式的属性。所有这些呈现逻辑都标有红色标签，指示给定任务是否在截止日期之前到期。

您可能已经注意到，这些操作按钮在我们当前的实现中不存在。我们将在下一节中修复这个问题，在我们的组件中玩转状态。回到第一章，*在 Angular 中创建我们的第一个组件*，我们提到了点击事件处理程序来停止和恢复倒计时，然后在第四章，*在我们的组件中实现属性和事件*中更深入地讨论了这个主题，我们涵盖了输出属性。让我们继续研究，看看我们如何将 DOM 事件处理程序与我们组件的公共方法连接起来，为我们的组件添加丰富的交互层。

# 在我们的任务列表中切换任务

将以下方法添加到您的`TasksComponent`控制器类中。它的功能非常基本；我们只是简单地切换给定`Task`对象实例的 queued 属性的值：

```ts
toggleTask(task: Task): void {
 task.queued = !task.queued;
}
```

现在，我们只需要将其与我们的视图按钮连接起来。更新我们的视图，包括在`ngFor`循环中创建的按钮中的点击属性（用大括号括起来，以便它充当输出属性）。现在，我们的`Task`对象将具有不同的状态，让我们通过一起实现`ngSwitch`结构来反映这一点：

```ts
<table class="table">
 <thead>
 <tr>
 <th>Task ID</th>
 <th>Task name</th>
 <th>Deliver by</th>
 <th>Units to ship</th>
 <th>Actions</th>
 </tr>
 </thead>
 <tbody>
 <tr *ngFor="let task of tasks; let i = index">
 <th scope="row">{{i}}
 <span *ngIf="task.queued" class="label label-info">Queued</span>
 </th>
 <td>{{task.name | slice:0:35}}
 <span [hidden]="task.name.length < 35">...</span>
 </td>
 <td>{{ task.deadline | date:'fullDate'}}
 <span *ngIf="task.deadline < today" class="label label-danger">Due</span>
 </td>
 <td class="text-center">{{task.hoursLeft}}</td>
 <td>
 <button type="button" 
 class="btn btn-default btn-xs"
 (click)="toggleTask(task)"
 [ngSwitch]="task.queued">
 <ng-template ngSwitchCase="false">
 <i class="glyphicon glyphicon-plus-sign"></i>
 Add
 </ng-template>
 <ng-template ngSwitchCase="true">
 <i class="glyphicon glyphicon-minus-sign"></i>
 Remove
 <ng-template>
 <ng-template ngSwitchDefault>
 <i class="glyphicon glyphicon-plus-sign"></i>
 Add
 </ng-template>
 </button>
 </td>
 </tbody>
</table>
```

我们全新的按钮可以在我们的组件类中执行“toggleTask（）”方法，将`Task`对象作为参数传递给`ngFor`迭代对应的对象。另一方面，先前的`ngSwitch`实现允许我们根据`Task`对象在任何给定时间的状态来显示不同的按钮标签和图标。

我们正在用从 Glyphicons 字体系列中获取的字体图标装饰新创建的按钮。这些图标是我们之前安装的 Bootstrap CSS 捆绑包的一部分，与 Angular 无关。请随意跳过使用它或用另一个图标字体系列替换它。

现在执行代码并自行检查结果。整洁，不是吗？但是，也许我们可以通过向任务列表添加更多功能来从 Angular 中获得更多的效果。

# 在我们的模板中显示状态变化

现在我们可以从表中选择要完成的任务，很好地显示出我们需要运送多少个单位的一些视觉提示将是很好的。逻辑如下：

+   用户审查表上的任务，并通过点击每个任务来选择要完成的任务

+   每次点击一行时，底层的`Task`对象状态都会发生变化，并且其布尔排队属性会被切换

+   状态变化立即通过在相关任务项上显示`queued`标签来反映在表面上

+   用户得到了需要运送的单位数量的提示信息和交付所有这些单位的时间估计

+   我们看到在表格上方显示了一排图标，显示了所有要完成的任务中所有单位的总和

这个功能将不得不对我们处理的`Task`对象集的状态变化做出反应。好消息是，由于 Angular 自己的变化检测系统，使组件完全意识到状态变化变得非常容易。

因此，我们的第一个任务将是调整我们的`TasksComponent`类，以包括一种计算和显示排队任务数量的方法。我们将使用这些信息来在我们的组件中渲染或不渲染一块标记，其中我们将通知我们排队了多少任务，以及完成所有任务需要多少累计时间。

我们类的新`queuedTasks`字段将提供这样的信息，我们将希望在我们的类中插入一个名为`updateQueuedTasks()`的新方法，该方法将在实例化组件或排队任务时更新其数值。除此之外，我们将创建一个键/值映射，以便稍后根据排队任务的数量使用`I18nPlural`管道来呈现更具表现力的标题头：

```ts
class TasksComponent {
 today: Date;
 tasks: Task[];
 queuedTasks: number;
 queuedHeaderMapping: any = {
 '=0': 'No tasks',
 '=1': 'One task',
 'other' : '# tasks'
 };

 constructor() {
 const TasksService: TasksService = new TasksService();
 this.tasks = tasksService.tasksStore;
 this.today = new Date();
 this.updateQueuedTasks();
 }

 toggleTask(task: Task) {
 task.queued = !task.queued;
 this.updateQueuedTasks();
 }

 private updateQueuedTasks() {
 this.queuedTasks = this.tasks
 .filter( task:Task => task.queued )
 .reduce((hoursLeft: number, queuedTask: Task) => {
 return hoursLeft + queuedTask.hoursLeft;
 }, 0)
 }
}
```

`updateQueuedTasks()`方法利用 JavaScript 的原生`Array.filter()`和`Array.reduce()`方法从原始任务集合属性中构建一个排队任务列表。应用于结果数组的`reduce`方法给出了要运送的单位总数。现在有了一个有状态的计算排队单位数量的方法，是时候相应地更新我们的模板了。转到`tasks.html`并在`<h4>Tasks backlog</h4>`元素之前注入以下 HTML 代码块。代码如下：

```ts
<div>
 <h3>
 {{queuedTasks | i18nPlural:queueHeaderMapping}}
 for today
 <span class="small" *ngIf="queuedTasks > 0">
 (Estimated time: {{ queuedTasks > 0 }})
 </span>
 </h3>
</div>
<h4>Tasks backlog</h4>
<!-- rest of the template remains the same -->
```

前面的代码块始终呈现一个信息性的标题，即使没有任务排队。我们还将该值绑定在模板中，并使用它通过表达式绑定来估算通过每个会话所需的分钟数。

我们正在在模板中硬编码每个任务的持续时间。理想情况下，这样的常量值应该从应用程序变量或集中设置中绑定。别担心，我们将在接下来的章节中看到如何改进这个实现。

保存更改并重新加载页面，然后尝试在表格上切换一些任务项目，看看信息如何实时变化。令人兴奋，不是吗？

# 嵌入子组件

现在，让我们开始构建一个微小的图标组件，它将嵌套在`TasksComponent`组件内部。这个新组件将显示我们大图标的一个较小版本，我们将用它来在模板上显示排队等待完成的任务数量，就像我们在本章前面描述的那样。让我们为组件树铺平道路，我们将在第六章中详细分析，*使用 Angular 组件构建应用程序*。现在，只需在之前构建的`TasksComponent`类之前包含以下组件类。

我们的组件将公开一个名为 task 的公共属性，我们可以在其中注入一个`Task`对象。组件将使用这个`Task`对象绑定，根据该任务的`hoursLeft`属性所需的会话次数，在模板中复制渲染的图像，这都是通过`ngFor`指令实现的。

在我们的`tasks.ts`文件中，在`TasksComponent`之前注入以下代码块：

```ts
@Component({
 selector : 'task-icons',
 template : `
 <img *ngFor="let icon of icons"
 src="/assets/img/task.png"
 width="50">`
})
export class TaskIconsComponent implements OnInit {
 @Input() task: Task;
 icons: Object[] = [];
 ngOnInit() {
 this.icons.length = this.task.hoursLeft;
 this.icons.fill({ name : this.task.name });
 }
}
```

在我们继续迭代我们的组件之前，重要的是要确保我们将组件注册到一个模块中，这样其他构造体就可以知道它的存在，这样它们就可以在它们的模板中使用该组件。我们通过将它添加到其模块对象的`declarations`属性中来注册它：

```ts
@NgModule({
 imports : [ /* add needed imports here */ ]
 declarations : [ 
 TasksComponent,
   TaskIconsComponent  
 ]
})
export class TaskModule {}
```

现在`TaskModule`知道了我们的组件，我们可以继续改进它。

我们的新`TaskIconsComponent`具有一个非常简单的实现，具有一个非常直观的选择器，与其驼峰命名的类名匹配，以及一个模板，在模板中，我们根据控制器类的 icons 数组属性中填充的对象的数量，多次复制给定的`<img>`标签，这是通过 JavaScript API 中的`Array`对象的 fill 方法填充的（fill 方法用静态值填充数组的所有元素作为参数传递），在`ngOnInit()`中。等等，这是什么？我们不应该在构造函数中实现填充图标数组成员的循环吗？

这种方法是我们将在下一章概述的生命周期钩子之一，可能是最重要的一个。我们之所以在这里填充图标数组字段，而不是在构造方法中，是因为我们需要在继续运行 for 循环之前，每个数据绑定属性都得到适当的初始化。否则，太早访问输入值任务将会返回一个未定义的值。

`OnInit`接口要求在实现此接口的控制器类中集成一个`ngOnInit()`方法，并且一旦所有已定义绑定的输入属性都已检查，它将被执行。我们将在第六章中对组件生命周期钩子进行概述，*使用 Angular 组件构建应用程序*。

我们的新组件仍然需要找到其父组件。因此，让我们在`TasksComponent`的装饰器设置的 directives 属性中插入对组件类的引用：

```ts
@Component({
 selector : 'tasks',
 styleUrls : ['tasks.css'],
 templateUrl : 'tasks.html'
})
```

我们的下一步将是在`TasksComponent`模板中注入`<task-icons>`元素。回到`tasks.html`，并更新条件块内的代码，以便在`hoursLeft`大于零时显示。代码如下：

```ts
<div>
 <h3>
 {{ hoursLeft | i18nPlural:queueHeaderMapping }}
 for today
 <span class="small" *ngIf="hoursLeft > 0">
 (Estimated time : {{ hoursLeft * 25 }})
 </span>
 </h3> 
 <p>
 <span *ngFor="let queuedTask of tasks">
      <task-icons
 [task]="queuedTask"
 (mouseover)="tooltip.innerText = queuedTask.name"
 (mouseout)="tooltip.innerText = 'Mouseover for details'">
 </task-icons>
 </span>
 </p>
 <p #tooltip *ngIf="hoursLeft > 0">Mouseover for details</p>
</div>
<h4>Tasks backlog</h4>
<!-- rest of the template remains the same -->
```

然而，仍然有一些改进的空间。不幸的是，图标大小在`TaskIconsComponent`模板中是硬编码的，这使得在其他需要不同大小的上下文中重用该组件变得更加困难。显然，我们可以重构`TaskIconsComponent`类，以公开一个`size`输入属性，然后将接收到的值直接绑定到组件模板中，以便根据需要调整图像的大小。

```ts
@Component({
 selector : 'task-icon',
 template : `
 <img *ngfor="let icon of icons" 
 src="/assets/img/task.png" 
 width="{{size}}">`
})
export class TaskIconsComponent implements OnInit {
 @Input() task: Task;
 icons : Object[] = [];
  @Input() size: number;
 ngOnInit() {
 // initialise component here
 }
}
```

然后，我们只需要更新`tasks.html`的实现，以声明我们需要的大小值：

```ts
<span *ngFor="let queuedTask of tasks">
 <task-icons 
 [task]="queuedTask" 
    size="50" 
 (mouseover)="tooltip.innerText = queuedTask.name">
 </task-icons>
</span>
```

请注意，`size`属性没有用括号括起来，因为我们绑定了一个硬编码的值。如果我们想要绑定一个组件变量，那么该属性应该被正确声明为`[size]="{{mySizeVariable}}"`。

我们插入了一个新的 DOM 元素，只有在剩余小时数时才会显示出来。我们通过在 H3 DOM 元素中绑定`hoursLeft`属性，显示了一个实际的标题告诉我们剩余多少小时，再加上一个总估计时间，这些都包含在`{{ hoursLeft * 25 }}`表达式中。

`ngFor`指令允许我们遍历 tasks 数组。在每次迭代中，我们渲染一个新的`<task-icons>`元素。

我们在循环模板中将每次迭代的`Task`模型对象，由`queuedTask`引用表示，绑定到了`<task-icons>`的 task 输入属性中。

我们利用了`<task-icons>`元素来包含额外的鼠标事件处理程序，这些处理程序指向以下段落，该段落已标记为`#tooltip`本地引用。因此，每当用户将鼠标悬停在任务图标上时，图标行下方的文本将显示相应的任务名称。

我们额外努力，将由`<task-icons>`渲染的图标大小作为组件 API 的可配置属性。我们现在有了实时更新的图标，当我们切换表格上的信息时。然而，新的问题已经出现。首先，我们正在显示与每个任务剩余时间匹配的图标组件，而没有过滤掉那些未排队的图标。另一方面，为了实现所有任务所需的总估计时间，显示的是总分钟数，随着我们添加更多任务，这个信息将毫无意义。

也许，现在是时候修改一下了。自定义管道来拯救真是太好了！

# 构建我们自己的自定义管道

我们已经看到了管道是什么，以及它们在整个 Angular 生态系统中的目的是什么，但现在我们将更深入地了解如何构建我们自己的一组管道，以提供对数据绑定的自定义转换。

# 自定义管道的解剖

定义管道非常容易。我们基本上需要做以下事情：

+   导入`Pipe`和`PipeTransform`

+   实现`PipeTransform`接口

+   将`Pipe`组件添加到模块中

实现`Pipe`的完整代码看起来像这样：

```ts
import { Pipe, PipeTransform, Component } from '@angular/core';

@Pipe({
 name : 'myPipeName'
})
export class MyPipe implements PipeTransform {
 transform( value: any, ...args: any[]): any {
 // We apply transformations to the input value here
 return something;
 }
}
@Component({
 selector : 'my-selector',
 template : '<p>{{ myVariable | myPipeName: "bar"}}</p>'
})
export class MyComponent {
 myVariable: string = 'Foo';
}
```

让我们逐步分解即将到来的小节中的代码。

# 导入

我们导入了以下结构：

```ts
import { Pipe, PipeTransform, Component }
```

# 定义我们的管道

`Pipe`是一个装饰器，它接受一个对象文字；我们至少需要给它一个名称属性：

```ts
@Pipe({ name : 'myPipeName' })
```

这意味着一旦使用，我们将像这样引用它的名称属性：

```ts
{{ value | myPipeName }}
```

`PipeTransform`是我们需要实现的接口。我们可以通过将其添加到我们的类中轻松实现：

```ts
@Pipe({ name : 'myPipeName' })
export class MyPipeClass {
 transform( value: any, args: any[]) {
 // apply transformation here
 return 'add banana ' + value; 
 }
}
```

在这里，我们可以看到我们有一个 transform 方法，但第一个参数是值本身，其余是`args`，一个包含您提供的任意数量参数的数组。我们已经展示了如何使用这个`Pipe`，但是如果提供参数，它看起来有点不同，就像这样：

```ts
{{ value | myPipeName:arg1:arg2 }}
```

值得注意的是，对于我们提供的每个参数，它最终都会出现在`args`数组中，并且我们用冒号分隔它。

# 注册它

要使一个构造可用，比如一个管道，你需要告诉模块它的存在。就像组件一样，我们需要像这样添加到 declarations 属性中：

```ts
@NgModule({
 declarations : [ MyPipe ]
})
export ModuleClass {}
```

# 纯属性

我们可以向我们的`@Pipe`装饰器添加一个属性，`pure`，如下所示：

```ts
@Pipe({ name : 'myPipe', pure : false })
export class MyPipe implements PipeTransform {
 transform(value: any, ...args: any[]) {}
}
```

“为什么我们要这样做？”你问。嗯，有些情况下可能是必要的。如果你有一个像这样处理原始数据的管道：

```ts
{{ "decorate me" |  myPipe }}
```

我们没有问题。但是，如果它看起来像这样：

```ts
{{ object | myPipe }}
```

我们可能会遇到问题。考虑组件中的以下代码：

```ts
export class Component {
 object = { name : 'chris', age : 37 }

 constructor() {
 setTimeout(() => this.object.age = 38 , 3000)
 }
}
```

假设我们有以下`Pipe`实现来配合它：

```ts
@Pipe({ name : 'pipe' })
export class MyPipe implements PipeTransform {
 transform(value:any, ...args: any[]) {
 return `Person: ${value.name} ${value.age}` 
 }
}
```

这起初会是输出：

```ts
Chris 37
```

然而，你期望输出在 3 秒后改变为`Chris 38`，但它没有。管道只关注引用是否已更改。在这种情况下，它没有，因为对象仍然是相同的，但对象上的属性已更改。告诉它对更改做出反应的方法是指定`pure`属性，就像我们在开始时所做的那样。因此，我们更新我们的`Pipe`实现如下：

```ts
@Pipe({ name : 'pipe', pure: false })
export class MyPipe implements PipeTransform {
 transform(value: any, ...args:any[]) {
 return `Person: ${value.name} ${value.age}`
 }
}
```

现在，我们突然看到了变化发生。不过，需要注意的是，这实际上意味着`transform`方法在每次变更检测周期被触发时都会被调用。因此，这对性能可能会造成损害。如果设置`pure`属性，你可以尝试缓存该值，但也可以尝试使用 reducer 和不可变数据以更好地解决这个问题：

```ts
// instead of altering the data like so
this.jedi.side = 'Dark'

// instead do
this.jedi = Object.assign({}, this.jedi, { side : 'Dark' });
```

前面的代码将更改引用，我们的 Pipe 不会影响性能。总的来说，了解 pure 属性的作用是很好的，但要小心。

# 更好地格式化时间输出的自定义管道

当排列要完成的任务时，观察总分钟数的增加并不直观，因此我们需要一种方法将这个值分解为小时和分钟。我们的管道将被命名为`formattedTime`，并由`formattedTimePipe`类实现，其唯一的 transform 方法接收一个表示总分钟数的数字，并返回一个可读的时间格式的字符串（证明管道不需要返回与载荷中接收到的相同类型）。：

```ts
@Pipe({
 name : 'formattedTime'
})
export class FormattedTimePipe implements PipeTransform {
 transform(totalMinutes : number) {
 let minutes : number = totalMinutes % 60;
 let hours : numbers = Math.floor(totalMinutes / 60);
 return `${hours}h:{minutes}m`;
 }
}
```

我们不应该错过强调管道的命名约定，与我们在组件中看到的一样，管道类的名称加上`Pipe`后缀，再加上一个与该名称匹配但不带后缀的选择器。为什么管道控制器的类名和选择器之间存在这种不匹配？这是常见的做法，为了防止与第三方管道和指令定义的其他选择器发生冲突，我们通常会给我们自定义管道和指令的选择器字符串添加一个自定义前缀。

```ts
@Component({
 selector : 'tasks',
 styleUrls : [ 'tasks.css' ],
 templateUrl : 'tasks.html'
})
export class TasksComponent {}
```

最后，我们只需要调整`tasks.html`模板文件中的 HTML，以确保我们的 EDT 表达式格式正确：

```ts
<span class="small">
 (Estimated time: {{ queued * 25 | formattedTime }})
</span>
```

现在，重新加载页面并切换一些任务。预计时间将以小时和分钟正确呈现。

最后，我们不要忘记将我们的`Pipe`构造添加到其模块`tasks.module.ts`中：

```ts
@NgModule({
 declarations: [TasksComponent, FormattedTimePipe]
})
export class TasksModule {}
```

# 使用自定义过滤器过滤数据

正如我们已经注意到的，我们目前为每个任务在从任务服务提供的集合中显示一个图标组件，而没有过滤出哪些任务标记为排队，哪些不是。管道提供了一种方便的方式来映射、转换和消化数据绑定，因此我们可以利用其功能来过滤我们`ngFor`循环中的任务绑定，只返回那些标记为排队的任务。

逻辑将非常简单：由于任务绑定是一个`Task`对象数组，我们只需要利用`Array.filter()`方法来获取那些`queued`属性设置为`true`的`Task`对象。我们可能会额外配置我们的管道以接受一个布尔参数，指示我们是否要过滤出排队或未排队的任务。这些要求的实现如下，您可以再次看到选择器和类名的惯例：

```ts
@Pipe({
 name : 'queuedOnly'
})
export class QueuedOnlyPipe implements PipeTransform {
 transform(tasks: Task[]), ...args:any[]): Task[] {
 return tasks.filter( task:Task => task.queued === args[0])
 }
}
```

实现非常简单，所以我们不会在这里详细介绍。然而，在这个阶段有一件值得强调的事情：这是一个不纯的管道。请记住，任务绑定是一个有状态对象的集合，随着用户在表格上切换任务，其长度和内容将发生变化。因此，我们需要指示管道利用 Angular 的变更检测系统，以便其输出在每个周期都被后者检查，无论其输入是否发生变化。然后，将管道装饰器的`pure`属性配置为`false`就可以解决问题。

现在，我们只需要更新使用此管道的组件的 pipes 属性：

```ts
@Component({
 selector : 'tasks',
 styleUrls : ['tasks.css'],
 templateUrl : 'tasks.html'
})
export class TasksComponent {
 // Class implementation remains the same
}
```

然后，在`tasks.html`中更新`ngFor`块，以正确过滤出未排队的任务：

```ts
<span *ngFor="queuedTask of tasks | queuedOnly:true">
 <task-icons
 [task]="queuedTask"
 (mouseover)="tooltip.innerText = queuedTask.name"
 (mouseout)="tooltip.innerText = 'Mouseover for details'">
 </task-icons>
</span>
```

请检查我们如何将管道配置为`queuedOnly: true`。将布尔参数值替换为`false`将使我们有机会列出与我们未选择的队列相关的任务。

保存所有工作并重新加载页面，然后切换一些任务。您将看到我们的整体 UI 如何根据最新更改做出相应的反应，我们只列出与排队任务的剩余小时数相关的图标。

# 构建我们自己的自定义指令

自定义指令涵盖了广泛的可能性和用例，我们需要一整本书来展示它们提供的所有复杂性和可能性。

简而言之，指令允许您将高级行为附加到 DOM 中的元素上。如果指令附有模板，则它将成为一个组件。换句话说，组件是具有视图的 Angular 指令，但我们可以构建没有附加视图的指令，这些指令将应用于已经存在的 DOM 元素，使其 HTML 内容和标准行为立即对指令可用。这也适用于 Angular 组件，其中指令将在必要时访问其模板和自定义属性和事件。

# 自定义指令的解剖

声明和实现自定义指令非常容易。我们只需要导入`Directive`类，以为其附属的控制器类提供装饰器功能：

```ts
import { Directive } from '@angular/core';
```

然后，我们定义一个由`@Directive`装饰器注释的控制器类，在其中我们将定义指令选择器、输入和输出属性（如果需要）、应用于宿主元素的可选事件，以及可注入的提供者令牌，如果我们的指令构造函数在实例化时需要特定类型由 Angular 注入器实例化自己（我们将在第六章中详细介绍这一点，*使用 Angular 组件构建应用程序*）：

让我们先创建一个非常简单的指令来热身：

```ts
import { Directive, ElementRef } from '@angular/core';

@Directive({
 selector : '[highlight]'
})
export class HighLightDirective {
 constructor( private elementRef: ElementRef, private renderer : Renderer2 ) {
 var nativeElement = elementRef.nativeElement;
 this.renderer.setProperty( nativeElement,'backgroundColor', 'yellow');
 }
}
```

要使用它就像输入一样简单：

```ts
<h1 highlight></h1>
```

我们在这里使用了两个 actor，`ElementRef`和`Renderer2`，来操作底层元素。我们可以直接使用`elementRef.nativeElement`，但这是不鼓励的，因为这可能会破坏服务器端渲染或与服务工作者交互时。相反，我们使用`Renderer2`的实例进行所有操作。

注意我们不输入方括号，而只输入选择器名称。

我们在这里快速回顾了一下，注入了`ElementRef`并访问了`nativeElement`属性，这是实际元素。我们还像在组件和管道上一样，在类上放置了一个`@Directive`装饰器。创建指令时要有的主要思维方式是考虑可重用的功能，不一定与某个特定功能相关。之前选择的主题是高亮，但我们也可以相对容易地构建其他功能，比如工具提示、可折叠或无限滚动功能。

属性和装饰器，比如选择器、`@Input()`或`@Output()`（与输入和输出相同），可能会让您回想起我们概述组件装饰器规范时的时间。尽管我们尚未详细提到所有可能性，但选择器可以声明为以下之一：

+   `element-name`: 通过元素名称选择

+   `.class`: 通过类名选择

+   `[attribute]`: 通过属性名称选择

+   `[attribute=value]`: 通过属性名称和值选择

+   `not(sub_selector)`: 仅在元素不匹配时选择

`sub_selector`

+   `selector1`, `selector2`: 如果`selector1`或`selector2`匹配，则选择

除此之外，我们还会找到主机参数，该参数指定了与主机元素（即我们指令执行的元素）相关的事件、动作、属性和属性，我们希望从指令内部访问。因此，我们可以利用这个参数来绑定与容器组件或任何其他目标元素（如窗口、文档或主体）的交互处理程序。这样，当编写指令事件绑定时，我们可以引用两个非常方便的本地变量：

+   `$event`: 这是触发事件的当前事件对象。

+   `$target`: 这是事件的来源。这将是一个 DOM 元素或一个 Angular 指令。

除了事件，我们还可以更新属于主机组件的特定 DOM 属性。我们只需要将任何特定属性用大括号括起来，并在我们指令的主机定义中将其作为键值对与指令处理的表达式链接起来。

可选的主机参数还可以指定应传播到主机元素的静态属性，如果尚未存在。这是一种方便的方式，可以使用计算值注入 HTML 属性。

Angular 团队还提供了一些方便的装饰器，这样我们就可以更加直观地在代码中声明我们的主机绑定和监听器，就像这样：

```ts
@HostBinding('[class.valid]')
isValid: boolean; // The host element will feature class="valid"
// is the value of 'isValid' is true.
@HostListener('click', ['$event'])
onClick(e) {
 // This function will be executed when the host 
  // component triggers a 'click' event.
}
```

在接下来的章节中，我们将更详细地介绍指令和组件的配置接口，特别关注它的生命周期管理以及我们如何轻松地将依赖项注入到我们的指令中。现在，让我们只是构建一个简单但强大的指令，它将对我们的 UI 的显示和维护产生巨大的影响。

# 监听事件

到目前为止，我们已经能够创建我们的第一个指令，但这并不是很有趣。然而，添加监听事件的能力会使它变得更有趣，所以让我们来做吧。我们需要使用一个叫做`HostListener`的辅助工具来监听事件，所以我们首先要导入它：

```ts
import { HostListener } from '@angular/core';
```

我们需要做的下一件事是将它用作装饰器并装饰一个方法；是的，一个方法，而不是一个类。它看起来像下面这样：

```ts
@Directive({
 selector : '[highlight]'
})
export class HighlightDirective {
 @HostListener('click')
 clicked() {
 alert('clicked') 
 }
}

```

使用这个指令点击一个元素将会导致一个警告窗口弹出。添加事件非常简单，所以让我们尝试添加`mouseover`和`mouseleave`事件：

```ts
@Directive({
 selector : '[highlight]'
})
export class HighlightDirective {
 private nativeElement;

 constructor(elementRef: ElementRef, renderer: Renderer2) {
 this.nativeElement = elementRef.nativeElement;
 }

 @HostListener('mousenter')
 onMouseEnter() {
 this.background('red');
 }

 onMouseLeave('mouseleave') {
 this.background('yellow');
 }

 private background(bg:string) {
 this.renderer.setAttribute(nativeElement,'backgroundColor', bg);
 }
}
```

这给了我们一个指令，当鼠标悬停在组件上时，背景会变成`红色`，当鼠标离开时会恢复为`黄色`。

# 添加输入数据

我们的指令对于使用什么颜色是相当静态的，所以让我们确保它们可以从外部设置。要添加第一个输入，我们需要使用我们的老朋友`@Input`装饰器，但是不像我们习惯的那样不给它任何参数作为输入，我们需要提供指令本身的名称，如下所示：

```ts
<div highlight="orange"></div>

@Directive({ selector : '[highlight]' })
export class HighlightDirective 
 private nativeElement;

 constructor(elementRef: ElementRef, renderer: Renderer2) {
 this.nativeElement = elementRef.nativeElement;
 }

 @Input('highlight') color:string;

 @HostListener('mousenter')
 onMouseEnter(){
 this.background(this.color);
 }

 onMouseLeave() {
 this.background('yellow'); 
 }

 private background(bg: string) {
 this.renderer( nativeElement, 'background', bg );
 }
}
```

在这一点上，我们已经处理了第一个输入；我们用以下方法做到了这一点：

```ts
@Input('highlight') color: string;
```

但是，我们如何向我们的指令添加更多的输入？我们将在下一小节中介绍这个问题。

# 添加多个输入属性

所以你想要添加另一个输入，这也相对容易。我们只需要在我们的 HTML 元素中添加一个属性，如下所示：

```ts
<div [highlight]="orange" defaultColor="yellow">
```

在代码中我们输入：

```ts
@Directive({})
export class HighlightDirective {
 @Input() defaultColor
 constructor() {
 this.background(this.defaultColor);
 }
 // the rest omitted for brevity
}
```

然而，我们注意到在我们进行第一次`mousenter` + `mouseleave`之前，我们没有颜色，原因是构造函数在我们的`defaultColor`属性被设置之前运行。为了解决这个问题，我们需要稍微不同地设置输入。我们需要像这样使用一个属性：

```ts
private defaultColor: string;

@Input()
set defaultColor(value) { 
 this.defaultColor = value;
 this.background(value); 
}

get defaultColor(){ return this.defaultColor; }
```

总结一下关于使用输入的部分，很明显我们可以使用`@Input`装饰器来处理一个或多个输入。然而，第一个输入应该是指令的选择器名称，第二个输入是你给它的属性的名称。

# 第二个例子 - 错误验证

让我们利用对指令的这些新知识，构建一个指示字段错误的指令。我们认为错误是指我们着色元素并显示错误文本：

```ts
import { Directive, ElementRef, Input } from '@angular/core';
@Directive({
 selector: '[error]'
})
export class ErrorDirective {
 error:boolean;
 private nativeElement;
 @Input errorText: string;
 @Input()
 set error(value: string) {
 let val = value === 'true' ? true : false;
 if(val){ this.setError(); }
 else { this.reset(); }
 }

 constructor(
 private elementRef: ElementRef, 
 private renderer: Renderer2
 ) {
 this.nativeElement = elementRef.nativeElement;
 }

 private reset() { 
 this.renderer.setProperty(nativeElement, 'innerHTML', '');
 this.renderer.setProperty(nativeElement, 'background', '') 
 }

 private setError(){
 this.renderer.setProperty(nativeElement, 'innerHTML', this.errorText);
 this.renderer.setProperty(nativeElement, 'background', 'red');
 }
}
```

而要使用它，我们只需输入：

```ts
<div error="{{hasError}}" errorText="display this error">
```

# 构建一个任务提示自定义指令

到目前为止，我们已经构建了一个高亮指令以及一个错误显示指令。我们已经学会了如何处理事件以及多个输入。

关于提示信息的简短说明。当我们悬停在一个元素上时，会出现提示信息。通常你要做的是在元素上设置 title 属性，就像这样：

```ts
<div title="a tooltip"></div>
```

通常有几种方法可以在这样的组件上构建提示信息。一种方法是绑定到`title`属性，就像这样：

```ts
<task-icons [title]="task.name"></task-icons>
```

然而，如果你有更多的逻辑想法，将所有内容都添加到标记中可能不太好，所以在这一点上，我们可以创建一个指令来隐藏提示信息，就像这样：

```ts
@Directive({ selector : '[task]' })
export class TooltipDirective {
 private nativeElement;
 @Input() task:Task;
 @Input() defaultTooltip: string;

 constructor(private elementRef: ElementRef, private renderer : Renderer2) {
 this.nativeElement = elementRef.nativeElement;
 }

 @HostListener('mouseover')
 onMouseOver() {
 let tooltip = this.task ? this.task.name : this.defaultTooltip;
 this.renderer.setProperty( this.nativeElement, 'title', tooltip );
 }
}
```

使用它将是：

```ts
<div [task]="task">
```

然而，我们还可以采取另一种方法。如果我们想在悬停在一个元素上时改变另一个元素的 innerText 呢？这是很容易做到的，我们只需要将我们的指令传递给另一个元素，并更新它的 innerText 属性，就像这样：

```ts
<div [task]="task" [elem]="otherElement" defaultTooltip="default text" >
<div #otherElement>
```

当然，这意味着我们需要稍微更新我们的指令到这样：

```ts
@Directive({ selector : '[task]' })
export class TooltipDirective {
 private nativeElement;
 @Input() task:Task;
 @Input() defaultTooltip: string;

 constructor(private elementRef: ElementRef, private renderer : Renderer2) {
 this.nativeElement = elementRef.nativeElement;
 }

 @HostListener('mouseover')
 onMouseOver() {
 let tooltip = this.task ? this.task.name : this.defaultTooltip;
    this.renderer.setProperty( this.nativeElement, 'innerText', tooltip );
 }
}
```

# 关于自定义指令和管道的命名约定

谈到可重用性，通常的约定是在选择器前面添加一个自定义前缀。这可以防止与其他库定义的选择器发生冲突，这些库可能在我们的项目中使用。同样的规则也适用于管道，正如我们在介绍我们的第一个自定义管道时已经强调的那样。

最终，这取决于你和你采用的命名约定，但建立一个可以防止这种情况发生的命名约定通常是一个好主意。自定义前缀绝对是更容易的方法。

# 总结

现在我们已经达到这一点，可以说你几乎知道构建 Angular 组件所需的一切，这些组件确实是所有 Angular 2 应用程序的核心和引擎。在接下来的章节中，我们将看到如何更好地设计我们的应用程序架构，因此在整个组件树中管理依赖注入，使用数据服务，利用新的 Angular 路由器在需要时显示和隐藏组件，并管理用户输入和身份验证。

然而，这一章是 Angular 开发的支柱，我们希望您和我们一样喜欢它，当我们写关于模板语法、基于属性和事件的组件 API、视图封装、管道和指令时。现在，准备好迎接新的挑战——我们将从学习如何编写组件转向发现如何使用它们来构建更大的应用程序，同时强调良好的实践和合理的架构。我们将在下一章中看到所有这些。
