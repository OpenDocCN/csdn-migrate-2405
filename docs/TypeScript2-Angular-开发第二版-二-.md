# TypeScript2 Angular 开发第二版（二）

> 原文：[`zh.annas-archive.org/md5/81C516831B5BF457C3508E2F3CF1895F`](https://zh.annas-archive.org/md5/81C516831B5BF457C3508E2F3CF1895F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 TypeScript 进行组件组合

使用 TypeScript 编写的组件在保持简短和简单时效果最佳。然而，一个简短和简单的组件很难构建一个完整的应用程序。如何组合执行特定任务的组件并将它们组合在一起以制作可用的应用程序？这就是本章的内容。我们将讨论以下主题：

+   组件层次结构

+   不同级别组件之间的通信

我们还将看到一些实际示例，说明组件是如何组合的，以及这些组合的组件如何相互通信。

# 组件的可组合性

可组合性是组件最突出的特点和卖点。事实上，这就是使组件成为组件的原因。不仅在网络上，而且每当一个实体被称为组件时，它都有与其他组件组合的倾向。

虽然一些组件可以独立运行，但大多数隐式或显式地依赖于其他独立组件来完成特定任务。TypeScript 和模板极大地简化了 Angular 中的组合，使其能够以一种无缝和易于维护的方式将应用程序的各个部分组合在一起。

组合是分层发生的；因此，大多数组件关系要么是父子关系，要么是子父关系。还要记住，如果存在这样的父子关系，那么根据架构，一些组件可能是其他组件的兄弟。

# 分层组合

一个组合的组件与另一个组件有父子关系，可以是父组件或子组件。存在嵌套链的倾向；因此，没有什么能阻止子组件有一个祖父组件或父组件有一个孙子组件。

以下截图更好地说明了这一点：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/453d62b1-475d-435f-8b61-67100bb55440.png)

在这里，入口 `App` 组件有两个子组件：`CommentList` 和 `CommentForm`。`CommentList` 也有一个子组件，`CommentItem`。可以说 `CommentItem` 是 `App` 的孙子。也可以说 `CommentList` 和 `CommentForm` 是兄弟。

粗箭头显示了数据如何从父组件流向子组件，而虚线箭头显示了数据如何作为事件从子组件推送到父组件。这种数据向下流动和向上移动的说明引导我们进入下一个讨论主题：组件通信。

# 组件通信

根据我们之前看到的图表，让我们看一些实际示例。开始的推荐位置是从父级到子级的数据流。

# 父子流程

立即开始并使用 Angular CLI 创建一个新的 Angular 项目。完成后，使用以下内容更新`AppComponent`：

```ts
import { Component } from '@angular/core';    @Component({  selector: 'app-root',  templateUrl: './app.component.html',  styleUrls: ['./app.component.css']  })  export class AppComponent {  title = 'app';  comments = [  {  author: 'Jay Kay',  content: 'TypeScript makes Angular awesome'  },  {  author: 'William',  content: 'Yeah, right!'  },  {  author: 'Raphael',  content: 'Got stuck passing data around'  }  ]  }  
```

关键区别在于我添加了一个评论数组。这些评论是我们打算传递给子组件的。

让我们使用 Angular CLI 生成命令创建`CommentListComponent`：

```ts
ng g component comment-list
```

创建的组件旨在从父组件`AppComponent`接收评论列表。当它接收到这个组件时，它可以对它们进行迭代并在屏幕上打印它们：

```ts
import { Component, OnInit, Input } from '@angular/core';    @Component({  selector: 'app-comment-list',  templateUrl: './comment-list.component.html',  styleUrls: ['./comment-list.component.css']  })  export class CommentListComponent implements OnInit {  // Received via Imputs @Input() comments;   constructor() { }   
 ngOnInit() {}    }   
```

`Input` TypeScript 装饰器用于指定一个类属性将由父组件设置。因此，我们不需要在`CommentListComponent.comments`上设置任何值，但是我们需要等待直到通过`AppComponent`传递一个值给它。请记住`AppComponent.comments`也存在，因此我们可以使用属性绑定将`AppComponent.comments`传递给`CommentListComponent.comments`在`app.component.html`中：

```ts
<div>  <h2>Comments</h2>  <app-comment-list [comments]="comments"></app-comment-list>  </div>  
```

`comments`数组是传递给`[comments]`属性的值。这个属性是我们在`CommentListComponent`组件中创建和装饰的。

现在您在父组件（`AppComponent`）上有一个评论数组；您已经通过属性绑定将此组件传递给子组件（`CommentListComponent`），并且正在使用`Input`装饰器接收评论列表。您需要做的下一件事是在`comment-list.component.html`上显示接收到的评论：

```ts
<div class="comment-box" *ngFor="let comment of comments">  <h3>{{comment.author}}</h3>  <p>{{comment.content}}</p>  </div>  
```

`*ngFor`指令用于遍历评论，获取每条评论，并在我们的视图上显示评论。

这就是输出的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/ba7abb11-cdac-4852-a474-b5a22ea57684.png)

您可以再深入一层，创建一个评论项组件，它只需要一个评论并显示它。创建另一个组件：

```ts
ng g component comment-item
```

添加一个装饰的评论属性，它将从评论列表中接收评论项：

```ts
import { Component, OnInit, Input } from '@angular/core';    @Component({  selector: 'app-comment-item',  templateUrl: './comment-item.component.html',  styleUrls: ['./comment-item.component.css']  })  export class CommentItemComponent implements OnInit {  // Decorated comment 
 @Input() comment;   constructor() { }    ngOnInit() {}    }   
```

通过`评论列表`父组件将评论传递下去：

```ts
<app-comment-item 
 *ngFor="let comment of comments" [comment]="comment">  </app-comment-item>  
```

`comment`模板变量不必存在于组件类中。它是从迭代器中获取的。

然后，您可以简单地在`comment-item.component.html`模板上渲染评论项：

```ts
<h3>{{comment.author}}</h3>  <p>{{comment.content}}</p>  
```

添加另一个子组件说明了嵌套。`App | 评论列表 | 评论项`是流程。`App`是`评论列表`的父级，也是`评论项`的祖父级。`评论列表`是`评论项`的父级。

转到浏览器，看到，虽然实际上没有任何变化，但我们的代码结构更好了：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/52f7ff63-9805-4065-93e8-79ad575cba53.png)

# 拦截属性更改

有时，您可能希望对从父组件流入子组件的数据进行一些调整。您可以使用 getter 和 setter 拦截数据并在将其设置到视图之前对其进行操作。让我们通过将作者名称大写化来演示这一点：

```ts
import { Component, OnInit, Input } from '@angular/core';    @Component({  selector: 'app-comment-item',  templateUrl: './comment-item.component.html',  styleUrls: ['./comment-item.component.css']  })  export class CommentItemComponent implements OnInit {   
 private _comment;  constructor() { }    ngOnInit() {}    @Input()  set comment(comment) {  this._comment = Object.assign(comment, {
 author: comment.author.toUpperCase()
 });  }    get comment() {  return this._comment  }    }   
```

装饰器不再设置在值属性上，而是设置在 setter 属性上。该属性接收来自评论列表（父组件）的评论。然后，它用作者姓名的大写版本覆盖作者属性。getter 只是返回评论，所以您可以从视图中访问它。

在浏览器中的效果如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/fb9adce2-7254-4c30-9bbe-d16ff3140fa3.png)

# 子-父流程

在这个流程中，数据不是向下传递，而是需要沿着链条向上流动。大多数情况下，数据是根据用户在子组件上触发的事件而向上流动的，我们试图通知父组件有关该事件。因此，Angular 允许您在父组件上监听子事件并对事件做出反应。这些事件可以以数据作为有效载荷进行描述。

让我们首先通过评论列表组件在每个评论项上注册双击事件：

```ts
<app-comment-item 
 *ngFor="let comment of comments" 
 [comment]="comment" 
 (dblclick)="showComment(comment)">  </app-comment-item>  
```

然后，您需要在组件类上添加`showComment`处理程序来处理此事件：

```ts
import { 
 Component, 
 OnInit, 
 Input, 
 EventEmitter, 
 Output } from '@angular/core';    @Component({  selector: 'app-comment-list',  templateUrl: './comment-list.component.html',  styleUrls: ['./comment-list.component.css']  })  export class CommentListComponent implements OnInit {    @Input() comments;  @Output() onShowComment = new EventEmitter();    constructor() { }   ngOnInit() {}    showComment(comment) {  this.onShowComment.emit(comment);  }    }   
```

处理程序使用`onShowComment`，它被装饰为`Output`装饰器的输出属性，以发出`EventEmitter`类型的事件。这个发出的事件是父组件需要监听的。注意评论是如何传递给`emit`方法的；这显示了我们如何可以从子组件向父组件传递数据。

接下来，我们监听父组件（`App`）以便发生这个事件：

```ts
<div>  <h2>Comments</h2>  <app-comment-list 
 [comments]="comments" 
 (onShowComment)="onShowComment($event)">
 </app-comment-list>  </div>  
```

请注意，事件绑定注释`()`用于事件，在这种情况下是`onShowComment`。绑定指的是`EventEmitter`，而其值指的是尚未创建的处理程序方法。处理程序方法被调用，我们将来自子组件的值数据作为`$event`传递。

以下是处理程序的实现：

```ts
import { Component } from '@angular/core';    @Component({  selector: 'app-root',  templateUrl: './app.component.html',  styleUrls: ['./app.component.css']  })  export class AppComponent {  title = 'app';  comments = [  {  author: 'Jay Kay',  content: 'TypeScript makes Angular awesome'  },  // ...  ]    onShowComment(comment) {  alert(comment.content);  }  }   
```

该方法只是像下面的截图中所示警报评论：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/536c136e-4205-42ba-88e1-03897066c949.png)

# 通过父组件访问子组件的属性和方法

除了数据流向和事件向上推送之外，还有其他的通信策略。我们可以使用模板变量从父组件访问子成员。让我们创建一个计数器组件作为示例：

```ts
ng g component counter
```

现在添加一个计数器变量并将其初始化为零：

```ts
//counter.component.html
<h5>  {{counter}}  </h5> //counter.component.ts import { Component, OnInit } from '@angular/core';    @Component({  selector: 'app-counter',  templateUrl: './counter.component.html',  styleUrls: ['./counter.component.css']  })  export class CounterComponent implements OnInit {   
 counter: number = 0;    increment() {  this.counter++  }    decrement() {  this.counter--  }    }   
```

此外，还有两种方法只增加或减少计数器。请注意，没有任何东西调用这些方法；没有按钮附带事件来增加或减少。我们想要做的是从父组件访问这些方法。

为此，在模板中添加组件并使用模板变量：

```ts
<div>  <h2>Comments</h2>  <app-comment-list [comments]="comments" (onShowComment)="onShowComment($event)"></app-comment-list>  ...

  <h2>Counter</h2>  <app-counter #counter></app-counter>    </div>  
```

`#counter`是一个在模板中任何地方都可以访问的变量。因此，您可以将其用作访问计数器组件的方法和属性的对象：

```ts
<div>
  <h2>Comments</h2>
  <app-comment-list [comments]="comments" (onShowComment)="onShowComment($event)"></app-comment-list>

 ... <h2>Counter</h2>
  <app-counter #counter></app-counter>
  <button (click)="counter.increment()">++</button>
  <button (click)="counter.decrement()">--</button>
</div>
```

这显示了一个带有按钮的按钮计数器，我们可以点击按钮来增加或减少计数器：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/d175e8fa-a9ae-4ae4-840e-66b381d81a10.png)

# 使用 ViewChild 访问子成员

如果模板变量感觉不自然，您可以使用`ViewChild`来实现相同的行为。这允许您将子组件作为类上的变量而不是模板上的变量来访问：

```ts
//app.component.ts
import { Component, ViewChild } from '@angular/core';  import { CounterComponent } from './counter/counter.component'    @Component({  selector: 'app-root',  templateUrl: './app.component.html',  styleUrls: ['./app.component.css']  })  export class AppComponent {
  @ViewChild(CounterComponent)  counterComponent: CounterComponent   comments = [  {</span&gt;  author: 'Jay Kay',  content: 'TypeScript makes Angular awesome'  },  // ...  ]    onShowComment(comment) {  alert(comment.content);  }    } 
```

我们导入计数器组件，并使用`ViewChild`将其注册为此组件的子组件。然后，我们创建一个`CounterComponent`类型的`counterComponent`变量。然后我们可以在模板中使用这个变量：

```ts
<app-counter></app-counter>  <button (click)="counterComponent.increment()">++</button>  <button (click)="counterComponent.decrement()">--</button>  
```

# 总结

现在，您可以通过编写小型、可维护的组件，并使用组合使它们相互交互，从而将组件作为构建块来使用。在本章中，您学习了组件体系结构中层次继承的含义，数据如何在层次树中上下流动，以及组件如何相互交互。

在下一章中，我们将探讨一种更加集中的交互策略，即使用服务。这将帮助我们创建组件将共享的逻辑，从而保持我们的代码库非常干净（不重复自己）。


# 第七章：使用类型化服务分离关注点

本章在前一章的基础上构建，展示了更多关于应用程序构建模块内部通信的技术。在本章中，您将学习以下主题：

+   服务和依赖注入（DI）概念

+   使用服务进行组件通信

+   使用服务编写数据逻辑

要更好地理解服务，您需要至少了解依赖注入的基本概念。

# 依赖注入

在 TypeScript 中编写 Angular 要求您的构建模块（组件、指令、服务等）都是以类的形式编写的。它们只是构建模块，这意味着它们在成为功能模块之前需要相互交织，从而形成一个完整的应用程序。

这种交织的过程可能会非常令人望而生畏。因此，让我们首先了解问题。例如，考虑以下 TypeScript 类：

```ts
export class Developer {
 private skills: Array<Skill>;
 private bio: Person;
 constructor() {
 this.bio = new Person('Sarah', 'Doe', 24, 'female');
 this.skills = [
 new Skill('css'), 
 new Skill('TypeScript'), 
 new Skill('Webpack')
 ];
 }
}
```

`Person`和`Skill`类的实现就像下面这样简单：

```ts
// Person Class
export class Person {
 private fName: string;
 private lName: string;
 private age: number;
 private gender: string;
 constructor(
 fName: string, 
 lName: string, 
 age: number, 
 gender: string, 
 ) {
 this.fName = fName;
 this.lName = lName;
 this.age = age;
 this.gender = gender;
 }
}

// Skill Class
export class Skill {
 private type: string;
 constructor(
 type: string
 ) {
 this.type = type;
 }
}
```

前面的示例是非常实用和有效的代码，直到您开始使用这个类创建更多类型的开发人员。由于所有实现细节都与一个类绑定，因此实际上无法创建另一种类型的开发人员；因此，这个过程并不灵活。在可以用于创建更多类型的开发人员之前，我们需要使这个类更加通用。

让我们尝试改进`Developer`类，使其从构造函数中接收创建类所需的所有值，而不是在类中设置它：

```ts
export class Developer {
 private skills: Array<Skills>;
 private bio: Person;
 constructor(
 fName: string, 
 lName: string, 
 age: number, 
 gender: string, 
 skills: Array<string>
 ) {
 this.bio = new Person(fName, lName, age, gender);
 this.skills = skills.map(skill => new Skill(skill));
 }
}
```

这么少的代码就有了这么多的改进！我们现在使用构造函数使代码更加灵活。通过这个更新，您可以使用`Developer`类来创建所需数量的开发人员类型。

尽管这个解决方案看起来像是能拯救一天，但系统中仍然存在紧密耦合的问题。当`Person`和`Skill`类中的构造函数发生变化时会发生什么？这意味着您将不得不回来更新`Developer`类中对此构造函数的调用。以下是`Skill`中这种变化的一个例子：

```ts
// Skill Class
export class Skill {
 private type: string;
 private yearsOfExperience: number;
 constructor(
 type: string,
 yearsOfExperience: number
 ) {
 this.type = type;
 this.yearsOfExperience = yearsOfExperience
 }
}
```

我们为`yearsOfExperience`类添加了另一个字段，它是一个数字类型，表示开发人员练习所声称技能的时间有多长。为了使`Developer`中实际工作，我们还必须更新`Developer`类：

```ts
export class Developer {
 public skills: Array<Skill>;
 private bio: Person;
 constructor(
 fName: string, 
 lName: string, 
 age: number, 
 gender: string, 
 skils: Array<any>
 ) {
 this.bio = new Person(fName, lName, age, gender);
 this.slills = skills.map(skill => 
 new Skill(skill.type, skill.yearsOfExperience));
 }
}
```

每当依赖项发生变化时更新这个类是我们努力避免的。一个常见的做法是将依赖项的构造函数提升到类本身的构造函数中：

```ts
export class Developer {
 public skills: <Skill>;
 private person: Person;
 constructor(
 skill: Skill,
 person: Person
 ) {}
}
```

这样，`Developer`就不太了解`Skill`和`Person`的实现细节。因此，如果它们在内部发生变化，`Developer`不会在意；它仍然保持原样。

事实上，TypeScript 提供了一个高效的简写：

```ts
export class Developer {
 constructor(
 public skills: <Skill>,
 private person: Person
 ) {}
}
```

这个简写将隐式声明属性，并通过构造函数将它们分配为依赖项。

这还不是全部；提升这些依赖项还引入了另一个挑战。我们如何在应用程序中管理所有依赖项，而不失去它们应该在哪里的轨迹？这就是依赖注入的作用。这不是 Angular 的事情，而是在 Angular 中实现的一种流行模式。

让我们开始在 Angular 应用程序中看 DI 的实际应用。

# 组件中的数据

为了更好地理解服务和 DI 的重要性，让我们创建一个简单的应用程序，其中包含一个显示用户评论列表的组件。创建应用程序后，您可以运行以下命令来生成所需的组件：

```ts
ng g component comment-list
```

使用以下片段更新组件的代码：

```ts
import { Component, OnInit } from '@angular/core';

@Component({
 selector: 'app-comment-list',
 templateUrl: './comment-list.component.html',
 styleUrls: ['./comment-list.component.css']
})
export class CommentListComponent implements OnInit {

 comments: Array<any>
 constructor() { }

 ngOnInit() {
 this.comments = [
 {
 author: 'solomon',
 content: `TypeScript + Angular is amazing`
 },
 {
 author: 'lorna',
 content: `TypeScript is really awesome`
 },
 {
 author: 'codebeast',
 content: `I'm new to TypeScript`
 },
 ];
 }

}
```

该组件有一个`comments`数组，在组件通过`ngOnInit`生命周期初始化后，将使用硬编码的数据填充。现在我们需要遍历数组列表并在 DOM 上打印：

```ts
<div class="list-group">
 <a href="#" class="list-group-item" *ngFor="let comment of comments">
 <h4 class="list-group-item-heading">{{comment.author}}</h4>
 <p class="list-group-item-text">{{comment.content}}</p>
 </a>
</div>
```

您需要在入口（应用）组件中包含该组件才能显示出来：

```ts
<div class="container">
 <h2 class="text-center">TS Comments</h2>
 <div class="col-md-6 col-md-offset-3">
 <app-comment-list></app-comment-list>
 </div>
</div>
```

您的应用程序应该如下所示（记得包含 Bootstrap，就像在第二章中看到的那样，*使用 TypeScript 入门*）：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/d857dd7f-3771-4c0f-b578-17ce88a96779.png)

这个例子是有效的，但魔鬼在细节中。当另一个组件需要评论列表或列表的一部分时，我们最终会重新创建评论。这就是在组件中拥有数据的问题所在。

# 数据类服务

为了重用和可维护性，我们需要将组件中的逻辑关注点抽象出来，让组件只作为一个呈现层。这是 TypeScript 在 Angular 中发挥作用的用例之一。

您首先需要使用以下命令创建一个服务：

```ts
ng g service comment
```

这将创建您的服务类`./src/app/comment.service.ts`，其中包含一个框架内容。使用以下内容更新内容：

```ts
import { Injectable } from '@angular/core';

@Injectable()
export class CommentService {
 private comments: Array<any> = [
 {
 author: 'solomon',
 content: `TypeScript + Angular is amazing`
 },
 {
 author: 'lorna',
 content: `TypeScript is really awesome`
 },
 {
 author: 'codebeast',
 content: `I'm new to TypeScript`
 }
 ];
 constructor() {}

 getComments() {
 return this.comments;
 }
}
```

现在这个类会执行我们的组件应该对数据执行的操作，并且使用`getComments`方法获取数据，该方法简单地返回一个评论数组。`CommentService`类也被装饰了；这不是必需的，除非类有待解决的依赖关系。尽管如此，良好的实践要求我们始终使用`Injectable`进行装饰，以知道一个类是一个服务。

回到我们的列表组件，我们只需导入类，从构造函数中解析依赖项以创建服务类的实例，然后用`getComments`的返回值填充属性：

```ts
import { Component, OnInit } from '@angular/core';
import { CommentService } from '../comment.service';

@Component({
 selector: 'app-comment-list',
 templateUrl: './comment-list.component.html',
 styleUrls: ['./comment-list.component.css']
})
export class CommentListComponent implements OnInit {
 private comments: Array<any>;
 constructor(
 private commentService: CommentService
 ) { }

 ngOnInit() {
 this.comments = this.commentService.getComments();
 }

}
```

让我们尝试在浏览器中运行应用程序，看看当前的更改是否仍然按预期工作：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/8e3c6caa-3823-455d-9791-2546bf4e64f0.png)

该死，不行！它刚刚爆炸了。出了什么问题？错误消息显示没有为 CommentService 提供程序！

请记住，当我们使用`ng`CLI 命令脚手架组件时，CLI 不仅会创建一个组件，还会将其添加到`ngModule`装饰器的声明数组中：

```ts
// ./src/app/app.module.ts
declarations: [
 AppComponent,
 // New scaffolded component here
 CommentListComponent
 ],
```

模块需要知道哪些组件和服务属于它们的成员。这就是为什么组件会自动添加给你的原因。但是对于服务来说情况并不相同，因为当你通过 CLI 工具创建服务类时，CLI 不会自动更新模块（它会在脚手架期间警告你）。我们需要通过`providers`数组手动添加服务：

```ts
import { CommentService } from './comment.service';
//...

@NgModule({
 //...
 providers: [
 CommentService
 ],
})
export class AppModule { }
```

现在再次运行应用程序，看看我们的服务现在如何驱动应用程序，控制台中不再有错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/b6d2e1c8-27d6-4690-ad1e-ba2f1c79e877.png)

如果需要操作数据，则必须在服务中进行，而不是在组件中进行。假设您想通过双击列表中的每个项目来删除评论，那么在组件中接收事件是可以的，但实际的删除操作应该由服务处理。

首先为列表项添加事件监听器：

```ts
<a href="#" class="list-group-item" (dblclick)="removeComment(comment)" *ngFor="let comment of comments">
 <h4 class="list-group-item-heading">{{comment.author}}</h4>
 <p class="list-group-item-text">{{comment.content}}</p>
 </a>
```

`dblclick`事件是通过双击项目触发的。当这种情况发生时，我们调用`removeComment`方法，同时传递我们想要从项目中删除的评论。

这是组件中`removeComment`的样子：

```ts
removeComment(comment) {
 this.comments = this.commentService.removeComment(comment);
}
```

正如你所看到的，它除了调用服务上的一个方法之外，什么也不做，该方法也被称为`removeComment`。这个方法实际上负责从评论数组中删除项目：

```ts
// Comment service
removeComment(removableComment) {
 // find the index of the comment
 const index = this.comments.findIndex(
 comment => comment.author === removableComment.author
 );
 // remove the comment from the array
 this.comments.splice(index, 1);
 // return the new array
 return this.comments;
 }
```

# 组件与服务的交互

这是服务的一个非常方便的用例。在第六章中，*使用 TypeScript 进行组件组合*，我们讨论了组件如何相互交互，并展示了不同的方法。其中一种方法被遗漏了--使用服务作为不同组件的事件中心/通信平台。

再假设，当列表中的项目被点击时，我们使用评论列表组件的兄弟组件来显示所选评论的详细视图。首先，我们需要创建这个组件：

```ts
ng g component comment-detail
```

然后，您可以更新`app.component.html`文件以显示添加的组件：

```ts
<div class="container">
 <h2 class="text-center">TS Comments</h2>
 <div class="col-md-4 col-md-offset-2">
 <app-comment-list></app-comment-list>
 </div>
 <div class="col-md-4">
 <!-- Comment detail component -->
 <app-comment-detail></app-comment-detail>
 </div>
</div>

```

现在，我们需要定义我们的组件做什么，因为它现在是空的。但在此之前，让我们更新评论服务，使其也作为列表组件和兄弟详细组件之间的中心：

```ts
import { Injectable } from '@angular/core';
import { Subject } from 'rxjs/Subject';

@Injectable()
export class CommentService {
 private commentSelectedSource = new Subject<any>();
 public commentSelected$ = this.commentSelectedSource.asObservable();

 private comments: Array<any> = [
 // ...
 ];

 // ...

 showComment(comment) {
 this.commentSelectedSource.next(comment);
 }
}
```

现在，服务使用 Rx 主题来创建一个流和一个监听器，通过它传递和获取所选评论。`commentSelectedSource`对象负责在点击评论时向流中添加评论。`commetSelected$`对象是一个我们可以订阅并在点击此评论时执行操作的可观察对象。

现在，立即返回到您的组件，并添加一个点击事件来选择评论项：

```ts
<div class="list-group">
 <a href="#" class="list-group-item" 
 (dblclick)="removeComment(comment)" 
 *ngFor="let comment of comments"
 (click)="showComment(comment)"
 >
 <h4 class="list-group-item-heading">{{comment.author}}</h4>
 <p class="list-group-item-text">{{comment.content}}</p>
 </a>
</div>
```

点击事件触发组件上的`showComment`方法，然后调用服务上的`showComment`：

```ts
showComment(comment) {
 this.commentService.showComment(comment);
}
```

我们仍然需要更新评论详细组件，以便订阅我们在类中创建的可观察对象：

```ts
import { Component, OnInit } from '@angular/core';
import { CommentService } from '../comment.service';

@Component({
 selector: 'app-comment-detail',
 templateUrl: './comment-detail.component.html',
 styleUrls: ['./comment-detail.component.css']
})
export class CommentDetailComponent implements OnInit {

 comment: any = {
 author: '',
 content: ''
 };
 constructor(
 private commentService: CommentService
 ) { }

 ngOnInit() {
 this.commentService.commentSelected$.subscribe(comment => {
 this.comment = comment;
 })
 }

}
```

通过`ngOnInit`生命周期钩子，我们能够在组件准备就绪后创建对可观察对象的订阅。有一个评论属性将绑定到视图，这个属性通过订阅在每次点击评论项时更新。以下是显示所选评论的组件的模板：

```ts
<div class="panel panel-default" *ngIf="comment.author">
 <div class="panel-heading">{{comment.author}}</div>
 <div class="panel-body">
 {{comment.content}}
 </div>
</div>
```

您可以重新启动应用程序并尝试选择评论。您应该看到以下行为：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/48b9955d-ace1-4e62-9f8a-3a88ab63ddef.png)

# 服务作为实用工具

除了管理状态和组件交互之外，服务还以处理实用操作而闻名。假设我们想要在评论应用中开始收集新评论。我们对表单还不太了解，所以我们可以使用浏览器的提示框。我们期望用户通过提示框中的同一文本框传递用户名和内容，如下所示：

```ts
<username>: <comment content>
```

因此，我们需要一个实用方法来从文本框中提取这些部分，形成一个具有作者和内容属性的评论对象。让我们从评论列表组件中收集信息开始：

```ts
showPrompt() {
 const commentString = window.prompt('Please enter your username and content: ', 'username: content');
 const parsedComment = this.commentService.parseComment(commentString);
 this.commentService.addComment(parsedComment);
 }
```

`showPrompt()`方法用于收集用户输入，并将输入传递给服务中的`parseComment`方法。这个方法是一个实用方法的例子，我们很快会实现它。我们还将实现`addComment`方法，该方法将使用解析后的评论来更新评论列表。接下来，在视图中添加一个按钮，并添加一个点击事件监听器来触发`showPrompt`：

```ts
<button class="btn btn-primary" 
 (click)="showPrompt()"
>Add Comment</button>
```

将这两种方法添加到评论服务中：

```ts
parseComment(commentString) {
 const commentArr = commentString.split(':');
 const comment = {
 author: commentArr[0].trim(),
 content: commentArr[1].trim()
 }
 return comment;
 }

 addComment(comment) {
 this.comments.unshift(comment);
 }
```

`parseComment`方法接受一个字符串，拆分字符串，并获取评论的作者和内容。然后返回评论。`addComment`方法接受一个评论并将其添加到现有评论列表中。

现在，您可以开始添加新评论，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/31cc7b09-e373-4aa9-9fa7-f4ef30bd706d.png)

# 摘要

本章介绍了数据抽象中许多有趣的概念，同时利用了依赖注入的强大功能。您学会了组件如何使用服务作为中心相互交互，数据和逻辑如何从组件中抽象到服务中，以及如何在服务中处理可重用的实用代码以保持应用程序的清晰。在下一章中，您将学习 Angular 中表单和 DOM 事件的实际方法。


# 第八章：使用 TypeScript 进行更好的表单和事件处理

让我们谈谈表单。自本书开始以来，我们一直在避免在示例中使用表单输入。这是因为我想把整个章节都专门用于表单。我们将涵盖尽可能多的内容，以构建收集用户信息的业务应用程序。以下是您可以从本章中期待的内容：

+   类型化表单输入和输出

+   表单控件

+   验证

+   表单提交和处理

+   事件处理

+   控件状态

# 为表单创建类型

我们希望尽可能地利用 TypeScript，因为它简化了我们的开发过程，并使我们的应用行为更可预测。因此，我们将创建一个简单的数据类作为表单值的类型。

首先，创建一个新的 Angular 项目来跟随示例。然后，使用以下命令创建一个新的类：

```ts
ng g class flight
```

该类在`app`文件夹中生成；用以下数据类替换其内容：

```ts
export class Flight {
 constructor(
 public fullName: string,
 public from: string,
 public to: string,
 public type: string,
 public adults: number,
 public departure: Date,
 public children?: number,
 public infants?: number,
 public arrival?: Date,
 ) {}
}
```

这个类代表了我们的表单（尚未创建）将拥有的所有值。以问号（`?`）结尾的属性是可选的，这意味着当相应的值未提供时，TypeScript 不会抛出错误。

在着手创建表单之前，让我们从一张干净的纸开始。用以下内容替换`app.component.html`文件：

```ts
<div class="container">
 <h3 class="text-center">Book a Flight</h3>
 <div class="col-md-offset-3 col-md-6">
 <!-- TODO: Form here -->
 </div>
</div>
```

运行应用并让其保持运行状态。您应该在本地主机的端口`4200`看到以下内容（记得包括 Bootstrap）：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/61c38bbd-b40e-433e-9ebd-75b6eed4d0a9.png)

# 表单模块

现在我们有了一个我们希望表单遵循的约定，让我们现在生成表单的组件：

```ts
ng  g component flight-form
```

该命令还将该组件作为声明添加到我们的`App`模块中：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';
import { FlightFormComponent } from './flight-form/flight-form.component';

@NgModule({
 declarations: [
 AppComponent,
 // Component added after
 // being generated
 FlightFormComponent
 ],
 imports: [
 BrowserModule
 ],
 providers: [],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

Angular 表单的特殊之处和易用性在于提供了开箱即用的功能，比如`NgForm`指令。这些功能不在核心浏览器模块中，而在表单模块中。因此，我们需要导入它们：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

// Import the form module
import { FormsModule } from '@angular/forms';

import { AppComponent } from './app.component';
import { FlightFormComponent } from './flight-form/flight-form.component';

@NgModule({
 declarations: [
 AppComponent,
 FlightFormComponent
 ],
 imports: [
 BrowserModule,
 // Add the form module 
 // to imports array
 FormsModule
 ],
 providers: [],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

只需导入并将`FormModule`添加到`imports`数组中即可。

# 双向绑定

现在是在浏览器中使用表单组件显示一些表单控件的完美时机。在数据层（模型）和视图之间保持状态同步可能非常具有挑战性，但是使用 Angular 只需要使用`FormModule`中暴露的一个指令：

```ts
<!-- ./app/flight-form/flight-form.component.html -->
<form>
 <div class="form-group">
 <label for="fullName">Full Name</label>
 <input 
 type="text" 
 class="form-control" 
 [(ngModel)]="flightModel.fullName"
 name="fullName"
 >
 </div>
</form>
```

Angular 依赖于内部的`name`属性来进行绑定。因此，`name`属性是必需的。

注意`[(ngModel)]="flightModel.fullName"`；它试图将组件类上的属性绑定到表单。这个模型将是我们之前创建的`Flight`类型的类：

```ts
// ./app/flight-form/flight-form.component.ts

import { Component, OnInit } from '@angular/core';
import { Flight } from '../flight';

@Component({
 selector: 'app-flight-form',
 templateUrl: './flight-form.component.html',
 styleUrls: ['./flight-form.component.css']
})
export class FlightFormComponent implements OnInit {
 flightModel: Flight;
 constructor() {
 this.flightModel = new Flight('', '', '', '', 0, '', 0, 0, '');
 }

 ngOnInit() {}
}
```

`flightModel`属性被添加到组件中作为`Flight`类型，并用一些默认值进行初始化。

将组件包含在应用 HTML 中，以便在浏览器中显示：

```ts
<div class="container">
 <h3 class="text-center">Book a Flight</h3>
 <div class="col-md-offset-3 col-md-6">
 <app-flight-form></app-flight-form>
 </div>
</div>
```

这是你在浏览器中应该看到的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/7632cd3a-a1e3-4da8-b126-17290af51232.png)

看到双向绑定的实际效果，使用插值来显示`flightModel.fullName`的值。然后，输入一个值并查看实时更新：

```ts
<form>
 <div class="form-group">
 <label for="fullName">Full Name</label>
 <input 
 type="text" 
 class="form-control" 
 [(ngModel)]="flightModel.fullName"
 name="fullName"
 >
 {{flightModel.fullName}}
 </div>
</form>
```

这是它的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/26ef4055-66f5-4517-85ff-3f2508be6682.png)

# 更多表单字段

让我们动手添加剩下的表单字段。毕竟，我们不能只提供我们的名字就预订航班。

`from`和`to`字段将是*选择框*，其中包含我们可以飞往和飞出的城市列表。这个城市列表将直接存储在我们的组件类中，然后我们可以在模板中对其进行迭代，并将其呈现为选择框：

```ts
export class FlightFormComponent implements OnInit {
 flightModel: Flight;
 // Array of cities
 cities:Array<string> = [
 'Lagos',
 'Mumbai',
 'New York',
 'London',
 'Nairobi'
 ];
 constructor() {
 this.flightModel = new Flight('', '', '', '', 0, '', 0, 0, '');
 }
}
```

数组以字符串形式存储了世界各地的一些城市。现在让我们使用`ngFor`指令来迭代这些城市，并在表单中使用选择框显示它们：

```ts
<div class="row">
 <div class="col-md-6">
 <label for="from">From</label>
 <select type="text" id="from" class="form-control" [(ngModel)]="flightModel.from" name="from">
 <option *ngFor="let city of cities" value="{{city}}">{{city}}</option>
 </select>
 </div>
 <div class="col-md-6">
 <label for="to">To</label>
 <select type="text" id="to" class="form-control" [(ngModel)]="flightModel.to" name="to">
 <option *ngFor="let city of cities" value="{{city}}">{{city}}</option>
 </select>
 </div>
 </div>
```

整洁！您可以打开浏览器，就在那里看到它：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/cc07e8d4-009d-479f-ab6d-e598fdbd6b3b.png)

当点击选择下拉菜单时，会显示一个预期的城市列表：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/74a07788-3491-415c-8cea-90ed0bd340ea.png)

接下来，让我们添加行程类型字段（单选按钮）、出发日期字段（日期控件）和到达日期字段（日期控件）：

```ts
<div class="row" style="margin-top: 15px">
 <div class="col-md-5">
 <label for="" style="display: block">Trip Type</label>
 <label class="radio-inline">
 <input type="radio" name="type" [(ngModel)]="flightModel.type" value="One Way"> One way
 </label>
 <label class="radio-inline">
 <input type="radio" name="type" [(ngModel)]="flightModel.type" value="Return"> Return
 </label>
 </div>
 <div class="col-md-4">
 <label for="departure">Departure</label>
 <input type="date" id="departure" class="form-control" [(ngModel)]="flightModel.departure" name="departure">
 </div>
 <div class="col-md-3">
 <label for="arrival">Arrival</label>
 <input type="date" id="arrival" class="form-control" [(ngModel)]="flightModel.arrival" name="arrival">
 </div>
 </div>
```

数据如何绑定到控件与我们之前创建的文本和选择字段非常相似。主要区别在于控件的类型（单选按钮和日期）：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/93d3b746-b068-4e0b-9337-ac684ef5d492.png)

最后，添加乘客数量（成人、儿童和婴儿）：

```ts
<div class="row" style="margin-top: 15px">
 <div class="col-md-4">
 <label for="adults">Adults</label>
 <input type="number" id="adults" class="form-control" [(ngModel)]="flightModel.adults" name="adults">
 </div>
 <div class="col-md-4">
 <label for="children">Children</label>
 <input type="number" id="children" class="form-control" [(ngModel)]="flightModel.children" name="children">
 </div>
 <div class="col-md-4">
 <label for="infants">Infants</label>
 <input type="number" id="infants" class="form-control" [(ngModel)]="flightModel.infants" name="infants">
 </div>
 </div>
```

乘客部分都是数字类型，因为我们只需要选择每个类别上船的乘客数量：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/4f24bb9e-6103-4069-8780-86979a25aa23.png)

# 验证表单和表单字段

Angular 通过使用其内置指令和状态属性大大简化了表单验证。您可以使用状态属性来检查表单字段是否已被触摸。如果它被触摸但违反了验证规则，您可以使用`ngIf`指令来显示相关错误。

让我们看一个验证全名字段的例子：

```ts
<div class="form-group">
 <label for="fullName">Full Name</label>
 <input 
 type="text" 
 id="fullName" 
 class="form-control" 
 [(ngModel)]="flightModel.fullName" 
 name="fullName"

 #name="ngModel"
 required
 minlength="6">
 </div>
```

我们刚刚为表单的全名字段添加了三个额外的重要属性：`#name`，`required`和`minlength`。`#name`属性与`name`属性完全不同，前者是一个模板变量，通过`ngModel`值保存有关此给定字段的信息，而后者是通常的表单输入名称属性。

在 Angular 中，验证规则被传递为属性，这就是为什么`required`和`minlength`在那里的原因。

是的，字段已经验证，但用户没有得到任何反馈，不知道出了什么问题。让我们添加一些错误消息，以便在表单字段违反时显示：

```ts
<div *ngIf="name.invalid && (name.dirty || name.touched)" class="text-danger">
 <div *ngIf="name.errors.required">
 Name is required.
 </div>
 <div *ngIf="name.errors.minlength">
 Name must be at least 6 characters long.
 </div>
 </div>
```

`ngIf`指令有条件地显示这些`div`元素：

+   如果表单字段已被触摸但没有值，则会显示“名称是必需的”错误

+   当字段被触摸但内容长度小于*6*时，也会显示“名称必须至少为 6 个字符长”。

以下两个屏幕截图显示了浏览器中的这些错误输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/24770a2a-1b0f-4039-926b-abccb82b063a.png)

当输入一个值但值的文本计数不到 6 时，会显示不同的错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/46db1233-a42c-45db-9ae2-739fb0952514.png)

# 提交表单

在提交表单之前，我们需要考虑一些因素：

+   表单是否有效？

+   在提交之前是否有表单处理程序？

为了确保表单有效，我们可以禁用提交按钮：

```ts
<form #flightForm="ngForm">
 <div class="form-group" style="margin-top: 15px">
 <button class="btn btn-primary btn-block" [disabled]="!flightForm.form.valid">
 Submit
 </button>
 </div>
</form>
```

首先，我们向表单添加一个模板变量称为`flightForm`，然后使用该变量来检查表单是否有效。如果表单无效，我们将禁用按钮的点击：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/99a2e768-93a1-436b-a474-ba333e7fb8ba.png)

要处理提交，向表单添加一个`ngSubmit`事件。当点击按钮时，将调用此事件：

```ts
<form #flightForm="ngForm" (ngSubmit)="handleSubmit()">
 ...
</form>
```

现在，您可以添加一个类方法`handleSubmit`来处理表单提交。对于这个例子来说，简单的控制台日志可能就足够了：

```ts
export class FlightFormComponent implements OnInit {
 flightModel: Flight;
 cities:Array<string> = [
 ...
 ];
 constructor() {
 this.flightModel = new Flight('', '', '', '', 0, '', 0, 0, '');
 }

 // Handle for submission
 handleSubmit() {
 console.log(this.flightModel);
 }
}
```

# 处理事件

表单不是我们从用户那里接收值的唯一方式。简单的 DOM 交互、鼠标点击和键盘交互可能引发事件，这些事件可能导致用户的请求。当然，我们必须以某种方式处理他们的请求。有许多事件我们无法在本书中讨论。我们可以看一下基本的键盘和鼠标事件。

# 鼠标事件

为了演示两种常见的鼠标事件，单击和双击，创建一个新的 Angular 项目，然后添加以下自动生成的 `app.component.html`：

```ts
<div class="container">
 <div class="row">
 <h3 class="text-center">
 {{counter}}
 </h3>
 <div class="buttons">
 <div class="btn btn-primary">
 Increment
 </div>
 <div class="btn btn-danger">
 Decrement
 </div>
 </div>
 </div>
</div>
```

`counter` 属性通过插值和增量和减量按钮绑定到视图。该属性在应用程序组件上可用，并初始化为零：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})
export class AppComponent {
 counter = 0;
}
```

以下基本上是它的外观：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/b3831e47-a5b0-41ec-a37c-f9d5894d0061.png)

单击按钮完全没有任何作用。让我们为增量按钮添加一个点击事件，这样每次单击时它都会将 1 添加到计数器属性中：

```ts
export class AppComponent {
 counter = 0;
 increment() {
 this.counter++
 }
}
```

我们需要将此事件处理程序绑定到模板中的按钮，以便在单击按钮时实际增加计数器：

```ts
<div class="btn btn-primary" (click)="increment()">
 Increment
</div>
```

事件通过属性绑定到模板，但将属性包装在括号中。属性值成为组件类上将充当事件处理程序的方法。

我们需要为减量添加相同的功能。假设减量是您希望确保用户打算执行的操作，您可以附加双击事件：

```ts
<div class="btn btn-danger" (dblclick)="decrement()">
 Decrement
</div>
```

如您所见，我们使用 `dblclick` 事件而不是 `click`，然后将减量事件处理程序绑定到它。处理程序只是增量处理程序的反向，同时检查我们是否已经达到零：

```ts
decrement() {
 this.counter <= 0 ? (this.counter = 0) : this.counter--;
}
```

以下显示了新事件的执行情况：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/0afbe16e-d007-41f3-a927-ffd0c386fa24.png)

# 键盘事件

您可以通过监听各种键盘事件来跟踪键盘交互。`keypress` 事件告诉您按钮被点击；如果您附加了监听器，监听器将被触发。您可以以与附加鼠标事件相同的方式附加键盘事件：

```ts
<div class="container" (keypress)="showKey($event)" tabindex="1">
 ...
 <div class="key-bg" *ngIf="keyPressed">
 <h1>{{key}}</h1>
 </div>
<div>
```

具有 `key-bg` 类的元素在按下键时显示；它显示我们按下的确切键，该键保存在 `key` 属性中。`keyPressed` 属性是一个布尔值，当按下键时我们将其设置为 `true`。

事件触发 `showKey` 监听器；让我们实现它：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})
export class AppComponent {
 keyPressed = false;
 key = '';
 // ....
 showKey($event) {
 this.keyPressed = true;
 this.key = $event.key.toUpperCase();
 setTimeout(() => {
 this.keyPressed = false;
 }, 500)
 }
}
```

`showKey` 处理程序执行以下操作：

+   它使用按下的键的值设置了 `key` 属性

+   按下的键被表示为小写字符串，因此我们使用 `toUpperCase` 方法将其转换为大写

+   `keyPressed` 属性设置为 `true`，因此显示按下的键，然后在 500 毫秒后设置为 `false`，因此显示的键被隐藏

当您按下键时（并且 `container` div 获得焦点），以下屏幕截图显示了发生了什么：

>![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/865639ab-db68-4952-b736-2ee817c0ecc6.png)

# 总结

你现在对通过表单或事件收集用户输入有了很多知识。我们还涵盖了表单的重要特性，如输入类型、验证、双向绑定、提交等。我们看到的事件示例涵盖了鼠标和键盘事件以及如何处理它们。所有这些有趣的经历都为你构建业务应用程序做好了准备。


# 第九章：使用 TypeScript 编写模块、指令和管道

模块化对于构建大型软件系统至关重要，Angular 项目也不例外。当我们的应用开始增长时，在一个入口模块中管理其不同成员变得非常困难和混乱。当你有很多服务、指令和管道时，情况变得更具挑战性。说到指令和管道，我们将花一些时间在本章讨论它们的用例和示例，同时在模块中更好地管理我们的应用程序。

# 指令

DOM 操作并不总是最好在组件中处理。组件应该尽可能精简；这样，事情就会变得简单，你的代码可以轻松地移动和重用。那么，我们应该在哪里处理 DOM 操作呢？答案是指令。就像你应该将数据操作任务交给服务一样，最佳实践建议你将繁重的 DOM 操作交给指令。

Angular 中有三种指令类型：

+   组件

+   属性指令

+   结构指令

是的，组件！组件是合格的指令。它们是具有直接访问被操作的模板的指令。我们在本书中已经看到了足够多的组件；让我们专注于属性和结构指令。

# 属性指令

这类指令以为 DOM 添加行为特性而闻名，但不会删除或添加任何 DOM 内容。诸如改变外观、显示或隐藏元素、操作元素属性等等。

为了更好地理解属性指令，让我们构建一些应用于组件模板的 UI 指令。这些指令将在应用时改变 DOM 的行为。

在一个新项目中使用以下命令创建一个新的指令：

```ts
ng generate directive ui-button
```

这将在应用程序文件夹中创建一个空指令，内容如下：

```ts
import { Directive } from '@angular/core';

@Directive({
 selector: '[appUiButton]'
})
export class UiButtonDirective {
 constructor() {}
}
```

`Directive`装饰器首先从`@angular/core`模块中导入。该装饰器用于任何预期充当指令的类。就像组件上的装饰器一样，指令装饰器接受一个具有选择器属性的对象。当这个选择器应用到 DOM 时，指令的行为就会展现出来。

在这个例子中，我们试图实现的行为是用一个属性来为一个完全未经样式处理的按钮添加样式。假设我们在我们的应用组件中有以下按钮：

```ts
<div class="container">
 <button>Click!!</button>
</div>
```

这只是屏幕上的一个简单无聊的按钮：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/4c27b9ac-8bbe-47d1-8d4c-fc4668eefec0.png)

要使用我们刚刚创建的属性指令，将其作为*无值*属性添加到按钮中：

```ts
<button appUiButton>Click!!</button>
```

接下来，找到一种方法来从`directive`类中访问按钮元素。我们需要这种访问权限来能够直接从类中应用样式到按钮上。感谢`ElementRef`类，通过构造函数注入到指令中，它给了我们访问原生元素的权限，这就是按钮元素可以被访问的地方：

```ts
import { Directive, ElementRef } from '@angular/core';

@Directive({
 selector: '[appUiButton]'
})
export class UiButtonDirective {
 constructor(el: ElementRef) {

 }
}
```

它被注入并解析为`el`属性。我们可以从该属性访问按钮元素：

```ts
import { Directive, ElementRef } from '@angular/core';

@Directive({
 selector: '[appUiButton]'
})
export class UiButtonDirective {
 constructor(el: ElementRef) {
 el.nativeElement.style.backgroundColor = '#ff00a6';
 }
}
```

`nativeElement`属性让你可以访问应用属性指令的元素。然后你可以像处理 DOM API 一样处理这个值，这就是为什么我们可以访问`style`和`backgroundColor`属性：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/7cd2e5f0-0729-4fff-968a-b6968f9e5506.png)

你可以看到粉色背景已经有效应用。让我们通过指令为按钮添加更多样式，使其更有趣：

```ts
import { Directive, ElementRef } from '@angular/core';

@Directive({
 selector: '[appUiButton]'
})
export class UiButtonDirective {
 constructor(el: ElementRef) {
 Object.assign(el.nativeElement.style, {
 backgroundColor: '#ff00a6',
 padding: '7px 15px',
 fontSize: '16px',
 color: '#fff',
 border: 'none',
 borderRadius: '4px'
 })
 }
}
```

我们不再使用多个点来设置值，而是使用`Object.assign`方法来减少我们需要编写的代码量。现在，我们在浏览器中有一个更漂亮的按钮，完全由指令进行样式设置：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/fef31767-c6f0-4eb3-ae1b-ab8a2f6942bd.png)

# 在指令中处理事件

指令非常灵活，可以根据用户触发的事件应用不同的状态。例如，我们可以为按钮添加一个悬停行为，当鼠标光标移动到按钮上时，按钮会应用不同的颜色（比如黑色）：

```ts
import { 
 Directive, 
 ElementRef, 
 HostListener } from '@angular/core';

@Directive({
 selector: '[appUiButton]'
})
export class UiButtonDirective {
 constructor(private el: ElementRef) {
 Object.assign(el.nativeElement.style, {
 backgroundColor: '#ff00a6',
 ...
 })
 }

 @HostListener('mouseenter') onMouseEnter() {
 this.el.nativeElement.style.backgroundColor = '#000';
 }

 @HostListener('mouseleave') onMouseLeave() {
 this.el.nativeElement.style.backgroundColor = '#ff00a6';
 }
}
```

我们在这个文件中引入了一些成员：

+   我们导入了`HostListener`，这是一个装饰器，可以扩展类中的方法。它将方法转换为附加到原生元素的事件监听器。装饰器接受事件类型的参数。

+   我们在`onMouseEnter`和`onMouseLeave`上定义了两种方法，然后用`HostListener`装饰这些方法。这些方法在悬停发生时改变按钮的背景颜色。

当我们将鼠标悬停在按钮上时，行为看起来像这样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/8495e131-6c3b-4e47-8bf6-619d6415048c.png)

# 动态属性指令

如果我们，作为这个指令的作者，是最终的使用者呢？如果另一个开发人员将指令作为 API 进行重用呢？我们如何使它具有足够的灵活性来处理动态值？当你在编写指令时问自己这些问题时，就是使其动态化的时候了。

一直以来，我们一直在使用指令而没有任何值。实际上，我们可以使用属性值将输入传递到指令中：

```ts
<button appUiButton bgColor="red">Click!!</button>
```

我们添加了一个新属性`bgColor`，它不是一个指令，而是一个输入属性。该属性用于将动态值发送到指令，如下所示：

```ts
import { 
 Directive, 
 ElementRef, 
 HostListener, 
 Input,
 OnInit } from '@angular/core';

@Directive({
 selector: '[appUiButton]'
})
export class UiButtonDirective implements OnInit {
 @Input() bgColor: string;
 @Input() hoverBgColor: string;
 constructor(private el: ElementRef) {}

 ngOnInit() {
 Object.assign(this.el.nativeElement.style, {
 backgroundColor: this.bgColor || '#ff00a6',
 padding: '7px 15px',
 fontSize: '16px',
 color: '#fff',
 border: 'none',
 borderRadius: '4px'
 })
 }

 @HostListener('mouseenter') onMouseEnter() {
 console.log(this.bgColor);
 this.el.nativeElement.style.backgroundColor = this.hoverBgColor || '#000';
 }

 @HostListener('mouseleave') onMouseLeave() {
 this.el.nativeElement.style.backgroundColor = this.bgColor || '#ff00a6';
 }
}
```

以下是我们引入的更改：

+   引入了两个`Input`装饰的属性--`bgColor`和`bgHoverColor`--用作从模板到指令的动态值流。

+   该指令的设置从构造函数移至`ngOnInit`方法。这是因为 Angular 的变更检测设置了输入装饰器，构造函数中不会发生这种情况，因此当我们尝试从构造函数中访问它们时，`bgColor`和`bgHoverColor`是未定义的。

+   在设置样式时，我们不是硬编码`backgroundColor`的值，而是使用通过`bgColor`接收到的值。我们还设置了一个备用值，以防开发人员忘记包含属性。

+   鼠标进入和鼠标离开事件也会发生同样的事情。

现在，按钮的外观受到动态值的影响：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/95a00373-e877-40f1-8669-cb1b1bd41e35.png)

# 结构指令

结构指令与属性指令有很多共同之处，但它们在预期行为上有很大不同。与属性指令不同，结构指令预期创建或删除 DOM 元素。这与使用 CSS 显示属性来显示或隐藏元素不同。在这种情况下，元素仍然在 DOM 树中，但在隐藏时对最终用户不可见。

一个很好的例子是`*ngIf`。当使用`*ngIf`结构指令从 DOM 中移除元素时，该指令会从屏幕上消失，并从 DOM 树中删除。

# 为什么会有这样的差异？

您控制 DOM 元素的可见性的方式可能会对应用程序的性能产生重大影响。

举个例子，您可能有一个手风琴，用户预期点击以显示更多信息。用户在查看内容后可能决定隐藏手风琴的内容，并在以后的某个时间再次打开以供参考。很明显，手风琴的内容有可能随时显示和隐藏。

在这种情况下，最好使用一个不隐藏/移除手风琴内容，而只是隐藏它的属性指令。这样在需要时显示和隐藏会非常快速。使用`*ngIf`这样的结构指令会不断地创建和销毁 DOM 树的一部分，如果被控制的 DOM 内容很庞大，这样做会非常昂贵。

另一方面，当你有一些内容，你确信用户只会查看一次或最多两次时，最好使用`*ngIf`这样的结构指令。这样，你的 DOM 就不会被大量未使用的 HTML 内容所淹没。

# 星号的作用

星号在所有结构指令之前都非常重要。如果你从它们中移除星号，`*ngIf`和`*ngFor`指令将拒绝工作，这意味着星号是必需的。因此，问题是：为什么星号必须在那里呢？

它们在 Angular 中是语法糖，意味着不必以这种方式编写。这才是它们实际上的样子：

```ts
<div template="ngIf true">
 <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Nesciunt non perspiciatis consequatur sapiente provident nemo similique. Minus quo veritatis ratione, quaerat dolores optio facilis dolor nemo, tenetur, obcaecati quibusdam, doloremque.</p>
</div>
```

这个模板属性转换成了 Angular 中的以下内容：

```ts
<ng-template [ngIf]="true">
 <div template="ngIf true">
 <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit....</p>
 </div> </ng-template>
```

看看`ngIf`现在已经成为了一个普通的 Angular 属性，但被注入到了模板中。当值为`false`时，模板会从 DOM 树中被移除（而不是隐藏）。以这种方式编写这样的指令只是一大堆代码，所以 Angular 添加了语法糖来简化我们编写`ngIf`指令的方式：

```ts
<div *ngIf="true">
 <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Nesciunt non perspiciatis consequatur sapiente provident nemo similique.</p>
</div>
```

# 创建结构指令

我们已经从之前的例子中看到了如何使用结构指令。我们如何创建它们呢？我们通过在终端中运行以下命令来创建它们：

```ts
ng generate directive when
```

是的，我们将指令命名为`when`。这个指令确实做了`*ngIf`做的事情，所以希望这样做能帮助你更好地理解你已经使用过的指令的内部工作原理。

使用以下内容更新指令：

```ts
import { 
 Directive, 
 Input, 
 TemplateRef, 
 ViewContainerRef } from '@angular/core';

@Directive({
 selector: '[appWhen]'
})
export class WhenDirective {
 constructor(
 private templateRef: TemplateRef<any>,
 private viewContainer: ViewContainerRef) { }
}
```

我们介绍了一些你还不熟悉的成员。`TemplateRef`是对我们之前看到的`ng-template`模板的引用，其中包含了我们正在控制的 DOM 内容。`ViewContainerRef`是对视图本身的引用。

在视图中使用`appWhen`指令时，它预期接受一个条件，比如`ngIf`。为了接收这样的条件，我们需要创建一个装饰过的`Input` setter 方法：

```ts
export class WhenDirective {
 private hasView = false;

 constructor(
 private templateRef: TemplateRef<any>,
 private viewContainer: ViewContainerRef) { }

 @Input() set appWhen(condition: boolean) {
 if (condition && !this.hasView) {
 this.viewContainer.createEmbeddedView(this.templateRef);
 this.hasView = true;
 } else if (!condition && this.hasView) {
 this.viewContainer.clear();
 this.hasView = false;
 }
 }
}
```

指令中的 setter 方法检查值是否解析为`true`，然后显示内容并创建视图（如果尚未创建）。当值解析为`false`时，情况将发生变化。

让我们通过单击我们在属性指令部分劳累的按钮来测试指令。单击按钮时，它会将属性切换为`true`或`false`。此属性绑定到我们创建的指令的值。

使用以下内容更新应用程序组件类：

```ts
export class AppComponent {
 toggle = false;
 updateToggle() {
 this.toggle = !this.toggle;
 }
}
```

`updateToggle`方法绑定到按钮，以便在用户单击时翻转`toggle`的值。以下是应用程序组件 HTML 的样子：

```ts
<h3 
 style="text-align:center" 
 *appWhen="toggle"
 >Hi, cute directive</h3>

<button 
 appUiButton 
 bgColor="red" 
 (click)="updateToggle()"
>Click!!</button>
```

点击按钮后，它通过将文本添加或从屏幕中移除来显示或隐藏文本：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/3ba02da5-84b0-4609-ac7e-631d82b634c4.png)

# 管道

我们还没有讨论的另一个有趣的模板功能是管道。管道允许您在模板中就地格式化模板内容。您可以在模板中编写管道来代替在组件中格式化内容。这是一个管道的完美示例：

```ts
<div class="container">
 <h2>{{0.5 | percent}}</h2>
</div>
```

在小数后添加`| percent`会将值更改为百分比表示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/8ccef630-dbac-4d8d-982b-1a1e67e5ad0e.png)

以下是使用一个案例管道的另一个示例：

```ts
<div class="container">
 <h2>{{0.5 | percent}}</h2>
 <h3>{{'this is uppercase' | uppercase}}</h3>
</div>
```

`uppercase`管道将文本字符串转换为大写。以下是前面代码示例的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/1655112a-fdf8-404c-9a96-d6063cffaf9b.png)

一些管道接受参数，这些参数有助于微调应用于某些内容的管道的行为。这样的管道的一个例子是货币管道，它接受一个参数来定义要使用哪种货币格式化内容： 

```ts
<h2>{{50.989 | currency:'EUR':true}}</h2>
```

以下屏幕截图显示了一个格式良好的值：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/41576b5a-4a7a-48cc-92e8-ef5f2995ebb4.png)

管道采用由冒号（`:`）分隔的两个参数。第一个参数是我们设置为欧元的货币。第二个参数是一个布尔值，表示显示的货币符号的类型。因为值为`true`，所以显示欧元符号。当值为`false`时，输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/10f6ee42-d0fd-4ed7-a6cd-2d9f1dd96ae2.png)

不使用符号，而是用货币代码（EUR）在值之前。

# 创建管道

我们已经了解了管道的用途和使用场景。接下来，我们需要了解如何使用 TypeScript 类来创建自定义管道。首先，运行以下命令生成一个空管道：

```ts
ng generate pipe reverse
```

然后，使用以下内容更新生成的类文件：

```ts
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
 name: 'reverse'
})
export class ReversePipe implements PipeTransform {

 transform(value: any, args?: any): any {
 return value.split('').reverse().join('');
 }

}
```

这个示例接受一个字符串并返回字符串的颠倒版本。`ReversePipe`类实现了`PipeTransform`接口，该接口定义了必须以特定签名创建的`transform`方法，如前所述。

该类使用`Pipe`装饰器进行装饰，该装饰器以配置对象作为参数。该对象必须定义一个`name`属性，该属性用作应用到模板时管道的标识符。在我们的情况下，管道的名称是`reverse`。

现在可以将自定义管道应用到模板中：

```ts
<h3>{{'watch me flip' | reverse}}</h3> 
```

当您查看示例时，文本被颠倒，现在以 p 开头，以 w 结尾：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/70355d3c-9e20-42dd-815a-7797aafa89d7.png)

# 向管道传递参数

我们已经了解了如何创建管道，但我们也知道管道需要参数。我们如何将这些参数添加到我们的自定义管道中？

由于传递给 transform 方法的可选`args`参数，生成的管道可能已经给出了上一个示例的提示：

```ts
transform(value: any, args?: any): any {
 ...
}
```

假设我们想要定义字符串的颠倒是按字母还是按单词应用，向管道用户提供这种控制的最佳方式是通过参数。以下是更新后的示例：

```ts
export class ReversePipe implements PipeTransform {

 transform(value: any, args?: any): any {
 if(args){
 return value.split(' ').reverse().join(' ');
 } else {
 return value.split('').reverse().join('');
 }
 }

}
```

当提供的参数为`true`时，我们按单词而不是字母颠倒字符串。这是通过在存在空格的地方拆分字符串来实现的，而不是空字符串。当为`false`时，我们在空字符串处拆分，这样就可以根据字母颠倒字符串。

现在我们可以在传递参数的同时使用管道：

```ts
<h2>{{'watch me flip' | reverse:true}}</h2> 
```

这是生成的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/bab69d1f-d381-4538-827e-1b9d38be6c4d.png)

# 模块

我们在本文开头提到了模块以及它们如何帮助我们组织项目。考虑到这一点，看一下这个应用模块：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';
import { UiButtonDirective } from './ui-button.directive';
import { WhenDirective } from './when.directive';

@NgModule({
 declarations: [
 AppComponent,
 UiButtonDirective,
 WhenDirective
 ],
 imports: [
 BrowserModule
 ],
 providers: [],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

这是来自指令的一个模块：

```ts
examples:import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';
import { ReversePipe } from './reverse.pipe';

@NgModule({
 declarations: [
 AppComponent,
 ReversePipe
 ],
 imports: [
 BrowserModule
 ],
 providers: [],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

如果您对细节如此关注，您可能已经注意到我们在指令中从未添加`UiButtonDirective`或`WhenDirective`。在管道示例中也没有添加`ReversePipe`。这些添加是在运行`generate`命令时为所有成员自动完成的，除了服务。

对于您创建的所有成员，即组件、指令、管道和服务，您需要将它们包含在其所属的模块中。

模块（通常称为 `NgModule`）是一个用 `NgModule` 装饰器装饰的类。这个装饰器接受一个配置对象，告诉 Angular 应用中创建的成员以及它们所属的位置。

以下是不同的属性：

+   `declarations`：组件、指令和管道必须在 `declarations` 数组中定义，以便向应用程序公开它们。如果未这样做，将在控制台中记录错误，告诉您省略的成员未被识别。

+   `imports`：应用程序模块并不是唯一存在的模块。您可以拥有更小、更简单的模块，将相关任务成员组合在一起。在这种情况下，您仍然需要将较小的模块导入到应用程序模块中。这就是 `imports` 数组的作用。这些较小的模块通常被称为特性模块。特性模块也可以被导入到另一个特性模块中。

+   `providers`：如果您有抽象特定任务并需要通过依赖注入注入到应用程序中的服务，您需要在 `providers` 数组中指定这些服务。

+   `bootstrap`：`bootstrap` 数组只在入口模块中声明，通常是应用程序模块。这个数组定义了应该首先启动哪个组件，或者哪个组件作为应用程序的入口点。该值始终为 `AppComponent`，因为这是入口点。

# 总结

您学到了许多概念，从指令和管道到模块。您学到了不同类型的指令（属性和结构性），以及如何创建每种指令。我们还讨论了在创建管道时如何传递参数。在下一章中，我们将讨论 Angular 应用程序中的路由以及 TypeScript 扮演的重要角色。


# 第十章：SPA 的客户端路由

**单页应用程序**（**SPA**）是一个用来指代仅从一个服务器路由提供服务但具有多个客户端视图的应用程序的术语。单一服务器路由通常是默认的（`/`或`*`）。一旦加载了单一服务器路由，客户端（JavaScript）就会接管页面，并开始使用浏览器的路由机制来控制路由。

能够从 JavaScript 控制路由使开发人员能够构建更好的用户体验。本章描述了如何在 Angular 中使用 TypeScript 编写的类、指令等来实现这一点。

就像每一章一样，我们将通过实际示例来做这个。

# RouterModule

就像表单一样，Angular 在 CLI 脚手架中默认不生成路由。这是因为你可能在你正在工作的项目中不需要它。要使路由工作，你需要在需要使用它的模块中导入它：

```ts
import { RouterModule }   from '@angular/router';
```

该模块公开了一个静态的`forRoot`方法，该方法传入一个路由数组。这样做会为导入`RouterModule`的模块注册和配置这些路由。首先创建一个`routes.ts`文件在`app`文件夹中：

```ts
import { Routes } from '@angular/router';

export const routes: Routes = [
 {
 path: '',
 component: HomeComponent
 },
 {
 path: 'about',
 component: AboutComponent
 },
 {
 path: 'contact',
 component: ContactComponent
 }
];
```

`Routes`类的签名是一个数组，其中包含一个或多个对象。传入的对象应该有一个路径和一个组件属性。路径属性定义了位置，而组件属性定义了应该挂载在定义路径上的 Angular 组件。

然后你可以在`AppModule`中使用这些数组配置`RouterModule`。我们已经导入了`RouterModule`，所以让我们导入`routes`文件并在`imports`数组中配置路由：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
//Import RuterModule
import { RouterModule } from '@angular/router';

import { AppComponent } from './app.component';

//Imprt routes
import { routes } from './routes';

@NgModule({
 declarations: [
 AppComponent
 ],
 imports: [
 BrowserModule,
 // RouterModule used to
 // configure routes
 RouterModule.forRoot(routes)
 ],
 providers: [],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

这就是在 Angular 中配置路由所需的全部内容。路由的组件尚未创建，所以如果你尝试运行应用程序，你将在终端中看到相同的错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/885229f8-c052-470a-a72c-3335461f20af.jpg)

让我们使用 CLI 生成这些组件：

```ts
ng generate component home
ng generate component about
ng generate component contact
```

然后，更新路由配置以导入组件：

```ts
import { Routes } from '@angular/router';

import { ContactComponent } from './contact/contact.component';
import { AboutComponent } from './about/about.component';
import { HomeComponent } from './home/home.component';

export const routes: Routes = [
 {
 path: '',
 component: HomeComponent
 },
 {
 path: 'about',
 component: AboutComponent
 },
 {
 path: 'contact',
 component: ContactComponent
 }
];
```

再次运行应用程序，看看是否摆脱了错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/e245aa28-283f-4d3c-aad4-5d88b47d972b.jpg)

# 路由指令

我知道你迫不及待地想在浏览器中看到示例，但是如果你尝试在端口`4200`上测试应用程序，你仍然会看到`app`组件的内容。这是因为我们还没有告诉 Angular 它应该在哪里挂载路由。

Angular 公开了两个重要的路由指令：

+   **路由出口**：这定义了路由配置应该挂载的位置。这通常是单页应用程序的入口组件。

+   **路由链接**：这用于定义 Angular 路由的导航。基本上，它为锚标签添加功能，以便更好地与 Angular 应用程序中定义的路由一起工作。

让我们替换应用组件模板的内容以利用路由指令：

```ts
<div>
 <nav class="navbar navbar-inverse">
 <div class="container-fluid">
 <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
 <ul class="nav navbar-nav">
 <li><a routerLink="/">Home</a></li>
 <li><a routerLink="/about">About</a></li>
 <li><a routerLink="/contact">Contact</a></li>
 </ul>
 </div>
 </div>
 </nav>
 <div class="container">
 <router-outlet></router-outlet>
 </div>
</div>
```

具有`container`类的 div 是每个组件在我们访问相应路由时将显示的位置。我们可以通过点击具有`routerLink`指令的锚标签来浏览每个路由。

打开浏览器，访问端口`4200`的本地主机。您应该默认看到主页：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/62a7adaf-1178-4a2a-853b-8436fc3952b2.png)

尝试在导航栏中点击“关于”或“联系”链接。如果您按照所有步骤操作，您应该看到应用程序用“关于”或“联系”组件替换主页组件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/aae21ff1-f2b3-4455-8fc0-cdc6d4ead19a.png)

注意地址栏也会随着我们在配置中定义的路径位置更新：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/37d9804c-b80b-4f61-932a-e1694552599f.png)

# 带有路由的主细节视图

一个非常常见的 UI 模式是有一个项目列表，但关于项目的信息不多。当选择项目、点击或发生鼠标悬停时，会显示每个项目的详细信息。

每个项目通常被称为主项目，而与项目交互后显示的内容被称为子项目或详细信息。

让我们构建一个简单的博客，在主页上显示文章列表，当点击每篇文章时，会显示文章页面，您可以阅读所选文章。

# 数据源

对于一个基本的例子，我们不需要数据库或服务器。一个包含博客文章的简单 JSON 文件就足够了。在您的`app`文件夹中创建一个名为`db.json`的文件，结构如下：

```ts
[
 {
 "imageId": "jorge-vasconez-364878_me6ao9",
 "collector": "John Brian",
 "description": "Yikes invaluably thorough hello more some that neglectfully on badger crud inside mallard thus crud wildebeest pending much because therefore hippopotamus disbanded much."
 },
 {
 "imageId": "wynand-van-poortvliet-364366_gsvyby",
 "collector": "Nnaemeka Ogbonnaya",
 "description": "Inimically kookaburra furrowed impala jeering porcupine flaunting across following raccoon that woolly less gosh weirdly more fiendishly ahead magnificent calmly manta wow racy brought rabbit otter quiet wretched less brusquely wow inflexible abandoned jeepers."
 },
 {
 "imageId": "josef-reckziegel-361544_qwxzuw",
 "collector": "Ola Oluwa",
 "description": "A together cowered the spacious much darn sorely punctiliously hence much less belched goodness however poutingly wow darn fed thought stretched this affectingly more outside waved mad ostrich erect however cuckoo thought."
 },
....
]
```

结构显示了一个帖子数组。每篇文章都有`imageID`，作者作为收集者，以及作为帖子内容的描述。

默认情况下，TypeScript 在尝试将其导入到 TypeScript 文件中时不会理解 JSON 文件。为了解决这个问题，使用以下声明定义`typings`：

```ts
// ./src/typings.d.ts
declare module "*.json" {
 const value: any;
 export default value;
}
```

# 博客服务

请记住，我们提到将应用程序的业务逻辑放在组件中是一个坏主意。尽可能地，不建议直接从组件与数据源进行交互。我们将创建一个服务类来代替我们执行相同的操作：

```ts
ng generate service blog
```

使用以下内容更新生成的空服务：

```ts
import { Injectable } from '@angular/core';
import * as rawData from './db.json';

@Injectable()
export class BlogService {
 data = <any>rawData;
 constructor() { }

 getPosts() {
 return this.data.map(post => {
 return {
 id: post.imageId,
 imageUrl: `https://res.cloudinary.com/christekh/image/upload/c_fit,q_auto,w_300/${post.imageId}`,
 author: post.collector
 }
 })
 }

 byId(id) {
 return this.data
 .filter(post => post.imageId === id)
 .map(post => {
 return {
 id: post.imageId,
 imageUrl: `https://res.cloudinary.com/christekh/image/upload/c_fit,q_auto,w_300/${post.imageId}`,
 author: post.collector,
 content: post.description
 }
 })[0]
 }

}
```

让我们谈谈服务中发生的事情：

1.  首先，我们导入了创建的数据源。

1.  接下来，我们创建了一个`getPosts`方法，该方法在转换每个帖子项后返回所有帖子。我们还使用图像 ID 生成图像 URL。这是通过将 ID 附加到 Cloudinary ([`cloudinary.com/`](https://cloudinary.com/))图像服务器 URL 来完成的。在使用它们之前，这些图像已上传到 Cloudinary。

1.  `byId`方法以 ID 作为参数，使用 filter 方法找到具有该 ID 的帖子，然后转换检索到的帖子。转换后，我们获取数组中的第一个且唯一的项目。

要公开此服务，您需要将其添加到`app`模块中的`providers`数组中：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { BlogService } from './blog.service';

@NgModule({
 declarations: [
 AppComponent
 ],
 imports: [
 BrowserModule
 ],
 providers: [
 BlogService
 ],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

# 创建路由

现在我们有了数据源和与该数据源交互的服务，是时候开始处理将使用这些数据的路由和组件了。在`app`文件夹中添加一个`routes.ts`文件，并进行以下配置：

```ts
import { Routes } from '@angular/router';

import { HomeComponent } from './home/home.component';
import { PostComponent } from './post/post.component';

export const routes: Routes = [
 {
 path: '',
 component: HomeComponent
 },
 {
 path: 'post/:id',
 component: PostComponent
 }
]
```

指向`post`的第二个路由具有一个`:id`占位符。这用于定义动态路由，这意味着传递的 ID 值可以用于控制挂载组件的行为。

创建之前导入的两个组件：

```ts
# Generate home component
ng generate component home

# Generate post component
ng generate component post
```

更新`app`模块以导入配置的路由，使用`RouterModule`：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';

import { AppComponent } from './app.component';
import { HomeComponent } from './home/home.component';
import { PostComponent } from './post/post.component';
import { BlogService } from './blog.service';
import { routes } from './routes';

@NgModule({
 declarations: [
 AppComponent,
 HomeComponent,
 PostComponent
 ],
 imports: [
 BrowserModule,
 RouterModule.forRoot(routes)
 ],
 providers: [
 BlogService
 ],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

为了挂载路由器，用以下标记替换 app 组件模板的整个内容：

```ts
<div class="wrapper">
 <router-outlet></router-outlet>
</div>
```

# 在主页组件中列出帖子

我们在主页上挂载的主页组件预期显示帖子列表。因此，它需要与博客服务进行交互。将类更新为以下内容：

```ts
import { Component, OnInit } from '@angular/core';
import { BlogService } from './../blog.service';

@Component({
 selector: 'app-home',
 templateUrl: './home.component.html',
 styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {

 public posts;
 constructor(
 private blogService: BlogService
 ) { }

 ngOnInit() {
 this.posts = this.blogService.getPosts();
 }

}
```

该组件依赖于`BlogService`类，该类在构造函数中解析。然后使用`blogService`实例获取帖子列表并将其传递给`posts`属性。该属性将绑定到视图。

为了在浏览器中显示这些帖子，我们需要遍历每个帖子并在组件模板中显示它们：

```ts
<div class="cards">
 <div class="card" *ngFor="let post of posts">
 <div class="card-content">
 <img src="{{post.imageUrl}}" alt="{{post.author}}">
 <h4>{{post.author}}</h4>
 </div>
 </div>
</div>
```

当您运行应用程序时，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/a2075f80-0926-4465-b4da-026e2b6aee94.png)

我们需要定义与文章卡片交互的行为。当点击卡片时，我们可以使用路由链接指令导航到帖子页面。但是，因为我们已经看到了，让我们使用第二个选项，即在 TypeScript 方法中定义行为。首先，添加一个事件监听器：

```ts
<div class="cards">
 <div class="card" *ngFor="let post of posts" (click)="showPost(post.id)">
 ...
 </div>
</div>
```

我们打算在点击卡片时调用 `showPost` 方法。这个方法接收被点击图片的 ID。以下是方法的实现：

```ts
import { Router } from '@angular/router';

...
export class HomeComponent implements OnInit {

 public posts;
 constructor(
 private blogService: BlogService,
 private router: Router
 ) { }

 ngOnInit() {
 this.posts = this.blogService.getPosts();
 }

 showPost(id) {
 this.router.navigate(['/post', id]);
 }

}
```

`showPost` 方法使用路由器的 `navigate` 方法来移动到新的路由位置。

# 使用帖子组件阅读文章

帖子组件只显示带有所有细节的单个帖子。为了显示这个单个帖子，它从 URL 接收参数并将参数传递给博客服务类中的 `byId` 方法：

```ts
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { BlogService } from './../blog.service';

@Component({
 selector: 'app-post',
 templateUrl: './post.component.html',
 styleUrls: ['./post.component.css']
})
export class PostComponent implements OnInit {

 public post;
 constructor(
 private route: ActivatedRoute,
 private blogService: BlogService,
 ) { }

 ngOnInit() {
 this.route.params.subscribe(params => {
 this.post = this.blogService.byId(params.id)
 console.log(this.post)
 });
 }

}
```

`ActivatedRoute` 类公开了一个 `params` 属性，它是一个 Observable。您可以订阅这个 Observable 来获取传递给给定路由的参数。我们将 `post` 属性设置为 `byId` 方法返回的过滤值。

现在，您可以在模板中显示帖子：

```ts
<div class="detail">
 <img src="{{post.imageUrl}}" alt="">
 <h2>{{post.author}}</h2>

 <p>{{post.content}}</p>
</div>
```

打开应用程序，然后单击每张卡片。它应该带您到它们各自的详细页面：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/bdddddc5-5bb8-4bb6-8faf-13ea73664895.png)

# 摘要

在 Angular 中进行路由设置非常重要，可能是你日常项目的一部分。在这种情况下，这对你来说不会是一个全新的概念。这是因为本章已经教会了你一些路由基础知识，构建导航和客户端路由，通过开发一个简单的博客系统来构建主-子视图关系。在下一章中，您将运用所学的知识来构建一个实际使用真实和托管数据的应用程序。
