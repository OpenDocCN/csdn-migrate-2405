# Angular 专家级编程（二）

> 原文：[`zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9`](https://zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 Angular CLI 生成遵循最佳实践的 Angular 应用程序

Angular CLI 是用于 Angular 的命令行界面，它可以帮助您使用遵循所有必要最佳实践的样板代码快速启动应用程序开发。通过在 Angular CLI 中执行命令，您可以为应用程序生成服务、组件、路由和管道。

在本章中，我们将涵盖以下主题：

+   介绍 Angular CLI

+   安装和设置 Angular CLI

+   为新应用程序生成代码

+   生成组件和路由

+   生成服务

+   生成指令和管道

+   创建针对各种环境的构建

+   运行应用程序的测试

+   更新 Angular CLI

# 介绍 Angular CLI

Angular CLI 是一个作为节点包可用的命令行界面。Angular CLI 是与 Angular 一起推出的，它通过为新应用程序生成样板代码并向现有应用程序添加服务、管道、组件和指令等功能，帮助您更快地开发应用程序。Angular CLI 在轻松搭建应用程序方面非常强大和方便。借助 Angular CLI 的帮助，我们可以创建、构建、测试和运行我们的应用程序，这将极大地减轻开发人员的负担。

Angular CLI 在 node 下运行，并依赖于许多包。

# 安装和设置 Angular CLI

要安装 Angular CLI，我们必须在系统中安装最新版本的 node 和 npm。确保所需的包已经安装，并开始全局安装 Angular CLI。最低要求的 npm 版本是 3.x.x，node 版本是 4.x.x。有时，在安装 Angular CLI 时可能会出现错误。在这种情况下，请确保您已安装了最新版本的 node.js。我们可以通过执行以下命令验证 node 的版本：

```ts
node --version

```

我们可以通过执行以下命令检查 npm 的版本：

```ts
npm --version  

```

现在，我们知道了在我们的开发机器上安装的 node 和 npm 的版本。让我们通过执行以下命令全局安装 Angular CLI：

```ts
npm install -g angular-cli 

```

Angular CLI 已安装并可全局在我们的开发机器上使用。

# 为新应用程序生成代码

现在我们已经准备好使用 Angular CLI 了。让我们为一个显示书籍列表的 Angular 应用程序生成样板代码。我们将应用程序的名称命名为`BookList`。在 node.js 命令中执行以下命令：

```ts
ng new BookList

```

此命令将创建一个名为`BookList`的文件夹，并生成样板代码，以便开始使用 Angular 应用程序。以下图显示了生成代码中组织的文件结构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/cb0c2311-7712-431d-afa5-5751739e71c5.png)

为了确保生成的代码正常工作，让我们通过执行以下命令来运行应用程序。首先通过执行此语句导航到应用程序文件夹：

```ts
cd BookList

```

然后，执行以下代码来在开发服务器中启动应用程序：

```ts
ng serve

```

现在，让我们浏览到`http://localhost:4200/`，如果生成的代码正确，浏览器将呈现以下页面的默认文本。如果出现错误，请确保防火墙没有阻止端口 4200，并且在生成样板代码时 Angular CLI 没有抛出任何错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/f8829f1e-1720-4523-a364-5b49c5c2d77d.png)

# 生成组件和路由

组件是功能、视图和样式的逻辑组合，适用于视图和与组件相关的处理这些构件的类。组件负责根据业务逻辑要求呈现视图。

我们可以使用 Angular CLI 生成组件的代码。这个工具在搭建组件时非常方便。让我们通过执行以下语句为我们的应用程序生成一个名为`booklist`的组件。通过执行以下命令导航到 Angular 项目文件夹：

```ts
cd BookList

```

然后，执行以下 Angular CLI 命令来生成组件`Booklist`：

```ts
ng generate component booklist

```

执行上述语句会创建`booklist.component.css`、`booklist.component.html`、`booklist.component.spec.ts`和`booklist.component.ts`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e3923ee1-aa83-4bde-802d-4bfd2ba9db35.png)

`booklist.component.ts`文件负责根据业务逻辑需求呈现相关视图。书籍组件生成的代码片段如下：

```ts
import { Component, OnInit } from '@angular/core';   

@Component({   
  selector: 'app-booklist',   
  templateUrl: './booklist.component.html',   
  styleUrls: ['./booklist.component.css']   
})   
export class BooklistComponent implements   OnInit {   

  constructor() { }   

  ngOnInit() {   
  }   

}   

```

请注意，`BooklistComponent`类使用`@Component`指令进行修饰，以及选择器、`templateUrl`和`styleUrls`等元数据。元数据选择器使得 Angular 在遇到`app-booklist`选择器时实例化组件`BooklistComponent`。

Angular CLI 还生成了模板文件`booklist.component.html`，内容如下。Angular 将根据组件中给定的指令解析和呈现此内容：

```ts
<p>   
  booklist works!   
</p>   

```

我们还可以在生成的文件`booklist.component.css`中添加特定于此模板的样式，组件将会应用这些样式，因为元数据`styleUrls`与`booklist.component.css`的路径进行了映射。

生成`booklist.component.spec.ts`以添加测试方法来断言`BooklistComponent`的功能。`booklist.component.spec.ts`的代码片段如下所示：

```ts
/* tslint:disable:no-unused-variable */   

import { TestBed, async } from '@angular/core/testing';   
import { BooklistComponent } from './booklist.component';   

describe('Component: Booklist', () =>   {   
  it('should create an instance', ()   => {   
    let component = new   BooklistComponent();   
    expect(component).toBeTruthy();   
  });   
});   

```

# 路由

路由指示 Angular 导航应用程序。路由使得 Angular 能够仅加载特定路由的视图，而无需重新加载整个页面或应用程序。在撰写本章时，使用 Angular CLI 生成路由被禁用，但将很快启用。

# 生成服务

服务是用户定义的类，用于解决一些目的。Angular 建议在组件中只有特定于模板的代码。组件的责任是丰富 Angular 应用程序中的 UI/UX，并将业务逻辑委托给服务。组件是服务的消费者。

我们已经有了帮助渲染`Booklist`模板的组件。现在，让我们运行一个 CLI 命令来生成一个服务，以提供书籍列表。执行以下命令生成`booklist.services.ts`和`booklist.services.spec.ts`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/859ac249-25ad-4414-bb59-2f676782f5d5.png)

生成的`booklist.service.ts`的代码片段如下所示：

```ts
import { Injectable } from '@angular/core';   

@Injectable()   
export class BooklistService {   

  constructor() { }   

}   

```

请注意，`BooklistService`被装饰为`@Injectible`，以便该书单服务将可用于组件。还有一个警告消息，服务已生成但未提供，必须提供才能使用。这意味着要使用`BooklistService`，它需要提供给将要使用它的组件。Angular 中的提供者将在第十三章中详细讨论，*应用依赖注入*。

Angular CLI 还生成了一个文件，用于编写测试方法来断言`BooklistService`，`booklist.service.spec.ts`的代码片段如下所示：

```ts
/* tslint:disable:no-unused-variable */   

import { TestBed, async, inject } from '@angular/core/testing';   
import { BooklistService } from './booklist.service';   

describe('Service: Booklist', () => {   
  beforeEach(() => {   
    TestBed.configureTestingModule({   
      providers: [BooklistService]   
    });   
  });   

  it('should ...',   inject([BooklistService], (service: 
      BooklistService) => {   
           expect(service).toBeTruthy();   
  }));   
});   

```

# 生成指令和管道

一个使用`@Directive`装饰的类来附加元数据被称为指令。它是一个渲染模板的指示或指导方针。

我们已经看到了生成组件和服务。现在，让我们使用 Angular CLI 生成指令和管道。我们将从创建一个名为 book 的指令开始。运行以下命令生成指令：

```ts
ng generate directive book       

```

执行命令的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/8dda0309-762f-45d9-9aac-17c4ec73c6f3.png)

执行此命令会分别创建两个文件，即`book.directive.spec.ts`和`book.directive.ts`。以下是`book.directive.ts`的代码片段：

```ts
import { Directive } from '@angular/core';
 @Directive({
    selector: '[appBookish]' 
   }) 
  export class BookishDirective { 
      constructor() { } 
  } 

```

`book.directive.spec.ts`的代码片段如下所示：

```ts
/* tslint:disable:no-unused-variable */ 
import { TestBed, async } from '@angular/core/testing';
import { BookDirective } from './book.directive'; 

describe('Directive: Book', () => {
   it('should create an instance', () => 
     { let directive = new BookDirective();   
        expect(directive).toBeTruthy();
    }); 
  }); 

```

# 管道

管道指示 Angular 在过滤或渲染输入数据时的操作。管道根据管道中给定的逻辑转换输入数据。

现在，让我们通过执行以下语句使用 Angular CLI 生成一个管道：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/3abd8478-f105-4d2d-9c08-c00603b70577.png)

在这里，我使用 Angular CLI 创建了一个名为`bookfilter`的管道。请注意，它还创建了一个名为`bookfilter.pipe.spec.ts`的测试文件，用于编写测试方法来断言管道。`bookfilter.pipe.ts`的代码片段如下所示：

```ts
import { Pipe, PipeTransform } from '@angular/core'; 
 @Pipe({ 
    name: 'bookfilter'
    }) 
 export class BookfilterPipe implements PipeTransform { 
        transform(value: any, args?: any): any {
    return null; 
  } 
} 

```

为测试文件`bookfilter.pipe.spec.ts`生成的代码片段如下所示：

```ts
/* tslint:disable:no-unused-variable */ 
import { TestBed, async } from '@angular/core/testing'; 
import { BookfilterPipe } from './bookfilter.pipe'; 
  describe('Pipe: Bookfilter', () => { 
   it('create an instance', () => {
         let pipe = new BookfilterPipe(); 
         expect(pipe).toBeTruthy(); 
   }); 
 }); 

```

# 创建针对各种环境的构建

使用 Angular CLI，我们还可以为应用程序创建针对各种环境的构建，例如开发和生产。应用程序将根据环境进行特定配置。例如，应用程序可以配置为在开发或暂存环境中使用暂存 API 的 URL，并在 LIVE 或生产环境中配置 API 的生产 URL。开发人员将手动根据应用程序构建的环境更新 URL 的配置。Angular 可以简化通过针对各种环境创建构建的过程。

在名为`environment.ts`的文件中维护了一个常量变量环境。此文件将帮助根据执行构建命令时传递的参数来覆盖默认值。

要使用生产文件，我们需要执行以下命令：

```ts
 ng build --env=prod 

```

此命令将使用`environment.prod.ts`中的设置。用于识别环境文件的映射在`angular-cli.json`中指定，如下所示：

```ts
"environments": { 
  "source": "environments/environment.ts", 
   "dev": "environments/environment.ts", 
   "prod": "environments/environment.prod.ts" 
  } 

```

# 为您的应用程序运行测试

在将应用程序移至生产环境之前，测试应用程序是必不可少的过程。开发人员可以编写测试来断言应用程序的行为。编写适当的测试将保护应用程序免受偏离要求的影响。

Jasmine 是一个测试框架，它方便编写测试来断言应用程序的行为，并使用 HTML 测试运行器在浏览器中执行测试。Karma 是一个测试运行器，它使开发人员能够在开发阶段同时编写单元测试。一旦构建过程完成，将使用 Karma 执行测试。Protractor 可以用于运行端到端测试，以断言应用程序的工作流程，就像最终用户的体验一样。

以下命令在应用程序中运行测试：

```ts
ng test 

```

端到端测试可以通过在此处运行命令来执行，并且只有在应用程序由命令 ng serve 提供服务时才能成功运行。这个端到端测试是由 Protractor 运行的：

```ts
ng e2e 

```

我不会详细介绍每个生成的文件的内容，因为有章节会详细解释它们。

# 更新 Angular CLI

我们可以在全局包和本地项目中更新 Angular CLI 版本。要全局更新 Angular CLI 包，请运行以下命令：

```ts
npm uninstall -g @angular/cli npm cache clean npm install -g @angular/cli@latest 

```

要在本地项目文件夹中更新 CLI，请运行此命令：

```ts
rm -rf node_modules dist # use rmdir /S/Q node_modules dist in Windows 
  Command Prompt; use rm -r -fo node_modules,dist in Windows PowerShell npm install --save-dev @angular/cli@latest npm install 

```

# 总结

那很顺利和简单，不是吗？Angular CLI 通过为 Angular 应用程序的各种构件生成样板代码，使开发人员的生活更加轻松。您开始学习强大的工具 Angular CLI 以及它如何帮助您使用样板代码启动应用程序。然后，您学会了使用 Angular 命令行界面生成组件、指令、管道、路由和服务。最后，您还了解了如何使用 Angular CLI 构建 Angular 应用程序。在下一章中，我们将讨论如何使用 Angular 组件。


# 第四章：使用组件

在本章中，我们将讨论使用 Angular 组件的不同技术和策略：

+   初始化和配置组件

+   构建组件

+   组件生命周期

+   数据共享和组件间通信

本章假设读者具有 JavaScript 和 TypeScript 编程基础以及网页开发的知识，并熟悉本书中的第一章*，* *Angular 中的架构概述和构建简单应用*的内容。本章中的所有示例都使用 TypeScript，并且也可以在 GitHub 上找到，网址为[`github.com/popalexandruvasile/mastering-angular2/tree/master/Chapter4`](https://github.com/popalexandruvasile/mastering-angular2/tree/master/Chapter4)。

一个成功的开源项目的一个明显标志是出色的文档，Angular 也不例外。我强烈建议阅读来自[`angular.io/`](https://angular.io/)的所有可用文档，并在那里跟随可用的示例。作为一个一般规则，本章中的所有示例都遵循官方文档的格式和约定，我使用了来自[`github.com/angular/quickstart`](https://github.com/angular/quickstart)的 Angular 示例种子的简化版本作为示例。如果你想要尝试或玩自己的 Angular 创作，你可以使用本章代码中`Example1`文件夹的内容作为起点。

# 组件 101

组件是 Angular 应用程序的构建块，任何这样的应用程序在执行之前都需要至少定义一个称为根组件的组件。

# 基本根组件

在 Angular 中，组件被定义为一个具有特定元数据的类，将其与 HTML 模板和类似于 jQuery 的 HTML DOM 选择器相关联：

+   组件模板可以绑定到属于组件类的任何属性或函数

+   组件选择器（类似于 jQuery 选择器）可以针对定义组件插入点的元素标签、属性或样式类进行定位。

在 Angular 应用程序中执行时，组件通常会在特定页面位置呈现 HTML 片段，可以对用户输入做出反应并显示动态数据。

组件元数据表示为 TypeScript 装饰器，并支持本章中示例中将介绍的其他配置。

`TypeScript`装饰器在第一章中有介绍，*Angular 中的架构概述和构建简单应用程序*。它们对于理解组件如何配置至关重要，并且目前已经提议成为 JavaScript 规范（ECMAScript）的一部分。

本章的第一个示例是一个基本组件，也是一个根组件（任何 Angular 应用程序都至少需要一个根组件来初始化其组件树）：

```ts
import { Component } from '@angular/core'; 
@Component({ 
    selector: 'my-app', 
    template: ` 
    <div class="container text-center"> 
      <div class="row"> 
        <div class="col-md-12"> 
          <div class="page-header"> 
            <h1>{{title}}</h1> 
          </div> 
          <p class="lead">{{description}}</p> 
        </div> 
      </div> 
      <div class="row"> 
        <div class="col-md-6"> 
          <p>A child component could go here</p> 
        </div> 
        <div class="col-md-6"> 
          <p>Another child component could go here</p> 
        </div> 
      </div>           
    </div>     
    ` 
}) 
export class AppComponent {  
  title: string; 
  description: string; 
  constructor(){ 
    this.title = 'Mastering Angular - Chapter 4, Example 1'; 
    this.description = 'This is a minimal example for an Angular 2   
    component with an element tag selector.'; 
  } 
} 

```

组件模板依赖于 Bootstrap 前端设计框架（[`getbootstrap.com/`](http://getbootstrap.com/)）进行样式设置，并且绑定到组件类的属性以检索一些显示的文本。它包含模板表达式，用于从组件类的属性中插值数据，例如`{{title}}`。

根组件使用内联模板（模板内容与其组件在同一文件中）和一个元素选择器，该选择器将在`index.html`页面中呈现组件模板，替换高亮文本：

```ts
<!DOCTYPE html> 
<html> 
  <head> 
    <title>Mastering Angular example</title> 
    ... 
  </head> 
  <body> 
    <my-app>Loading...</my-app> 
  </body> 
</html>    

```

要查看示例的实际效果，您可以在本章的源代码中的`Example1`文件夹中运行以下命令行：

```ts
npm run start  

```

您可以在下一个截图中查看呈现的组件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e1ce556c-854b-418a-9502-1e09dfb8f98b.png)

Angular 应用程序至少需要一个根模块，在`main.ts`文件中，我们正在为我们的示例引导这个模块：

```ts
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic'; 
import { AppModule } from './app.module'; 
platformBrowserDynamic().bootstrapModule(AppModule);  

```

我们使用`app.module.ts`模块文件来定义应用程序的根模块：

```ts
import { NgModule } from '@angular/core'; 
import { BrowserModule } from '@angular/platform-browser'; 
import { AppComponent } from './app.component'; 
@NgModule({ 
  imports:      [ BrowserModule ], 
  declarations: [ AppComponent ], 
  bootstrap:    [ AppComponent ] 
}) 
export class AppModule { } 

```

模块可以使用`imports`属性导入其他模块，并且模块可以在`bootstrap`属性下定义一个或多个根组件。在我们的示例中，每个这样的根组件都将初始化其自己的组件树，该组件树仅包含一个组件。在模块中使用任何组件、指令或管道之前，都需要将其添加到`declarations`属性中。

# 定义子组件

虽然根组件代表 Angular 应用程序的容器，但您还需要其他直接或间接是根组件后代的组件。当呈现根组件时，它还将呈现其所有子组件。

这些子组件可以从其父组件接收数据，也可以发送数据回去。让我们在一个更复杂的示例中看到这些概念的运作，这个示例是在前一个示例的基础上构建的。请注意，在`Example1`中，我们建议子组件可以插入到根组件模板中；这样的一个子组件定义如下：

```ts
import { Component, Input, Output, EventEmitter } from '@angular/core'; 
@Component({ 
    selector: 'div[my-child-comp]', 
    template: ` 
        <p>{{myText}}</p> 
        <button class="btn btn-default" type="button" (click)="onClick()">Send message</button>` 
}) 
export class ChildComponent {  
  private static instanceCount: number = 0; 
  instanceId: number; 
  @Input() myText: string; 
  @Output() onChildMessage = new EventEmitter<string>();   
  constructor(){ 
    ChildComponent.instanceCount += 1; 
    this.instanceId = ChildComponent.instanceCount; 
  } 
  onClick(){ 
    this.onChildMessage.emit(`Hello from ChildComponent with instance  
    id: ${this.instanceId}`); 
  } 
} 

```

第一个突出显示的代码片段显示了组件选择器使用自定义元素属性而不是自定义元素标记。在使用现有的 CSS 样式和 HTML 标记时，往往需要确保你的 Angular 组件与其上下文的外观和感觉自然地集成。这就是属性或 CSS 选择器真正有用的地方。

乍一看，组件类结构看起来与`Example1`中的类似--除了第二个突出显示的代码片段中的两个新装饰器。第一个装饰器是`@Input()`，应该应用于可以从父组件接收数据的任何组件属性。第二个装饰器是`@Output()`，应该应用于可以向父组件发送数据的任何属性。Angular 2 定义了一个`EventEmitter`类，它使用类似 Node.js `EventEmitter`或 jQuery 事件的方法来生成和消费事件。`string`类型的输出事件是在`onClick()`方法中生成的，任何父组件都可以订阅这个事件来从子组件接收数据。

EventEmitter 类扩展了 RxJS Subject 类，而 RxJS Subject 类又是 RxJS Observable 的一种特殊类型，允许多播。关于可观察对象、订阅者和其他响应式编程概念的更多细节可以在第七章 *使用可观察对象进行异步编程*中找到。

我们利用了 TypeScript 中的`static`类属性来生成一个唯一的实例标识符`instanceId`，该标识符在子组件通过`onChildMessage`输出属性发送的消息中使用。我们将使用这条消息来明显地表明每个子组件实例向其订阅者发送一个唯一的消息，这在我们的示例中是`AppComponent`根组件。

```ts
@Component({ 
    selector: 'div.container.my-app', 
    template: ` 
    <div class="container text-center"> 
      <div class="row"><div class="col-md-12"> 
          <div class="page-header"><h1>{{title}}</h1></div> 
          <p class="lead">{{description}}</p> 
      </div></div> 
      <div class="row"> 
        <div class="col-md-6" my-child-comp myText="A child component 
 goes here" (onChildMessage)="onChildMessageReceived($event)"> 
 </div>       
        <div class="col-md-6" my-child-comp 
 [myText]="secondComponentText" 
 (onChildMessage)="onChildMessageReceived($event)"></div>          
        </div> 
      <div class="row"><div class="col-md-12"><div class="well well-
       sm">          
            <p>Last message from child components: <strong> 
               {{lastMessage}}</strong>
            </p> 
           </div></div></div>           
    </div> 
}) 
export class AppComponent {  
  title: string; 
  description: string; 
  secondComponentText: string; 
  lastMessage: string; 
  constructor(){ 
    this.title = 'Mastering Angular - Chapter 4, Example 2'; 
    this.description = 'This is an example for an Angular 2 root   
    component with an element and class selector and a child component 
    with an element attribute selector.'; 
    this.secondComponentText = 'Another child component goes here'; 
  } 

  onChildMessageReceived($event: string) 
  { 
    this.lastMessage = $event; 
  } 
} 

```

突出显示的代码显示了根组件如何引用和绑定`ChildComponent`元素。`onChildMessage`输出属性绑定到`AppComponent`方法，使用与 Angular 2 用于绑定原生 HTML DOM 事件相同的括号表示法；例如，`<button (click)="onClick($event)">`。

输入属性只是为第一个`ChildComponent`实例分配了一个静态值，并通过括号表示法绑定到`AppComponentsecondComponentText`属性。当我们仅分配固定值时，不需要使用括号表示法，Angular 2 在绑定到原生 HTML 元素属性时也会使用它；例如，`<input type="text" [value]="myValue">`。

如果您还不熟悉 Angular 如何绑定到原生 HTML 元素属性和事件，您可以参考第六章，*创建指令和实现变更检测*，以供进一步参考。

对于两个`ChildComponent`实例，我们使用相同的`AppComponentonChildMessageReceived`方法，使用简单的事件处理方法绑定到`onChildMessage`事件，这将在应用程序页面上显示最后一个子组件消息。根组件选择器被更改为使用元素标签和 CSS 类选择器，这种方法导致`index.html`文件结构更简单。

我们必须修改`AppModule`的定义，以确保`ChildComponent`可以被`AppComponent`和同一模块中的任何其他组件引用：

```ts
@NgModule({ 
  imports:      [ BrowserModule ], 
  declarations: [ AppComponent, ChildComponent ], 
  bootstrap:    [ AppComponent ] 
}) 
export class AppModule { } 

```

您可以在本章的代码中的`Example2`文件夹中找到此示例。本文涵盖的概念，如组件属性和事件、组件数据流和组件组合，在构建相对复杂的应用程序方面可以发挥重要作用，我们将在本章中进一步探讨它们。

除了组件，Angular 还有指令的概念，这在 Angular 1 中也可以找到。每个 Angular 组件也是一个指令，我们可以粗略地将指令定义为没有任何模板的组件。`@Component`装饰器接口扩展了`@Directive`装饰器接口，我们将在第六章中更多地讨论指令，*创建指令和实现变更检测*。

# 组件生命周期

Angular 渲染的每个组件都有自己的生命周期：初始化、检查变化和销毁（以及其他事件）。Angular 提供了一个`hook`方法，我们可以在其中插入应用代码以参与组件生命周期。这些方法通过 TypeScript 函数接口提供，可以选择性地由组件类实现，它们如下：

+   `ngOnChanges`：在数据绑定的组件属性在`ngOnInit`之前初始化一次，并且每次数据绑定的组件属性发生变化时都会被调用。它也是指令生命周期的一部分（约定是接口实现函数名加上`ng`前缀，例如`ngOnInit`和`OnInit`）。

+   `ngOnInit`：在第一次`ngOnChanges`之后调用一次，当数据绑定的组件属性和输入属性都被初始化时调用。它也是指令生命周期的一部分。

+   `ngDoCheck`：作为 Angular 变化检测过程的一部分被调用，应用于执行自定义变化检测逻辑。它也是指令生命周期的一部分。

+   `ngAfterContentInit`：在第一次调用`ngDoCheck`之后调用一次，当组件模板完全初始化时调用。

+   `ngAfterContentChecked`：在`ngAfterContentInit`之后和每次`ngDoCheck`调用后都会被调用，用于验证组件内容。

+   `ngAfterViewInit`：在第一次`ngAfterContentChecked`之后调用一次，当所有组件视图及其子视图都被初始化时调用。

+   `ngAfterViewChecked`：在`ngAfterViewInit`之后和每次`ngAfterContentChecked`调用后都会被调用，用于验证所有组件视图及其子视图。

+   `ngOnDestroy`：当组件即将被销毁时调用，应用于清理操作；例如，取消订阅可观察对象和分离事件。

我们将调整我们之前的示例来展示一些这些生命周期`hook`，并且我们将使用一个父组件和一个子组件，它们要么显示要么记录所有它们的生命周期事件到控制台。直到组件完全加载的事件触发将被清晰地显示/记录，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/2c60a3af-bf42-4fdb-bbba-b934b037a198.png)

父组件的代码与子组件的代码非常相似，子组件有一个按钮，可以根据需要向父组件发送消息。当发送消息时，`child`组件和父组件都会响应由 Angular 的变更检测机制生成的生命周期事件。您可以在本章的源代码中的`Example3`文件夹中找到`child.component.ts`文件中的子组件代码。

```ts
import {Component, Input, Output, EventEmitter, OnInit, OnChanges, DoCheck, AfterContentInit, AfterContentChecked, AfterViewInit, AfterViewChecked} from '@angular/core'; 
@Component({ 
  selector: 'div[my-child-comp]', 
  template: ` 
  <h2>These are the lifecycle events for a child component:</h2> 
  <p class="lead">Child component initial lifecycle events:</p> 
  <p>{{initialChildEvents}}</p> 
  <p class="lead">Child component continuous lifecycle events:</p> 
  <p>{{continuousChildEvents}}</p> 
  <button class="btn btn-default" type="button" (click)="onClick()">Send message from child to parent</button>` 
}) 
export class ChildComponent implements OnInit, OnChanges, DoCheck, AfterContentInit, AfterContentChecked, AfterViewInit, AfterViewChecked { 
  initialChildEvents: string[]; 
  continuousChildEvents: string[]; 
  @Output() onChildMessage = new EventEmitter<string>(); 
  private hasInitialLifecycleFinished: boolean = false; 
  private ngAfterViewCheckedEventCount: number = 0; 
  constructor() { 
    this.initialChildEvents = []; 
    this.continuousChildEvents = []; 
  } 
  private logEvent(message: string) { 
        if (!this.hasInitialLifecycleFinished) { 
            this.initialChildEvents.push(message); 
        } else { 
            this.continuousChildEvents.push(message); 
        } 
    } 
  ngOnChanges(): void { 
    this.logEvent(` [${new Date().toLocaleTimeString()}]-ngOnChanges`); 
  } 
  ngOnInit(): void { 
    this.logEvent(` [${new Date().toLocaleTimeString()}]-ngOnInit`); 
  } 
  ngDoCheck(): void { 
    this.logEvent(` [${new Date().toLocaleTimeString()}]-ngDoCheck`); 
  } 
  ngAfterContentInit(): void { 
    this.logEvent(` [${new Date().toLocaleTimeString()}]-
    ngAfterContentInit`); 
  } 
  ngAfterContentChecked(): void { 
    this.logEvent(` [${new Date().toLocaleTimeString()}]-
    ngAfterContentChecked`); 
  } 
  ngAfterViewInit(): void { 
    console.log(`child: [${new Date().toLocaleTimeString()}]-
    ngAfterViewInit`); 
  } 
  ngAfterViewChecked(): void { 
    this.ngAfterViewCheckedEventCount += 1; 
    if (this.ngAfterViewCheckedEventCount === 2) { 
      this.hasInitialLifecycleFinished = true; 
    } 
    console.log(`child: [${new Date().toLocaleTimeString()}]-
    ngAfterViewChecked`); 
  } 
  onClick() { 
    this.onChildMessage.emit(`Hello from ChildComponent at: ${new 
    Date().toLocaleTimeString()}`); 
  } 
} 

```

以`ng`开头的所有方法都是组件生命周期钩子，当触发时，大多数方法都会记录存储在组件中并通过数据绑定显示的事件（请参阅上一个代码清单中的突出显示的代码片段）。生命周期钩子中的两个--`ngAfterViewInit`和`ngAfterViewChecked`--会将事件记录到控制台，而不是将其存储为组件数据，因为在组件生命周期的那一点上组件状态的任何更改都会在 Angular 应用程序中生成异常。例如，让我们将`ngAfterViewInit`方法体更改为以下内容：

```ts
ngAfterViewInit(): void { 
    this.logEvent(` [${new Date().toLocaleTimeString()}]-
    ngAfterViewInit); 
} 

```

如果您查看应用程序页面浏览器控制台，在进行更改后，您应该会看到此错误消息：

表达在检查后已经改变。

在示例的初始运行中，`ngDoCheck`和`ngAfterContentChecked`方法（如果查看浏览器控制台输出，则还有`ngAfterViewChecked`）在任何用户交互之前已经为每个组件触发了两次。此外，每次按下示例按钮时，相同的三种方法都会被触发，每个组件一次。在实践中，除了编写更高级的组件或组件库之外，您可能很少使用这些生命周期钩子，除了`ngOnChanges`，`ngOnInit`和`ngAfterViewInit`。我们将在第六章中重新讨论这些核心生命周期钩子，*创建指令和实现变更检测*，因为它们在表单和其他交互式组件的上下文中非常有用。

# 在组件之间进行通信和共享数据

我们已经使用了最简单的方法来在组件之间通信和共享数据：`Input`和`Output`装饰器。使用`Input`装饰器装饰的属性通过传递数据来初始化组件，而`Output`装饰器可以用于分配事件监听器，以接收组件外部的数据。这种方法可以在本章源代码中的`Example2`文件夹中找到的组件中观察到。

# 从父组件引用子组件

我们可以通过模板引用变量或通过使用`ViewChild`和`ViewChildren`属性装饰器将目标组件注入到父组件中，来绕过声明性绑定到组件属性和事件。在这两种情况下，我们都可以获得对目标组件的引用，并且可以以编程方式分配其属性或调用其方法。为了演示这些功能的实际应用，我们将稍微修改`Example2`中的`ChildComponent`类，并确保`myText`属性具有默认文本设置。这可以在本章源代码中的`Example4`文件夹中找到的`child.component.ts`文件中的突出显示的代码片段中看到。

```ts
... 
export class ChildComponent {  
  private static instanceCount: number = 0;  
  instanceId: number; 
  @Input() myText: string; 
  @Output() onChildMessage = new EventEmitter<string>(); 

  constructor(){ 
    ChildComponent.instanceCount += 1; 
    this.instanceId = ChildComponent.instanceCount; 
    this.myText = 'This is the default child component text.'; 
  } 

  onClick(){ 
    this.onChildMessage.emit(`Hello from ChildComponent with instance 
    id: ${this.instanceId}`); 
  } 
} 

```

然后，我们将更改`app.component.ts`文件，以包括模板引用方法来处理第一个子组件和组件注入方法来处理第二个子组件：

```ts
import { Component, ViewChildren, OnInit, QueryList } from '@angular/core'; 
import { ChildComponent } from './child.component'; 
@Component({ 
    selector: 'div.container.my-app', 
    template: ` 
    <div class="container text-center"> 
      <div class="row"><div class="col-md-12"> 
          <div class="page-header"><h1>{{title}}</h1></div> 
          <p class="lead">{{description}}</p>           
      </div></div> 
      <div class="row"> 
        <div class="col-md-6"> 
          <button class="btn btn-default" type="button" 
 (click)="firstChildComponent.myText='First child component 
 goes here.'">Set first child component text</button> 
          <button class="btn btn-default" type="button" 
 (click)="firstChildComponent.onChildMessage.subscribe(onFirstChildComp
 onentMessageReceived)">Set first child component message 
 output</button> 
         </div>       
         <div class="col-md-6"> 
        <button class="btn btn-default" type="button" 
 (click)="setSecondChildComponentProperties()">Set second 
 child component properties</button> 
         </div>          
         </div>       
      <div class="row"> 
      <div class="col-md-6 well well-sm" my-child-comp 
 #firstChildComponent></div>       
        <div class="col-md-6 well well-sm" my-child-comp 
 id="secondChildComponent"></div>       
      </div> 
      <div class="row"><div class="col-md-12"><div class="well well-
      sm">          
            <p>Last message from child components: <strong>
            {{lastMessage}}</strong></p> 
      </div></div></div>           
    </div>` 
}) 
export class AppComponent {  
  title: string; 
  description: string; 
  lastMessage: string; 
  @ViewChildren(ChildComponent) childComponents: 
  QueryList<ChildComponent>; 
  constructor(){ 
    this.title = 'Mastering Angular - Chapter 4, Example 4'; 
    this.description = 'This is an example for how to reference 
    existing components from a parent component.'; 
    this.lastMessage = 'Waiting for child messages ...'; 
  } 
  onFirstChildComponentMessageReceived($event: string) 
  { 
    alert($event); 
  }   
  setSecondChildComponentProperties(){     
    this.childComponents.last.myText = "The second child component goes 
    here."; 
    this.childComponents.last.onChildMessage.subscribe( (message: 
    string) => {  
      this.lastMessage = message + ' (the message will be reset in 2 
      seconds)'; 
      setTimeout( ()=>{ this.lastMessage = 'Waiting for child messages 
      ...';}, 2000); 
    }); 
  } 
} 

```

首先，第三个突出显示的 HTML 片段中的两个子组件没有任何属性或事件绑定。第一个子组件有一个`#firstChildComponent`属性，它代表一个模板引用变量。

# 模板引用变量

模板引用变量可以在 Angular 模板中针对任何组件、指令或 DOM 元素进行设置，并且将该引用可用于当前模板。在前面示例中的第一个突出显示的 HTML 片段中，我们有两个按钮，它们使用内联 Angular 表达式来设置`myText`属性，并通过`firstChildComponent`模板引用变量绑定到`onChildMessage`事件。运行示例时，如果我们单击“设置第一个子组件文本”按钮，然后单击“设置第一个子组件消息输出”按钮，我们将通过模板引用变量直接操作第一个子组件，就像在之前示例中的第一个突出显示的 HTML 片段中所看到的那样。这种方法适用于初始化和读取组件属性，但在需要绑定到组件事件时，它被证明是繁琐的。

模板引用变量无法在组件类中访问；因此，我们的做法是绑定到第一个子组件事件。然而，在处理表单时，这种类型的变量将非常有用，我们将在第六章中重新讨论它们，*创建指令和实现变更检测*。

# 注入子组件

对于第二个子组件，我们使用了一种基于在`app.component.ts`文件中的属性声明中注入组件的技术：

```ts
@ViewChildren(ChildComponent) childComponents: QueryList<ChildComponent>; 

```

`ViewChildren`装饰器采用了`ChildComponent`类型的选择器，该选择器将从父组件模板中识别和收集所有`ChildComponent`实例，并将其放入`QueryList`类型的专门列表中。这个列表允许迭代子组件实例，我们可以在`AppComponent.setSecondChildComponentProperties()`方法中使用`QueryList.Last()`调用来获取第二个子组件的引用。当运行本章源代码中`Example4`文件夹中找到的代码时，如果单击“设置第二个子组件属性”按钮，前一个代码清单中的第二个 HTML 片段将开始运行。

注入子组件是一种多才多艺的技术，我们可以以更高效的方式从父组件代码中访问引用的组件。

# 使用服务与组件

现在，我们将再次演变`Example2`，并将一些在组件级别定义的代码重构为 Angular 服务。

服务是一个 TypeScript 类，它有一个名为`Injectable`的装饰器，没有任何参数，允许服务成为 Angular 2 中依赖注入（DI）机制的一部分。DI 将确保每个应用程序只创建一个服务实例，并且该实例将被注入到任何声明它为依赖项的类的构造函数声明中。除了特定的装饰器之外，服务通常需要在模块定义中声明为提供者，但也可以在组件、指令或管道定义中声明。在跳转到本节的示例之前，您可以在第十二章中找到有关服务的更多信息，*实现 Angular 服务*。

即使一个服务没有其他依赖，也最好确保它被装饰为可注入的，以防将来有依赖，并简化其在作为依赖项时的使用。

对于我们的示例，我们将在`Example2`代码的基础上构建一个新示例，该示例可以在本章的源代码中的`Example4`文件夹中找到。我们将首先将父组件和`child`组件的大部分逻辑提取到一个新的服务类中：

```ts
import {Injectable,EventEmitter} from '@angular/core'; 
@Injectable() 
export class AppService { 
  private componentDescriptions: string[]; 
  private componentMessages: string[]; 
  public appServiceMessage$ = new EventEmitter <string> (); 
  constructor() { 
    this.componentDescriptions = [ 
      'The first child component goes here', 
      'The second child component goes here' 
    ]; 
    this.componentMessages = []; 
  } 
  getComponentDescription(index: number): string { 
    return this.componentDescriptions[index]; 
  } 
  sendMessage(message: string): void { 
    this.componentMessages.push(message); 
    this.appServiceMessage$.emit(message); 
  } 
  getComponentMessages(): string[] { 
    return this.componentMessages; 
  } 
} 

```

该服务将用于存储`componentDescriptions`数组中由子组件使用的描述，并通过`sendMessage()`方法提供消息处理程序，该方法还将任何处理过的消息存储在`AppService.componentMessages`属性中。`Example2`中`child`组件的`onChildMessage`属性现在移动到`AppService.appServiceMessage$`，并且可以供任何需要它的组件或服务使用。`child`组件的定义现在大大简化了。

```ts
import {Component, Input, Output, EventEmitter, OnInit} from '@angular/core'; 
import {AppService} from './app.service'; 

@Component({ 
  selector: 'div[my-child-comp]', 
  template: ` 
        <p>{{myText}}</p> 
        <button class="btn btn-default" type="button" 
        (click)="onClick()">Send message</button>` 
}) 
export class ChildComponent implements OnInit { 
  @Input() index: number; 
  myText: string; 
  constructor(private appService: AppService) {} 
  ngOnInit() { 
    this.myText = this.appService.getComponentDescription(this.index); 
  } 

  onClick() { 
    if (this.appService.getComponentMessages().length > 3) { 
      this.appService.sendMessage(`There are too many messages ...`); 
      return; 
    } 
    this.appService.sendMessage(`Hello from ChildComponent with index: 
    ${this.index}`); 
  } 
} 

```

`Child`组件的消息现在通过`AppService`的`sendMessage()`方法发送。此外，唯一的`@Input()`属性称为`index`，它存储了用于通过`AppService.getComponentDescription()`方法设置`myText`属性的组件索引。除了`index`属性之外，`ChildComponent`类完全依赖于`AppService`来读取和写入数据。

`AppComponent`类现在几乎没有逻辑，虽然它显示了`AppService`实例提供的所有消息，但它还在`ngOnInit`方法中注册了一个自定义订阅，用于存储最后接收到的消息。`AppService.appServiceMessage$`属性是`EventEmitter`类型，为任何对消费此事件感兴趣的其他 Angular 类提供了一个公共订阅：

```ts
import { Component, OnInit } from '@angular/core'; 
import { AppService } from './app.service'; 
@Component({ 
    selector: 'div.container.my-app', 
    template: `<div class="container text-center"> 
      <div class="row"><div class="col-md-12"> 
          <div class="page-header"><h1>{{title}}</h1></div> 
          <p class="lead">{{description}}</p> 
      </div></div> 
      <div class="row"> 
        <div class="col-md-6 well" my-child-comp index="0"></div>       
        <div class="col-md-6 well" my-child-comp index="1"></div>          
      </div> 
      <div class="row"><div class="col-md-12"><div class="well well-
       sm"> 
            <p><strong>Last message received:</strong> 
             {{lastMessageReceived}}</p> 
            <p><strong>Messages from child components:</strong> 
            {{appService.getComponentMessages()}}</p> 
       </div></div></div>           
    </div>` 
}) 
export class AppComponent implements OnInit {  
  title: string; 
  description: string; 
  lastMessageReceived: string; 
  constructor(private appService: AppService){ 
    this.title = 'Mastering Angular - Chapter 4, Example 4'; 
    this.description = 'This is an example of how to communicate and 
    share data between components via services.';     
  }  
  ngOnInit(){ 
    this.appService.appServiceMessage$.subscribe((message:string) => { 
      this.lastMessageReceived = message; 
    }); 
  } 
} 

```

在这个例子中，我们从一个依赖`@Input()`属性来获取所需数据的`ChildComponent`类开始；我们转而使用一个只需要一个键值来从服务类获取数据的类。编写组件的两种风格并不互斥，使用服务可以进一步支持编写模块化组件。

# 总结

在本章中，我们首先看了一个基本的组件示例，然后探讨了父子组件。对组件生命周期的了解之后，我们举例说明了如何在组件之间进行通信和共享数据。


# 第五章：实现 Angular 路由和导航

应用程序导航是任何网站或应用程序的核心功能之一。除了定义路由或路径之外，导航还帮助用户到达应用程序页面，探索功能，并且对于 SEO 目的也非常有用。

在本章中，您将学习有关 Angular 路由和导航的所有内容。以下是我们将在路由和导航中学习和实现的功能的详细列表。

您将学习以下路由和导航方面：

+   导入和配置路由器

+   在视图中启用路由出口、`routerLink`、`routerLinkActive`和`base href`

+   自定义组件路由和子路由

+   具有内部子路由的自定义组件路由--同一页面加载

+   演示应用程序的路由和导航

在本章结束时，我们将能够做到以下事情：

+   为应用程序创建`app.routes`并设置所需的模块

+   实现并启用`RouterModule.forRoot`

+   定义路由出口和`routerLink`指令以绑定路由路径

+   启用`RouterLinkActivated`以查找当前活动状态

+   了解路由状态的工作原理

+   了解并实现路由生命周期钩子

+   创建自定义组件路由和子路由

+   为我们的 Web 应用程序实现位置策略

+   创建一个示例应用程序路由和导航

首先，让我们看一下我们将在本章开发的演示应用程序的路由和导航：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/d473f165-7a2c-437b-942c-9fbcf2978fa0.png)

作为演示应用程序的一部分，我们将为“关于我们”、“服务”和“产品”组件开发路由。

服务组件将具有内部子路由。产品组件将使用`ActivatedRoute`来获取路由`params`。我们还将使用 JavaScript 事件`onclick`来实现导航。

# 导入和配置路由器

为了定义和实现导航策略，我们将使用路由器和`RouterModule`。

我们需要更新我们的`app.module.ts`文件以执行以下操作：

+   从 Angular 路由器模块导入`RouterModule`和路由

+   导入应用程序组件

+   定义具有路径和组件详细信息的路由

+   导入`RouterModule.forRoot`（`appRoutes`）

每个路由定义可以具有以下键：

+   `path`：我们希望在浏览器地址栏中显示的 URL。

+   `component`：将保存视图和应用程序逻辑的相应组件。

+   `redirectTo`（可选）：这表示我们希望用户从此路径重定向的 URL。

+   `pathMatch`（可选）：重定向路由需要`pathMatch`--它告诉路由器如何将 URL 与路由的路径匹配。`pathMatch`可以取`full`或`prefix`的值。

现在我们将在我们的`NgModule`中导入和配置路由器。看一下更新的`app.module.ts`文件，其中包含了路由器的完整实现：

```ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { RouterModule, Routes } from '@angular/router';

import { AppComponent } from './app.component';
import { AboutComponent} from './about.component';
import { ServicesComponent} from './services.component';
import { ProductsComponent } from './products.component';

const appRoutes: Routes = [
 { path: 'about', component: AboutComponent },
 { path: 'services', component: ServicesComponent }, 
 { path: 'products', redirectTo:'/new-products', pathMatch:'full'},
 { path: '**', component: ErrorPageNotFoundComponent }
];

@NgModule({
 imports: [
 BrowserModule,
 FormsModule,
 RouterModule.forRoot(appRoutes)
 ],
 declarations: [
  AppComponent,
  AboutComponent,
  ServicesComponent,
  ProductsComponent,
 ],
 bootstrap: [ AppComponent ]
})
export class AppModule { }  

```

让我们分析上述代码片段：

1.  我们从`@angular/router`导入`Routes`和`RouterModule`。

1.  我们从各自的 Angular 库中导入所需的模块`NgModule`，`BrowserModule`和`FormsModule`。

1.  我们正在导入自定义定义的组件--`About`，`Services`和`Products`。

1.  我们在`appRoutes`中定义了一个常量，其中我们为我们的组件指定了路径。

1.  我们通过`appRoutes`创建我们的路由，并通过传递各种参数为各种 URL 路由链接定义自定义路径。

现在我们已经学会了如何导入和配置我们的`NgModule`来实现路由，在下一节中我们将学习路由器的构建模块。

# 路由器的构建模块

在本节中，您将学习路由器的重要构建模块。重要的构建模块包括`base href`，`Router Outlet`，`routerLink`和`routerLinkActive`。

现在让我们分析路由器库的每个构建模块：

+   `base href`：我们必须在`index.html`页面中设置`base`指令。*这是一个强制性步骤。*没有`base`标签，浏览器可能无法在*深度链接*到应用程序时加载资源（图像、CSS 和脚本）。

在我们的应用程序中，我们需要在`index.html`文件的`<head>`标签中定义`base href`：

```ts
<base href="/“>

```

+   **定义** `router-outlet`：`router-outlet`指令是包含视图加载数据的占位符。在`router-outlet`指令内，组件视图将被加载和显示。将该指令放在`app.component.html`模板中以呈现数据：

```ts
<router-outlet></router-outlet> 

```

+   **使用多个** `router-outlet`：在某些情况下，我们希望将数据加载到不同的视图容器而不是我们的`router-outlet`中。我们可以轻松地向页面添加多个 Router Outlets 并为它们分配名称，以便我们可以在其中呈现相应的数据：

```ts
<router-outlet></router-outlet> <router-outlet  name="content-farm"></router-outlet>

```

要加载视图数据到命名的`router-outlet`中，我们在定义路由时定义键：

```ts
 {   path:  'content', component: ContentFarmComponent, outlet:  'content- farm'
  }

```

+   **创建** `RouterLink`：这表示 URL 或链接地址可以直接从浏览器地址栏中到达。绑定并关联一个链接路径与锚点标签：例如，`/about`或`/products`。

绑定和关联锚点标签的一般语法如下：

```ts
<a [routerLink]="['/about']">About Us</a>
<a [routerLink]="['/products']">Products</a>
<a [routerLink]="['/services']">Services</a>

```

+   `RouterLinkActive` **用于活动状态链接**：`routerLinkActive`用于突出显示当前活动链接。使用`routerLinkActive`，我们可以轻松地突出显示当前活动的链接，以更好地适应我们应用程序的外观和感觉：

```ts
<a [routerLink]="['/about']" routerLinkActive = 
       “active-state">About Us</a>

```

在样式表中，添加我们的自定义样式类`active-state`。

+   **构建动态** `routerLink`：我们可以通过将它们与`routerLink`指令绑定来传递动态值或参数以传递自定义数据。

通常，在大多数应用程序中，我们使用唯一标识符对数据进行分类--例如，`http://hostname/product/10`将被写成如下形式：

```ts
<a [routerLink]="['/product', 10]">Product 10</a>

```

同样的前面的代码可以在我们的模板视图中动态呈现：

```ts
<a [routerLink]="['/product', product.id]">Product 10</a>

```

+   **使用** `routerLink` **指令传递数组和数据集**：我们可以通过`routerLink`传递数据数组。

```ts
 <a [routerLink]="['/contacts', { customerId: 10 }]">Crisis 
    Center</a>

```

# 关于路由器 LocationStrategy

我们需要定义应用程序的 URL 行为。根据应用程序的偏好，我们可以自定义 URL 应该如何呈现。

使用`LocationStrategy`，我们可以定义我们希望应用程序路由系统如何行为。

Angular 通过`LocationStrategy`提供了两种我们可以在应用程序中实现的路由策略。让我们了解一下我们可以在 Angular 应用程序中使用的不同路由策略选项：

+   `PathLocationStrategy`：这是默认的 HTML 样式路由机制。

应用`PathLocationStrategy`是常见的路由策略，它涉及在每次检测到更改时向服务器端发出请求/调用。实现此策略将允许我们创建清晰的 URL，并且也可以轻松地标记 URL。

使用`PathLocationStrategy`的路由示例如下：

```ts
http://hostname/about 

```

+   `HashLocationStrategy`*:* 这是哈希 URL 样式。在大多数现代 Web 应用程序中，我们看到哈希 URL 被使用。这有一个重大优势。

当`#`后的信息发生变化时，客户端不会发出服务器调用或请求；因此服务器调用较少：

```ts
http://hostname/#/about

```

+   在我们的应用程序中定义和设置`LocationStrategy`：在`app.module.ts`文件的`providers`下，我们需要传递`LocationStrategy`并告诉路由器使用`HashLocationStrategy`作为`useClass`。

在`app.module.ts`中，导入并使用`LocationStrategy`并说明我们要使用`HashLocationStategy`，如下所示：

```ts
@NgModule({
  imports: [
  BrowserModule,
  routing
 ],
 declarations: [
  AppComponent
 ],
 bootstrap: [
  AppComponent
 ],
 providers: [
  {provide: LocationStrategy, useClass: HashLocationStrategy }
 ]
})
export class AppModule { }

```

在上述代码中，我们在我们的提供者中注入了`LocationStrategy`，并明确告知 Angular 使用`HashLocationStrategy`。

默认情况下，Angular 路由器实现`PathLocationStrategy`。

# 处理错误状态-通配符路由

我们需要为找不到页面或 404 页面设置错误消息。我们可以使用`ErrorPageNotFoundComponent`组件来显示找不到页面或路由器未知路径的错误消息：

```ts
const appRoutes: Routes = [
 { path: 'about', component: AboutComponent },
 { path: 'services', component: ServicesComponent }, 
 { path: 'old-products', redirectTo:'/new-products', pathMatch:'full'},
 { path: '**', component: ErrorPageNotFoundComponent },
 { path:  'content', component: ContentFarmComponent, outlet:  'content-
    farm'  }
];

```

在这个阶段，有关如何使用路由器的各个方面的所有信息，让我们将它们全部添加到我们的`app.component.ts`文件中：

```ts
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
 selector: 'my-app',
 template: `
 <h2>Angular2 Routing and Navigation</h2>
 <div class="">
 <p>
   <a routerLink="/about" routerLinkActive="active"> About Us</a> |
   <a routerLink="/services" routerLinkActive="active" > Services</a> |
   <a routerLink="/products" routerLinkActive="active"> Products</a>
 </p>
 <div class="app-data">
  <router-outlet></router-outlet>
 </div> 
 </div>`,
  styles: [`
    h4 { background-color:rgb(63,81,181);color:#fff; padding:3px;}
    h2 { background-color:rgb(255, 187, 0);color:#222}
    div {padding: 10px;}
    .app-data {border: 1px solid #b3b3b3;}
    .active {color:#222;text-decoration:none;}
    `
   ],
 encapsulation: ViewEncapsulation.None
})
export class AppComponent {
}

```

让我们分析上述代码并将其分解为关键功能：

+   我们定义了`routerLink`属性，以便在用户点击锚链接时启用导航

+   我们实现了`routerLinkActive`属性以突出显示当前/活动链接，也就是用户点击的链接

+   我们为`<router-outlet>`定义了一个占位符，它将保存来自不同视图的数据--具体取决于点击了哪个链接

现在，当我们启动应用程序时，我们将看到以下结果输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/529ba97c-a27a-4980-9d5a-8a0f89e6ef56.png)

太棒了！到目前为止，一切都很好。现在让我们添加路由守卫功能。

在下一节中，我们将学习如何集成路由守卫以在各个组件之间实现受控导航。

# 路由守卫

路由守卫让您控制路由导航的各个阶段。在从一个组件导航到另一个组件时，我们需要确保将要显示的数据对用户是经过授权的，如果不是，则取消导航。

路由守卫可以返回一个`Observable<boolean>`或一个`Promise<boolean>`，路由器将等待 Observable 解析为 true 或 false：

+   如果路由守卫返回 true，它将继续导航并显示视图

+   如果路由守卫返回 false，它将中止/取消导航

有各种路由守卫可以独立使用或组合使用。它们如下：

+   `canActivate`

+   `canActivateChild`

+   `canDeactivate`

+   `Resolve`

+   `canLoad`

守卫函数可以接受参数以做出更好的决定。我们可以传递的参数如下：

+   `component`：我们创建的自定义组件指令：例如`Products`，`Services`等。

+   `route`：`ActivatedRouteSnapshot`是如果守卫通过将要激活的未来路由。

+   `state`：`RouterStateSnapshot`是如果守卫通过将来的路由状态。

+   `canActivate`：这保护组件——将其视为一个类似于著名酒吧外面保镖的消毒函数。确保在激活路由之前满足所有必要的标准。我们需要从路由器导入`canActivate`模块，并在组件类中调用该函数。

以下是用于通用健全性服务`check-credentials.ts`文件的代码片段：

```ts
import { Injectable } from '@angular/core';
import { CanActivate } from '@angular/router';

@Injectable()
export class checkCredentials implements CanActivate {
  canActivate() {
   console.log('checking on user credential - user logged in: Passed');
   return true;
 }
}

```

如果您想要在没有任何验证或业务规则的情况下重定向用户，请使用导航函数而不是`canActivate`。

+   `canActivateChild`：这保护子组件*——*在前一节中，我们创建了组件路由以及子路由？是的，现在我们也要确保保护它们。

+   `canActivateChild`函数类似于`canActivate`，但有一个关键区别，即此函数保护组件的子路由。

以下是在服务中使用`canActivateChild`函数的示例代码：

```ts
import {CanActivateChild} from "@angular/router";

@Injectable()
class checkCredentialsToken implements CanActivateChild {
 canActivateChild() {
 console.log("Checking for child routes inside components");
 return true;
 }
}

```

+   `canDeactivate`：这处理页面中的任何未保存更改*——*当用户尝试从具有未保存更改的页面导航时，我们需要通知用户有待更改，并确认用户是否要保存他们的工作或继续而不保存。

这就是`canDeactivate`的作用。以下是一个实现`canDeactivate`函数的服务的代码片段：

```ts
import { CanDeactivate } from '@angular/router';

@Injectable()
export class checkCredentials {
 canDeactivate() {
 console.log("Check for any unsaved changes or value length etc");
 return true;
 }
}

```

+   `Resolve`：这在路由激活之前执行路由数据检索——`Resolve`允许我们在激活路由和组件之前从服务中预取数据检索。

以下是我们如何使用`Resolve`函数并在激活路由之前从服务获取数据的代码片段：

```ts
import { Injectable } from '@angular/core';
import { Resolve, ActivatedRouteSnapshot } from '@angular/router';
import { UserService } from './shared/services/user.service';

@Injectable()
export class UsersResolve implements Resolve<any> {
  constructor(private service: UserService) {}
   resolve(route: ActivatedRouteSnapshot) {
   return this.service.getUsers();
  }
}

```

+   `canLoad`：这甚至在加载模块之前保护模块*——*使用`canActivate`，我们可以将未经授权的用户重定向到其他着陆页面，但在这些情况下，模块会被加载。

我们可以使用`canLoad`函数避免加载模块。

在下一节中，我们将学习为组件和子组件定义路由。我们将学习创建多级组件层次结构。

# 自定义组件路由和子路由

在之前的章节中，我们已经学习了路由的各种用法；现在是时候将我们的所有知识整合起来，使用所有的路由示例来创建一个样例演示应用程序。我们将创建一个自定义组件，并定义其带有子路由的路由文件。

我们将创建一个名为 Products 的项目列表，其中将包含子产品的链接列表项。点击相应的产品链接，用户将显示产品详情。

应用程序的导航计划如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/675cb239-5df0-4dcb-bfa5-13149826202c.png)

在之前的章节中，我们已经学习了在`NgModule`中定义和创建路由。我们也可以选择在单独的`app.route.ts`文件中定义所有的路由细节。

创建`app.route.ts`文件，并将以下代码片段添加到文件中：

```ts
import { productRoutes } from './products/products.routes';

export const routes: Routes = [
 {
 path: '',
 redirectTo: '/',
 pathMatch: 'full'
 },
 ...aboutRoutes,
 ...servicesRoutes,
 ...productRoutes,
 { path: '**', component: PageNotFoundComponent }
];

export const routing: ModuleWithProviders = RouterModule.forRoot(routes);

```

我们将我们的组件导入到`app.routes.ts`文件中，然后使用`productRoutes`定义路由。

现在，我们要创建我们的`product.routes.ts`文件，其中包含我们产品的路径定义。以下是这样做的代码：

```ts
import { Routes } from '@angular/router';
import { ProductsComponent } from './products.component';
import { ProductsDetailsComponent } from './products-details.component';

export const productRoutes: Routes = [
 { path: 'products', component: ProductsComponent },
 { path: 'products/:id', component: ProductsDetailsComponent } 
];

```

让我们详细分析前述代码：

1.  我们在`products.routes.ts`文件中定义了两个路径。

1.  路径`products`将指向`ProductsComponent`。

1.  路径`products/:id`将被映射到`ProductsDetailsComponent`，对应的路径为`products/10`。

现在，是时候创建我们的组件--`ProductsComponent`和`ProductsDetailsComponent`。

让我们在`products.components.ts`文件中定义`ProductsComponent`类，并添加以下代码：

```ts
import { Component } from '@angular/core';
import { Routes, Router } from '@angular/router';

@Component({
 template: `
 <div class="container">
 <h4>Built with Angular2</h4>
 <p> select country specific website for more details </p>
 <ul>
 <li><a routerLink="10" routerLinkActive="disabled">Product #10</a>
   </li>
 <li><a routerLink="11" routerLinkActive="disabled">Product #11</a>
   </li>
 <li><a routerLink="12" routerLinkActive="disabled">Product #12</a>
   </li>
 </ul>

<button (click)="navigateToServices()">Navigate via Javascript event</button>

<router-outlet></router-outlet>

</div>`,
 styles: ['.container {background-color: #fff;}']
})
export class ProductsComponent {

   constructor(private router: Router) {}

   navigateToServices(){
     this.router.navigate(['/services']);
   }
}

```

让我们详细分析前述代码：

+   我们已经使用`routerLink`指令创建了三个产品链接；点击这些链接将使我们映射到我们在`products.route.ts`文件中创建的路径。

+   我们创建了一个按钮，它具有`navigateToServices`事件，在`ProductsComponent`类中，我们实现了导航到服务页面的方法。

+   我们已经创建了一个`routerLink`来处理每个产品 ID，并且相应的数据将在`<router-outlet>`中加载。

现在，让我们在`products`文件夹下的`products-details.components.ts`中使用以下代码创建`ProductsDetailsComponent`：

```ts
import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import { ROUTER_DIRECTIVES, ActivatedRoute } from '@angular/router';

@Component({
 template: `
 <div class="container">
  <h4>Product Demo Information</h4>
  <p>This is a page navigation for child pages</p>
  showing product with Id: {{selectedId}}
  <p>
  <a routerLink="/products">All products</a>
  </p>
 </div>
 `,
 directives: [ROUTER_DIRECTIVES],
 styles: ['.container {background-color: #fff;}']
})

export class ProductsDetailsComponent implements OnInit {
  private selectedId: number;

  constructor(private route: ActivatedRoute) {}

  ngOnInit() {
   this.sub = this.route.params.subscribe(params => {
   let id = params['id'];
   this.selectedId = id;
   console.log(id);
  });
 }
}

```

以下是前述代码的分析：

+   当用户点击产品链接时，`id`将被映射，并显示相应的产品详情。

+   我们从`@angular/core`库中导入所需的模块`Component`和`OnInit`。

+   我们从`angular/router`库中导入所需的模块`ROUTER_DIRECTIVES`和`ActivatedRoute`

+   我们正在导出`ProductsDetailsComponent`类

+   我们在构造方法中注入了`ActivatedRoute`

+   我们正在定义`ngOnInIt`方法，该方法将在页面加载时调用

+   我们正在使用`ActivatedRoute`服务，它提供了一个`params` `Observable`，我们可以订阅以获取路由参数

+   我们使用`this.route.params.subscribe`来映射在 URL 中传递的参数

+   参数具有所选/点击产品的`id`，我们将其分配给变量`this.selectedId`

到目前为止一切都准备好了吗？太棒了。

现在是时候用新组件和它们的声明更新我们的`app.module.ts`文件了。更新后的`app.module.ts`将如下所示：

```ts
import { NgModule } from "@angular/core";
import { BrowserModule } from "@angular/platform-browser";
import { HashLocationStrategy, LocationStrategy } from "@angular/common";

import { AppComponent } from "./app.component";
import { routing } from "./app.routes";

import { ProductsComponent } from "./products/products.component";
import { ProductsDetailsComponent } from './products/products-
  details.component';

@NgModule({
  imports: [
      BrowserModule,
      routing
    ],
  declarations: [
     AppComponent,
     ProductsComponent,
     ProductsDetailsComponent
    ],
  bootstrap: [
     AppComponent
    ],
  providers: [
     {provide: LocationStrategy, useClass: HashLocationStrategy }
   ]
  })
export class AppModule { }

```

好的。现在，让我们测试一下我们迄今为止制作的应用程序。

以下图片显示了我们的应用在这个阶段应该如何运行：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/50883655-dd87-4758-aacb-4e37447cb411.png)

以下图片显示了当用户点击任何特定产品时，应用程序将带用户到相应的产品列表：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/52cdecfc-5e6e-4214-bc58-1142f3622c6e.png)

# 具有内部子路由的自定义组件路由

在上面的示例中，当用户点击产品链接时，用户将被导航到新路径。在这个示例中，您将学习如何创建自定义组件和子路由，并在同一路径内显示视图；也就是说，内部子路由。

扩展相同的示例，看一下应用程序的导航计划：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/a7991fcb-17a6-4b42-b902-cd6494d93356.png)

让我们从在`service.routes.ts`文件中定义路由定义开始。请参考以下代码进行路由定义：

```ts
import { Routes } from '@angular/router';

import { ServicesComponent } from './services.component';
import { ServicesChildComponent } from "./services-child.component";
import { ServicesInnerChildComponent } from "./services-inner-
    child.component";

export const servicesRoutes: Routes = [
 {
    path: 'services',
    component: ServicesComponent,
    children: [
       {
         path: '', redirectTo: 'services', pathMatch: 'full'},
         {
           path: 'web-technologies',
           component: ServicesChildComponent,
           children: [
              { path: '', redirectTo: 'web-technologies', pathMatch: 
                'full'},
              { path: 'angular2', component: 
                  ServicesInnerChildComponent}
           ]
         }
     ]
   }
];

```

在上述代码片段中，我们正在创建路径服务，并在同一路径内创建多级子路由，这些子路由都属于同一 URL 层次结构。

组件导航路由定义如下所示：

+   `/services`

+   `/services/web-technologies`

+   `/services/web-technologies/angular2`

现在，让我们为我们的服务创建三个新的组件：

+   `ServicesComponent`

+   `ServicesChildComponent`

+   `ServicesInnerChildComponent`

请注意，在父视图中添加`<router-outlet>`指令是重要的；否则，它会抛出错误。

现在我们需要创建我们的服务组件。对于`ServicesComponent`，创建一个名为`services.component.ts`的新文件，并将以下代码片段添加到其中：

```ts
import { Component } from '@angular/core';

@Component({
 template: `
 <div class="container">
 <h4>Services offered</h4>
 <ul>
 <li><a routerLink="web-technologies" routerLinkActive="active">Web 
     Technologies Services</a></li>
 <li><a routerLink="#" routerLinkActive="disabled">Mobile Apps</a></li>
 <li><a routerLink="#" routerLinkActive="disabled">CRM Apps</a></li>
 <li><a routerLink="#" routerLinkActive="disabled">Enterprise Apps</a> 
  </li>
 </ul>
 </div>
 <router-outlet></router-outlet>
 `,
 styles: ['.container {background-color:#fff;}']
})

export class ServicesComponent {
}

```

接下来是对上述代码的快速说明：

1.  我们在`ServicesComponent`模板中定义了一个无序列表`<ul>`和项目`<li>`。

1.  对于每个列表项，我们附加了`routerLink`属性来链接 URL。

1.  在模板中，我们还添加了`<router-outlet>`--这将允许子组件视图模板放置在父组件视图中。

我们已经创建好了父组件`ServicesComponent`。现在是时候创建内部组件`ServicesChildComponent`了。

让我们创建一个名为`services-child.component.ts`的新文件，并将以下代码片段添加到文件中：

```ts
import {Component} from '@angular/core';

@Component({
 template: `
 <div class="container">
 <h4>Web Technologies</h4>
 <p>This is 1st level Inner Navigation</p>
 <a routerLink="angular2" routerLinkActive="active">Angular2 Services</a>
 </div>
<router-outlet></router-outlet> 
 `,
 styles: ['.container {background-color: #fff;}']
})

export class ServicesChildComponent {}

```

接下来是对上述代码的快速说明：

1.  我们为标题和锚点标签`<a>`定义了`routerLink`和`routerLinkActive`属性。

1.  对于锚点标签，我们附加了`routerLink`和`routerLinkActive`属性。

1.  在模板中，我们还添加了`<router-outlet>`--这将允许内部子组件视图模板放置在子组件视图中。

看一下下面的层次结构图，它描述了组件结构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/58d49976-3ab6-4442-8952-82783f6d33ae.png)

到目前为止，我们已经创建了一个父组件`ServicesComponent`，以及它的子组件`ServicesChildComponent`，它们之间有父子关系的层次结构。

是时候创建第三级组件`ServicesInnerChildComponent`了。创建一个名为`services-child.component.ts`的新文件：

```ts
import {Component} from '@angular/core';

@Component({
 template: `
 <div class="container">
 <h4>Angular Services</h4>
 <p>This is 2nd level Inner Navigation</p>
 <a routerLink="/services" routerLinkActive="active">View All 
    Services</a>
 </div>
 `,
 styles: ['.container {background-color: #fff;}']
})

export class ServicesInnerChildComponent {}

```

好了，现在我们已经定义了所有的组件和子组件以及它们各自的路由定义，是时候看看它们的运行情况了。以下截图展示了服务组件和子组件的导航路由是如何工作的。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/5a272ae6-6784-43ad-8664-85661075a836.png)

点击 Web Technologies 链接将显示用户子组件数据。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/374256c1-7c0f-4d48-af2c-4869c5af0b4c.png)

点击 Angular Services 链接将显示用户子组件数据。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/222d5b54-6968-4386-8234-b0a4eecb1a86.png)

我们的组件分别很好地工作。在下一节中，我们将把它们全部集成到一个单一的工作应用程序中。

# 将所有组件集成在一起

我们已经为各个组件`About`、`Services`和`Products`定义并实现了路由。

在本节中，我们将把它们全部集成到一个单一的`NgModule`中，这样我们就可以将所有路由作为一个单页面应用程序一起工作。

让我们将`About`，`Services`和`Products`组件的所有单独路由添加到我们的`app.routes.ts`中，更新后的`app.route.ts`文件如下：

```ts
import { ModuleWithProviders } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { PageNotFoundComponent } from './not-found.component';

import { AboutComponent } from "./about/about.component";

import { ServicesComponent } from "./services/services.component";
import { ServicesChildComponent } from "./services/services-
  child.component";
import { ServicesInnerChildComponent } from "./services/services-inner-
  child.component";

import { ProductComponent } from "./products/products.component";
import { ProductsDetailsComponent } from './products/products-
  details.component';

import { aboutRoutes } from './about/about.routes';
import { servicesRoutes } from './services/services.routes';
import { productRoutes } from './products/products.routes';

export const routes: Routes = [
 {
   path: '',
   redirectTo: '/',
   pathMatch: 'full'
 },
 ...aboutRoutes,
 ...servicesRoutes,
 ...productRoutes,
 { 
  path: '**', component: PageNotFoundComponent }
];

export const routing: ModuleWithProviders = RouterModule.forRoot(routes);

```

我们已经更新了`app.routes.ts`文件，以包括所有组件以及子组件的路由。

现在是时候更新`NgModule`，导入所有组件以及更新的路由了。

更新后的`app.module.ts`文件如下：

```ts
import { NgModule } from "@angular/core";
import { BrowserModule } from "@angular/platform-browser";
import { HashLocationStrategy, LocationStrategy } from "@angular/common";

import { AppComponent } from "./app.component";
import { routing } from "./app.routes";
import { PageNotFoundComponent } from './not-found.component';

import { AboutComponent } from "./about/about.component";
import { ServicesComponent } from "./services/services.component";
import { ServicesChildComponent } from "./services/services-
  child.component";
import { ServicesInnerChildComponent } from "./services/services-inner-
  child.component";

import { ProductsComponent } from "./products/products.component";
import { ProductsDetailsComponent } from './products/products-
  details.component';

@NgModule({
  imports: [
   BrowserModule,
   routing
    ],
  declarations: [
   AppComponent,
   ProductsComponent,
   ServicesComponent,
   AboutComponent,
   ProductsDetailsComponent,
   PageNotFoundComponent,
   ServicesChildComponent,
   ServicesInnerChildComponent
    ],
  bootstrap: [
   AppComponent
    ],
  providers: [
   {provide: LocationStrategy, useClass: HashLocationStrategy }
   ]
})
export class AppModule { }

```

在上述代码中需要注意的重要事项是：

1.  我们导入了我们迄今为止创建的所有组件，即`About`，`Services`和`Products`。

1.  我们还在导入每个组件的`app.routes.ts`路由。

1.  我们正在注入`LocationStrategy`并明确地将其指定为`useClass HashLocationStrategy`。

我们已经了解了`router`，`routerModule`以及 Angular 提供的用于实现应用程序路由机制的实用工具。我们了解了可以使用的不同类型的`LocationStrategy`来定义 URL 应该如何显示。

我们创建了具有路由路径和子组件路由路径的组件，并且我们也学会了如何使用 JavaScript 事件进行导航。

在接下来的部分，我们将把所有的代码组合在一起，制作我们的演示应用程序。

# 演示应用程序的路由和导航

我们已经在学习 Angular 路由方面走了很长的路。我们已经看到了如何使用路由模块的各种技巧和窍门。现在是时候将我们迄今学到的所有知识整合到一个整洁、干净的应用程序中了。

以下图片显示了我们最终的应用程序文件系统结构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/4ab53ed1-f7dc-42e9-9b9c-9a4ecc4b2ba5.png)

我们将在`app.component.ts`文件中添加主导航菜单和一些基本样式来为我们的应用程序增添活力：

```ts
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
 selector: 'my-app',
 template: `
    <h2>Angular2 Routing and Navigation</h2>
    <div class="">
    <p>
      <a routerLink="/about" routerLinkActive="active">About Us</a>|
      <a routerLink="/services" routerLinkActive="active">Services</a>|
      <a routerLink="/products" routerLinkActive="active">Products</a>
    </p>
    <div class="app-data">
      <router-outlet></router-outlet>
    </div> 
   </div>`,
     styles: [`
       h4 { background-color:rgb(63,81,181);color:#fff; padding:3px;}
       h2 { background-color:rgb(255, 187, 0);color:#222}
       div {padding: 10px;}
       .app-data {border: 1px solid #b3b3b3;}
       .active {color:#222;text-decoration:none;}
      `
     ],
 encapsulation: ViewEncapsulation.None
})

export class AppComponent {
}

```

我们最终的`app.routes.ts`文件代码如下：

```ts
import { ModuleWithProviders } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { PageNotFoundComponent } from './not-found.component';

import { AboutComponent } from "./about/about.component";
import { ServicesComponent } from "./services/services.component";
import { ServicesChildComponent } from "./services/services-
   child.component";
import { ServicesInnerChildComponent } from "./services/services-inner-
   child.component";

import { ProductComponent } from "./products/products.component";
import { ProductsDetailsComponent } from './products/products-
   details.component';

import { aboutRoutes } from './about/about.routes';
import { servicesRoutes } from './services/services.routes';
import { productRoutes } from './products/products.routes';

export const routes: Routes = [
   {
     path: '',
     redirectTo: '/',
     pathMatch: 'full'
   },
   ...aboutRoutes,
   ...servicesRoutes,
   ...productRoutes,
   { path: '**', component: PageNotFoundComponent }
  ];

export const routing: ModuleWithProviders =
           RouterModule.forRoot(routes);

```

我们的`app.module.ts`文件代码如下：

```ts
import { NgModule } from "@angular/core";
import { BrowserModule } from "@angular/platform-browser";
import { HashLocationStrategy, LocationStrategy } from 
     "@angular/common";
import { AppComponent } from "./app.component";
import { routing } from "./app.routes";

import { PageNotFoundComponent } from './not-found.component';
import { AboutComponent } from "./about/about.component";

import { ServicesComponent } from "./services/services.component";
import { ServicesChildComponent } from "./services/services-
   child.component";
import { ServicesInnerChildComponent } from "./services/services-inner-
    child.component";

import { ProductsComponent } from "./products/products.component";
import { ProductsDetailsComponent } from './products/products-
    details.component';

@NgModule({
 imports: [
   BrowserModule,
   routing
   ],
 declarations: [
   AppComponent,
   ProductsComponent,
   ServicesComponent,
   AboutComponent,
   ProductsDetailsComponent,
   PageNotFoundComponent,
   ServicesChildComponent,
   ServicesInnerChildComponent
 ],
 bootstrap: [
    AppComponent
 ],
 providers: [
   { provide: LocationStrategy, useClass: HashLocationStrategy }
 ]
})
export class AppModule { }

```

我们的应用程序已经准备好进行大规模演示了。

在以下的屏幕截图中，我们展示了应用程序的行为。

当我们启动页面时，我们会看到登陆页面。登陆页面的截图如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/34d91e6f-784e-44f5-88d2-62ddd5cd8838.png)登陆页面

现在让我们点击 Services 链接。`routerLink/services`将被激活，并且应该显示以下屏幕：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/a6b5a78d-891c-4b3f-b176-d2bdf881a629.png)Services 页面。

好的，现在我们在服务页面。现在，点击子组件，Web 技术服务。应显示以下屏幕截图：

服务子页面--Web 技术。

事情在这里发展得非常顺利。

我们现在已经在子组件--Web 技术服务中，现在我们再点击一级。让我们点击 Angular2 服务。应显示以下屏幕截图：

Web 技术内部子路由--Angular2。

好的，现在点击“产品”链接。应显示以下屏幕截图：

产品页面。

好的，现在我们在产品页面。现在，点击“所有产品”链接，导航到服务页面。

但是，导航是使用 JavaScript 事件而不是`routerLink`发生的。

产品详情页面。

# 总结

Angular 路由是任何 Web 应用程序的核心功能之一。在本章中，我们详细讨论、设计和实现了我们的 Angular 路由。我们还讨论了如何实现和启用`RouterModule.forRoot`。此外，我们定义了 Router Outlet 和`routerLink`指令来绑定路由路径，并启用了`RouterLinkActivated`来查找当前活动状态。

我们重点关注路由状态的工作原理，并了解并实现了路由生命周期钩子。我们概述了如何创建自定义组件路由和子路由，以及如何为我们的 Web 应用程序实现位置策略。最后，我们创建了一个实现路由和导航的示例应用程序。

在下一章中，您将学习如何创建指令并实现变更检测。您还将了解 Angular 提供的不同类型的指令，并创建自定义用户定义的指令。

您将深入学习 Angular 如何处理变更检测以及如何在我们的应用程序中利用变更检测。
