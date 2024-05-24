# Angular .NET 开发学习手册（三）

> 原文：[`zh.annas-archive.org/md5/1D7CD4769EDA3E96BB350F0A5265564A`](https://zh.annas-archive.org/md5/1D7CD4769EDA3E96BB350F0A5265564A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第七章：在 Visual Studio 中使用 Angular，ASP.NET MVC 和 Web API 创建应用程序

本章将指导您通过将 Angular 应用程序与 ASP.NET MVC 和 ASP.NET Web API 集成的过程。在上一章中，我们使用 Angular 应用程序消耗了 ASP.NET Web API 服务。所有视图都由 Angular 渲染。在本章中，我们将从 ASP.NET MVC 提供视图。因此，它提供了许多机会，比如使用 Razor 语法，因为 Angular 视图将由 ASP.NET MVC 提供动力。

在本章中，我们将涵盖以下主题：

+   使用 ASP.NET MVC 为 Angular 组件模板提供视图

+   结合 ASP.NET MVC，ASP.NET Web API 和 Angular 的路由

## 使用 ASP.NET MVC

* * *

ASP.NET 包括 Web 堆栈，如 ASP.NET MVC，Razor 和 Web API。ASP.NET MVC 框架是建立在 ASP.NET 之上的。ASP.NET MVC Web 框架实现了**模型-视图-控制器**（MVC）模式以开发 Web 应用程序。

在 MVC 模式中，**模型**代表业务对象的状态。**视图**表示用户界面，**控制器**处理模型和视图之间的通信。所有请求将由控制器处理，并返回响应：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_001.jpg)

MVC 架构

ASP.NET MVC 有自己的视图引擎，称为 Razor 引擎。

## 结合 ASP.NET MVC，ASP.NET Web API 和 Angular 的路由

* * *

**路由**是将端点分解为可处理请求的模块或控制器和操作的过程。路由使 URL 可读且有意义。它还帮助隐藏用户的数据。

### ASP.NET MVC 中的路由

ASP.NET MVC 路由将请求映射到控制器操作。所有路由将在路由表中定义，并由路由引擎使用来匹配请求的 URL 模式与控制器和操作。

我们可以在`Startup.cs`文件的 configure 方法中向路由表添加路由。以下代码片段显示了在路由表上注册的默认路由：

```ts
public void Configure(IApplicationBuilder app) 
{ 
    app.UseIISPlatformHandler(); 
    app.UseDefaultFiles(); 
    app.UseStaticFiles(); 
    app.UseMvc(config => 
    { 
        config.MapRoute( 
            name: "Default", 
            template: "{controller}/{action}/{id?}", 
            defaults: new { controller = "Home", action = "Index" } 
            ); 
    });             
} 
```

在这里，一个路由被注册为模板和默认值。如果在 URL 中未提供控制器或操作名称，则该请求将映射到`HomeController`类中的`Index`操作；否则，它将映射到相应的控制器操作。

在我们的应用程序中，我们有三个 MVC 控制器，分别是`HomeController`，`UserController`和`TodoController`。

#### 添加 ASP.NET MVC HomeController

```ts
Index action:
```

```ts
public IActionResult Index() 
{ 
    return View(); 
} 
```

当一个请求被路由到`Index`操作时，它将返回`Index`视图。`Index.cshtml`的源代码如下所示：

```ts
 @{ 
    Layout = null; 
} 
<!DOCTYPE html> 
<html> 
<head> 
    <meta name="viewport" content="width=device-width" /> 
    <title>Index</title> 
</head> 
<body> 
    <h1>index view</h1> 
</body> 
</html> 
```

按照给定的步骤，将 ASP.NET MVC 的`HomeController`及其相应视图添加到我们在早期章节中创建的`My Todo`应用程序中：

1.  右键单击`Controllers`文件夹并添加一个新的控制器。

1.  将新添加的控制器命名为`HomeController`。请注意，默认情况下`HomeController`已添加了`Index`操作。

1.  现在，让我们为`Index`动作添加一个视图。右键单击`My Todo`应用程序，并添加一个名为`Views`的新文件夹。

1.  然后，在刚刚创建的`Views`文件夹下添加一个名为`Home`的文件夹。

1.  右键单击`Home`文件夹并添加一个名为`Index.cshtml`的新视图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_002.png)

ASP.NET MVC HomeController Index 视图

### ASP.NET MVC 的路由

我们刚刚创建了一个 ASP.NET MVC 控制器，并为控制器的`Index`动作添加了一个视图。现在我们需要为 ASP.NET MVC 应用配置路由，以便任何对`Index`动作的请求都由 ASP.NET MVC 路由处理。请按照以下步骤配置 ASP.NET MVC 路由：

1.  打开`Startup.cs`。

1.  请注释或删除`Configure`方法中的`app.UseDefaultFiles()`语句，因为我们将使用 ASP.NET MVC 来提供视图。

1.  用这个声明替换`Configure`方法中的`app.UseMvc()`语句：

```ts
     app.UseMvc(config =>   
            {   
              config.MapRoute(   
              name: "Default",   
              template: "{controller}/{action}/{id?}",   
     defaults: new   { controller = "Home", action =    
     "Index" }   
               );   
            });
```

在这里，我们已经添加了 ASP.NET MVC 的默认路由。对于 Web API 的任何请求都将与控制器中的 HTTP 谓词或动作进行映射。

通过按下*F5*键来运行应用程序，您将在浏览器中看到呈现的图形界面：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_003.png)

ASP.NET MVC HomeController Index 视图在浏览器中呈现

### 将内容从默认页面移动到 ASP.NET MVC 视图

在前面的部分中，我们能够运行应用程序并注意到默认视图是由 HomeController 提供的 ASP.NET MVC Index 视图。现在，让我们使用`wwwroot`文件夹下的`Index.html`文件的内容更新`Index.cshtml`视图。更新后的`Index.cshtml`如下所示：

```ts
@{   
    Layout = null;   
}   
<!DOCTYPE html>   
<html>   
<head>   
    <title>My   Todo</title>   
    <script>document.write('<base   href="' + 
    document.location + '" />');</script>   
    <meta charset="UTF-8">   
    <!-- Polyfills -->   
    <script src="img/shim.min.js"></script>   
    <script src="img/zone.min.js"></script>   
    <script src="img/system.src.js"></script>   
    <script src="img/systemjs.config.js"></script>   
    <script>   
    System.import('main.js').catch(function(err){   
    console.error(err); });   
    </script>   
</head>   
<body>   
    <h1>My Todo   App</h1>   
    <my-app>Loading My Todo   App...</my-app>   
</body>   
</html>   
```

现在通过按下*F5*来运行应用程序，并注意`my-app`特殊标签已被 Angular 解析为`app.component.html`的模板，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_004.png)

Angular 应用加载到 ASP.NET MVC Index 视图

### ASP.NET Web API 中的路由

任何对 Web API 的请求都将使用路由将其映射到控制器中的 HTTP 谓词或动作。Web API 2 引入了一种基于属性的路由技术，称为**属性路由**。可以在控制器级别和操作级别添加属性路由。可以通过传递 URL 模板来修饰 Web API 控制器的`Route`属性，如下所示：

```ts
[Route("api/[controller]")] 
public class TodosController : Controller 
{    
    // GET: api/todos/pending-only 
    [HttpGet] 
    [Route("pending-only")] 
    public IEnumerable<Todo> GetPendingOnly() 
    { 
    } 
} 
```

在这里，`TodosController`被`Route`修饰，并且使用`api/[controller]` URL 模板。这意味着如果收到的请求为[`www.programmerguide.net/api/todos`](http://www.programmerguide.net/api/todos)，它将被路由到`TodosController`，且动作将根据应用的 HTTP 动作进行选择。

注意`GetPendingOnly`动作被`Route`修饰，并且使用`pending-only`URL 模板。这意味着如果控制器中有更多的`GET`动作可用，且请求 URL 为[`www.programmerguide.net/api/todos/pending-only`](http://www.programmerguide.net/api/todos/pending-only)，它将被映射到`GetPendingOnly`动作。

`TodosController` Web API 控制器的完整源代码如下：

```ts
[Produces("application/json")] 
    [Route("api/Todos")] 
    public class TodosController : Controller 
    { 
        private TodoContext _db; 
        public TodosController(TodoContext context) 
        { 
            _db = context; 
        } 
        // GET: api/todos 
        [HttpGet] 
        public IEnumerable<Todo> Get() 
        { 
            return _db.Todos.ToList(); 
        } 
        // GET: api/todos/pending-only 
        [HttpGet] 
        [Route("pending-only")] 
        public IEnumerable<Todo> GetPendingOnly() 
        { 
            _db.Todos.RemoveRange(_db.Todos.Where(x => 
            x.Completed == true)); 
            _db.SaveChanges(); 
            return _db.Todos.ToList(); 
        } 
        // POST api/todos 
        [HttpPost] 
        public Todo Post([FromBody]Todo value) 
        { 
            _db.Todos.Add(value); 
            _db.SaveChanges(); 
            return value; 
        } 
        // PUT api/todos/id 
        [HttpPut("{id}")] 
        public Todo Put(int id, [FromBody]Todo value) 
        { 
            var todo = _db.Todos.FirstOrDefault(x => x.Id  
            == id); 
            todo.Title = value.Title; 
            todo.Completed = value.Completed; 
            _db.Entry(todo).State = EntityState.Modified; 
            _db.SaveChanges(); 
            return value; 
        } 
        // DELETE api/todos/id 
        [HttpDelete("{id}")] 
        public void Delete(int id) 
        { 
            var todo = _db.Todos.FirstOrDefault(x => x.Id 
            == id); 
            _db.Entry(todo).State = EntityState.Deleted; 
            _db.SaveChanges(); 
        } 
  } 
```

### Angular 中的路由

正如我们在第三章，*Angular 构建模块 - 第二部分*中看到的那样，Angular 引入了一个组件路由器，它深度链接 URL 请求，映射为此路由注释的组件，并渲染与该组件关联的模板或视图。Angular 路由器不是核心 Angular 框架的一部分，它作为 Angular 路由器模块的一部分。我们需要在`package.json`中的依赖项部分添加对此库的引用，如下所示：

```ts
"dependencies": {
"@angular/router": "~4.0.0",
}
<base> tag with the href attribute that should be added to the head tag in the index file, considering that the app folder is the root of the application:
```

```ts
<base href="/">
```

路由器通过查看浏览器请求的 URL 的`RouteDefinition`决定组件和模板。因此，我们需要配置路由定义。

我们的首页将有三个超链接，分别是`todo`、`about`和`contact`。点击`todo`将导航用户到`todo`应用，点击`about`将导航到`about`视图，最后，点击`contact`将导航用户到`contact`视图。因此，我们需要添加另外两个组件，分别是`AboutComponent`和`ContactComponent`，以及它们各自的模板文件，分别是`about.component.html`和`contact.component.html`。按照下面的步骤创建这些组件和它们的模板：

1.  右键单击`app`文件夹，并添加两个 HTML 模板：`about.component.html`和`contact.component.html`。

1.  将以下 HTML 片段添加为`about.component.html`的内容：

```ts
      <h1>This is the About   View</h1>   
```

1.  将以下 HTML 片段添加为`contact.component.html`的内容：

```ts
      <h1>This is the Contact   View</h1>   
```

1.  右键单击`app`文件夹，添加两个 Angular 组件：`about.component.ts`和`contact.component.ts`。

1.  将以下代码片段添加到`about.component.ts`：

```ts
    import { Component } from '@angular/core';   
    @Component({   
        selector: 'about-me',   
        templateUrl: './app/about.component.html',   
    })   
    export class AboutComponent { }   
```

1.  将以下代码片段添加到`contact.component.ts`：

```ts
    import { Component } from '@angular/core';    
    @Component({   
        selector: 'contact-us',   
        templateUrl: './app/contact.component.html',   
    })     
      export class ContactComponent { }
```

1.  还要创建一个 Angular 组件，`todo.component.ts`，并将`app.component.ts`中的属性和方法移动到`todo.component.ts`。同时，更新`TodoComponent`的导入和注解。`TodoComponent`的完整代码片段如下所示：

```ts
     import { Component, OnInit } from   '@angular/core';   
     import { Todo } from './todo'   
     import { TodoService } from './todo.service'     
     @Component({   
         selector: 'my-app',   
         templateUrl: './app/todo.component.html',   
         providers: [TodoService]   
     })   
       export class TodoComponent   implements OnInit {   
         todos: Array<Todo>;   
         newTodoText = '';   
       constructor(private   todoService: TodoService) {   
          this.todos = new Array();   
       }   
           getTodos(): void {   
           this.todoService   
           .getTodos()   
           .then(todos =>   this.todos = todos);   
       }   
       ngOnInit(): void {   
        this.getTodos();   
       }   
        removeCompleted() {   
        this.todoService.removeCompleted();   
        this.todos =   this.getPending();   
       }   
       toggleCompletion(todo: Todo)   {   
          this.todoService.toggleCompletion(todo);   
       }   
       remove(todo: Todo) {   
          this.todoService.remove(todo);   
          this.todos.splice(this.todos.indexOf(todo), 1);   
       }   
       addTodo() {   
           if (this.newTodoText.trim().length)   {   
           this.todoService.add(this.newTodoText).then(res      
           => {   
           this.getTodos();   
           });   
           this.newTodoText = '';   
           this.getTodos();   
           }   
       }   
       getPending() {   
           return this.todos.filter((todo:   Todo) =>   
     todo.completed === false);   
       }   

        getCompleted() {   
        return   this.todos.filter((todo: Todo) =>   
        todo.completed === true);   
       }   
     }   
```

1.  现在，创建`todo.component.html`模板，并将`app.component.html`的内容移动过去。更新后的`todo.component.html`如下所示：

```ts
    <section>   
       <header>   
          <h1>todos</h1>   
        <input placeholder="Add   new todo" autofocus=""   
        [(ngModel)]="newTodoText">   
        <button type="button"   
        (click)="addTodo()">Add</button>   
     </header>   
    <section>   
        <ul>   
            <li *ngFor="let   todo of todos">   
            <input type="checkbox"    
            (click)="toggleCompletion(todo)"  
            [checked]="todo.completed">   
            <label>{{todo.title}}</label>   
            <button   (click)="remove(todo)">X</button>   
            </li>   
        </ul>   
    </section>   
          <footer *ngIf="todos.length   > 0">   
          <span><strong>{{getPending().length}}</strong>     
          {{getPending().length == 1 ? 'item' : 'items'}}   
          left</span>   
          <button *ngIf="getCompleted().length   > 0"    
          (click)="removeCompleted()">Clear     
          completed</button>   
          </footer>   
    </section>
```

1.  接下来，添加一个`app.routing.ts`文件，并使用下面的代码片段更新它。在这里，我们为`todo`、`about`和`contact`配置了三个路由。此外，我们分配了三个组件--`TodoComponent`、`AboutComponent`和`ContactComponent`--来导出`NgModule`属性的元数据：

```ts
    import { NgModule } from '@angular/core';   
    import { Routes, RouterModule }   from  
    '@angular/router';   
    import { TodoComponent } from './todo.component';   
    import { AboutComponent } from './about.component';   
    import { ContactComponent } from   
    './contact.component';   
    export const appRoutes: Routes =   [   
        {   
            path: '',   
            redirectTo: 'todo',   
            pathMatch: 'full',   
        },       
        { path: 'todo', component:   TodoComponent, data:    
          { title: 'Todo' } },   
        { path: 'about', component:  AboutComponent, data:   
          { title: 'About' } },   
        { path: 'contact', component: ContactComponent,   
           data: { title: 'Contact' } }   
    ];     
    export const routedComponents = [   
        TodoComponent,   
        AboutComponent,   
        ContactComponent   
    ];   
    @NgModule({   
        imports:   [RouterModule.forRoot(appRoutes)],   
        exports: [RouterModule]   
    })   
     export class AppRoutingModule { }   
```

1.  更新`app.module.ts`如下以导入我们在上一步创建的`AppRoutingModule`：

```ts
    import { NgModule } from '@angular/core';   
    import { BrowserModule } from '@angular/platform-  
    browser';   
    import { FormsModule } from '@angular/forms';   
    import { HttpModule } from '@angular/http';   
    import { AppComponent } from './app.component';   
    import { TodoComponent } from './todo.component';   
    import { AboutComponent } from './about.component';   
    import { ContactComponent } from   
    './contact.component';   
    import { AppRoutingModule } from './app.routing';   
    import { TodoService } from './todo.service'     
    @NgModule({   
        imports: [   
            BrowserModule,   
            FormsModule,   
            HttpModule,   
            AppRoutingModule   
        ],   
        declarations: [   
            AppComponent,    
            TodoComponent,   
            AboutComponent,   
            ContactComponent   
        ],   
        providers: [TodoService],   
        bootstrap: [AppComponent]   
    })   
    export class AppModule { }   
```

1.  最后，如下更新`app.component.html`：

```ts
    <a routerLinkActive="active"   [routerLink]="   
    ['/todo']">Todo</a>   
    <a routerLinkActive="active"   [routerLink]="
    ['/about']">About</a>   
    <a routerLinkActive="active"   [routerLink]="
    ['/contact']">Contact</a>   
    <router-outlet></router-outlet>   
```

注意每个超链接都有`routerLink`属性，并分配了路由路径。这里，`routerLinkActive`属性分配了`active` CSS 类，当该路由变为活动状态时，将添加到该元素上。换句话说，当用户点击`Todo`链接时，该链接将被分配`active` CSS 类。

`routerLink`属性使应用程序能够链接到应用程序的特定部分或组件。下一条语句是组件路由的`<router-outlet/>`特殊标记，类似于 AngularJS 1.x 中的`<ng-view/>`标记，用于加载与相应路由路径相关联的模板。

1.  按下*F5*运行应用程序，浏览器将通过导航到**`Todo`**路径来加载应用程序，因为我们已经设置了如果是根路径，就重定向到`todo`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_005.png)

加载 todo 模板，URL 为\todo 路径

1.  点击**`About`**链接将导航到\about 路径，并加载`about`的解析模板视图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_006.png)

加载 about 模板，URL 为\about 路径

1.  点击**`Contact`**链接将导航到\contact 路径，并加载 about 的解析模板视图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_007.png)

加载 contact 模板，URL 为\contact 路径

注意在 URL 中路由路径的变化。

### 将 Angular 模板移到 ASP.NET MVC 模板

我们几乎完成了应用程序。但是，我们只使用了 Angular 视图作为 Angular 组件的模板。我们需要通过 ASP.NET MVC 提供模板。这将使我们能够根据需要添加 Razor 代码，因为这些视图是由 ASP.NET MVC 提供支持的。按照以下步骤添加 Razor 视图并更新每个 Angular 组件中的`templateUrl`：

1.  首先，在`HomeController`中添加三个动作，分别为`About`、`Contact`和`Todo`，如下所示：

```ts
        public IActionResult   About()   
        {   
            return View();   
        }   
        public IActionResult   Contact()   
        {   
            return View();
        }      
        public IActionResult   Todo()   
        {   
            return View();   
        }   
```

1.  在`Views -> Home`文件夹下添加三个视图，分别是`About`、`Contact`和`Todo`，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_008.png)

在 Home 下添加 Razor 视图

1.  将以下 HTML 内容添加到`About.cshtml`：

```ts
    <h1>This is the About Razor   View</h1>   
```

1.  添加以下 HTML 内容到`Contact.cshtml`：

```ts
    <h1>This is the Contact Razor View</h1>
```

1.  然后，将`todo.component.html`的内容移动到`Todo.cshtml`：

1.  现在需要将`AboutComponent`、`ContactComponent`和`TodoComponent`的`templateUrl`的元数据更新为 HomeController 中相应操作的 URL：

```ts
     TodoComponent:   
           templateUrl: '/Home/Todo'   
     AboutComponent:   
           templateUrl: '/Home/About'   
     ContactComponent:   
           templateUrl: '/Home/Contact',   
```

1.  现在，按下*F5*运行应用程序，并注意视图是从 ASP.NET MVC 提供的。现在你可以在视图中添加 Razor 语法，因为它们现在由 ASP.NET MVC 提供支持。

1.  点击`About`链接将导航到\about 路径，并实例化相应的组件。这里，它是`AboutComponent`，并且会呈现适当的`about` Razor 视图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_009.png)

关于 Razor 模板呈现

1.  点击**`联系`**链接将导航到 `\contact` 路径，并启动负责呈现`联系`Razor 视图的`ContactComponent`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_07_010.png)

联系 Razor 模板呈现

点击注销将重定向到`登录`视图。

## 摘要

* * *

哇！我们刚刚创建了一个由 ASP.NET MVC 提供支持的 Angular 应用程序，具有后端 Web API。我们结合了 Angular 和 ASP.NET MVC 的路由，并演示了这些路由是如何连接在一起的。

在下一章，我们将讨论测试 Angular 应用程序。


## 第八章：测试 Angular 应用

本章讨论使用**Jasmine**框架测试 Angular 组件和服务。

在本章中，我们将涵盖以下主题：

+   介绍 Jasmine

+   测试 Angular 服务

+   测试 Angular 组件

## 介绍 Jasmine

* * *

Jasmine 是一个开源框架，用于在不依赖于 DOM 的情况下测试 JavaScript 代码。由于 Angular 是松散耦合的，我们可以使用 Jasmine 框架来测试 Angular 组件、服务等。独立于彼此，Jasmine 的清晰语法使您能够轻松编写测试。

一个名为 describe 的全局函数是**Jasmine**函数的起始点。这个全局函数接受一个函数和两个 string 类型的参数。字符串参数描述了测试，函数将有测试的实际实现：

```ts
describe("short description about the test suite", function() { 
}); 
```

实际测试方法由名为`it`函数的全局函数定义，该函数接受两个参数。第一个参数是测试或规范的标题，第二个参数是通过验证代码状态来测试期望的函数。期望与 Microsoft 单元测试框架中的断言类似。如果在规范中任何一个定义的期望失败，这被称为失败的规范。以下代码说明了前述声明：

```ts
describe("short description about the test suite", function() { 
  it("a spec with single expectation", function() { 
    expect(true).toBe(true); 
  }); 
}); 
```

测试方法或规范方法将会有一个或多个 expect 语句，如下所示，通过链式连接到 expect 函数的匹配器函数来比较实际值和期望值；有各种默认的匹配器函数可供使用：

```ts
describe("short description about the test suite", function() { 
it("a spec with single expectation", function() { 
expect(afunction).toThrow(e); 
expect(true).toBe(true); 
expect(variable).toBeDefined(); 
expect(variable).toBeFalsy(); 
expect(number).toBeGreaterThan(number); 
expect(number).toBeLessThan(number); 
expect(variable).toBeNull(); 
expect(variable).toBeTruthy(); 
expect(value).toBeUndefined(); 
expect(array).toContain(member); 
expect(string).toContain(substring); 
expect(variable).toEqual(variable); 
expect(value).toMatch(pattern); 
  }); 
}); 
```

我们只看到了**Jasmine**框架的基础知识，还有更多的功能可以使用。你可以通过访问官方网站[`jasmine.github.io/`](http://jasmine.github.io/)了解更多信息。这个简介已经足够让我们学会如何测试 Angular 服务和组件了。

## 测试 Angular 服务

* * *

```ts
Todo class:
```

```ts
export class Todo { 
    title: string; 
    completed: boolean;
    constructor(title: string) { 
        this.title = title; 
        this.completed = false; 
    } 
    set isCompleted(value: boolean) { 
        this.completed = value; 
    } 
} 
```

接下来，创建一个名为`todo.service.ts`的服务，它在构造函数中构建`Todo`项目列表。`todo.service.ts`的完整代码如下所示：

```ts
import { Todo } from './todo' 
export class TodoService { 
    todos: Array<Todo> 
    constructor() { 
        this.todos = [new Todo('First item'), 
        new Todo('Second item'), 
        new Todo('Third item')]; 
    } 
    getPending() { 
        return this.todos.filter((todo: Todo) => todo.completed === 
        false); 
    } 
    getCompleted() { 
        return this.todos.filter((todo: Todo) => todo.completed === 
        true); 
    } 
    remove(todo: Todo) { 
        this.todos.splice(this.todos.indexOf(todo), 1); 
    } 
    add(title: string) { 
        this.todos.push(new Todo(title)); 
    } 
    toggleCompletion(todo: Todo) { 
        todo.completed = !todo.completed; 
    } 
    removeCompleted() { 
        this.todos = this.getPending(); 
    } 
} 
```

我们已经建立了与数据源交互的服务。现在，让我们使用 Jasmine 框架编写测试来测试`TodoService`。我们将测试`getPending()`和`getCompleted()`两种方法。创建一个名为`todo.service.spec.ts`的文件。

导入`TodoService`应用特定的服务，如下所示：

```ts
import { TodoService } from "./todo.service"; 
```

定义`describe`方法：是 Jasmine 函数的起始点的全局函数，接受两个参数，一个描述测试的字符串和一个具有测试实际实现的函数：

```ts
describe("TodoService Testing",() => { 
}); 
describe function with beforeEach is given here:
```

```ts
describe('TodoService Testing', () => { 
  let service: TodoService; 
  beforeEach(() => { service = new TodoService(); });   
}); 
```

`beforeEach`函数将在运行每个测试方法之前执行，并且为每个测试提供一个`TodoService`的实例。

现在，让我们定义`it`测试方法，示例如下：

```ts
it('getPending length should return 3', () => { 
    expect(service.getPending().length).toBe(3); 
}); 
it('getCompleted length should return 0', () => { 
    expect(service.getCompleted().length).toBe(0); 
}); 
```

在这里，我们验证`getPending()`和`getCompleted()`返回值的长度期望。

```ts
todo.service.spec.ts is this:
```

```ts
import { TodoService } from "./todo.service";  
describe('TodoService Testing', () => { 
  let service: TodoService; 
  beforeEach(() => { service = new TodoService(); }); 
  it('getPending length should return 3', () => { 
    expect(service.getPending().length).toBe(3); 
  }); 
  it('getCompleted length should return 0', () => { 
    expect(service.getCompleted().length).toBe(0); 
  }); 
}); 
```

我们已准备好要运行的测试用例或测试; 通过执行以下命令来运行它们：

```ts
npm run build:watchkarma start karma.conf.js
```

`npm run build:watch`命令将构建您的应用程序，并将 TypeScript 文件转译为 JavaScript。然后，执行`karma start karma.config`命令启动我们应用程序的测试运行器。

Karma 是一个测试运行器，可用于对任何 JavaScript 应用程序运行测试。`karma.config.js`文件是 karma 的配置文件，提供有关我们应用程序的信息，以便它能够了解并测试应用程序。karma 配置文件包含应用程序消耗的 JavaScript 库和框架的路径详细信息，还提供 karma 所使用的插件的详细信息。

Karma 配置文件包含了应用程序中`basePath`，`frameworks`，`plugins`，`client`和自定义启动器的配置详细信息。我们已在 karma 中配置了 Jasmine 作为我们的测试框架，我们在运行测试时加载了所需模块的插件列表。我们还配置了具有`buildPaths`和`clearContext`的客户端。`buildPaths`将包含查找转译后应用程序 JS 和映射文件的路径详细信息。以下是供您参考的完整 karma 配置文件：

```ts
module.exports = function(config)   {    
  var appBase    = 'src/';         // transpiled app JS and map files   
  var appAssets  = '/base/app/';   // component assets fetched by  
  Angular's compiler   
  // Testing helpers (optional)   are conventionally in a folder called 
     `testing`   
  var testingBase    = 'src/testing/';   // transpiled test JS and map  
  files   
  var testingSrcBase = 'src/testing/';   // test source TS    
   files   
  config.set({   
    basePath: '',   
    frameworks: ['jasmine'],   
    plugins: [   
      require('karma-jasmine'),   
      require('karma-chrome-launcher'),   
      require('karma-jasmine-html-reporter')   
    ],   
    client: 
  {   
      builtPaths: [appBase,   testingBase], // add more 
      spec base paths 
      as needed   
      clearContext: false //   leave Jasmine Spec Runner 
      output visible  
      in browser   
    },   
    customLaunchers: {   
      // From the CLI. Not used   here but interesting   
      // chrome setup for travis   CI using chromium   
      Chrome_travis_ci: {   
        base: 'Chrome',   
        flags: ['--no-sandbox']   
      }   
    },   
    files: [   
      // System.js for module   loading   
      'node_modules/systemjs/dist/system.src.js',   
      // Polyfills   
      'node_modules/core-js/client/shim.js',   
      // zone.js   
      'node_modules/zone.js/dist/zone.js',   
      'node_modules/zone.js/dist/long-stack-trace-
       zone.js',   
      'node_modules/zone.js/dist/proxy.js',   
      'node_modules/zone.js/dist/sync-test.js',   
      'node_modules/zone.js/dist/jasmine-patch.js',   
      'node_modules/zone.js/dist/async-test.js',   
      'node_modules/zone.js/dist/fake-async-test.js',   
      // RxJs   
      { pattern: 'node_modules/rxjs/**/*.js',   included: 
        false, 
        watched: false },   
      { pattern: 'node_modules/rxjs/**/*.js.map',   
        included: false, 
        watched: false },   
      // Paths loaded via module   imports:   
      // Angular itself   
      { pattern: 'node_modules/@angular/**/*.js',   
        included: false, 
        watched: false },   
      { pattern: 'node_modules/@angular/**/*.js.map',   
        included: 
        false, watched: false },   
      { pattern: appBase + '/systemjs.config.js',   
        included: false, 
         watched: false },   
      { pattern: appBase + '/systemjs.config.extras.js',   
        included: 
        false, watched: false },   
      'karma-test-shim.js', //   optionally extend 
       SystemJS mapping 
       e.g., with barrels   
      // transpiled application   & spec code paths loaded 
         via module 
         imports   
      { pattern: appBase + '**/*.js',   included: false, 
        watched: true   
  },   
      { pattern: testingBase + '**/*.js',   included: 
        false, watched:  
        true 
  },   
      // Asset (HTML & CSS)   paths loaded via Angular's 
         component    
         compiler   
      // (these paths need to be   rewritten, see proxies 
          section)   
      { pattern: appBase + '**/*.html',   included: false, 
        watched: 
        true 
  },   
      { pattern: appBase + '**/*.css',   included: false, 
        watched: true        
  },    
      // Paths for debugging with   source maps in dev    
         tools   
      { pattern: appBase + '**/*.ts',   included: false, 
        watched: false   
  },   
      { pattern: appBase + '**/*.js.map',   included: 
        false, watched: 
        false 
  },   
      { pattern: testingSrcBase +   '**/*.ts', included: 
        false, 
        watched: false },   
      { pattern: testingBase + '**/*.js.map',   included: 
        false, 
        watched: false}   
    ],   
    // Proxied base paths for   loading assets   
        proxies: 
  {   
      // required for modules   fetched by SystemJS   
      '/base/src/node_modules/': '/base/node_modules/'   
  },   
    exclude: [],   
    preprocessors: {},   
    reporters: ['progress', 'kjhtml'],   
    port: 9876,   
    colors: true,   
    logLevel: config.LOG_INFO,   
    autoWatch: true,   
    browsers: ['Chrome'],   
    singleRun: false   
   })   
 }   
```

命令`karma start`会以 karma 配置文件路径为参数，并启动 karma 测试运行器。`npm run build`命令配置在`pretest`中，这样它将在运行测试之前执行。它执行`tsc -p src`命令，这是一个 TypeScript 编译器，用于转译`src`文件夹中的代码。以下屏幕截图说明了根据`package.json`中`scripts`项中的配置，在命令窗口中执行这些命令：

```ts
C:\Users\rajesh.g\Packt\Chapter8\mytodos>npm     
            test> my-todo@1.0.0 pretest   
          C:\Users\rajesh.g\Packt\Chapter8\mytodos> npm run build> my-todo@1.0.0 build   
          C:\Users\rajesh.g\Packt\Chapter8\mytodos> tsc -p src/> my-todo@1.0.0 test   
          C:\Users\rajesh.g\Packt\Chapter8\mytodos> concurrently "npm run   build:watch" "karma 
            start 
            karma.conf.js"
```

Karma 在浏览器中启动应用程序，并运行 specs 中的所有测试。`http-server`命令将启动开发服务器，以托管`mytodo` Angular 应用程序。测试执行结果如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_08_001.png)

TodoService 的测试结果

## Angular 组件测试

* * *

我们刚刚学习了如何在 Angular 应用程序中测试服务。现在，让我们讨论如何测试 Angular 组件。执行以下步骤来为应用程序创建`AppComponent`：

1.  创建名为`app.component.ts`的文件。

1.  导入必要的`Component`、`TodoService`和`Todo`等模块，用于`AppComponent`，如下所示：

```ts
        import { Component } from '@angular/core'; 
        import { Todo } from './todo'; 
        import { TodoService } from './todo.service'; 
```

1.  如下所示，定义`AppComponent`类：

```ts
        export class AppComponent {} 
```

1.  通过`@Component`属性装饰`AppComponent`类，具有`selector`，`providers`和`templateUrl`元数据：

```ts
        @Component({ 
            selector: 'my-app', 
            templateUrl: './app.component.html', 
            providers: [TodoService] 
        }) 
        export class AppComponent {     
        } 
```

1.  声明`todos`，`todoService`，`newTodoText`和`title`变量：

```ts
        todos: Array<Todo>; 
        todoService: TodoService; 
        newTodoText = ''; 
        title = 'Test My Todo App'; 
```

1.  定义构造函数，并注入`todoService`，如下所示。请注意，构造函数使用`todoService`返回的`todos`更新`todos`：

```ts
        constructor(todoService: TodoService) 
        { 
              this.todoService = todoService; 
              this.todos = todoService.todos; 
        } 
```

1.  引入`addTodo()`函数，调用`TodoService`的`add()`方法，并传递新`todo`的描述，如下图所示：

```ts
        addTodo() 
        { 
              if (this.newTodoText.trim().length) 
              { 
                  this.todoService.add(this.newTodoText); 
                  this.newTodoText = ''; 
              } 
        }
```

1.  引入调用`TodoService`的`remove()`方法通过传递要移除的`todo`对象来移除该对象的`remove()`函数，如下所示：

```ts
       remove(todo: Todo) 
       { 
              this.todoService.remove(todo); 
       } 
```

1.  引入调用`TodoService`的`removeCompleted()`方法来删除所有已完成的待办事项的`removeCompleted()`函数：

```ts
      removeCompleted() 
      { 
            this.todoService.removeCompleted(); 
      } 
```

1.  引入调用`TodoService`的`toggleCompletion()`方法来切换`todo`项的完成状态值的`toggleCompletion()`函数：

```ts
      toggleCompletion(todo: Todo) 
      { 
             todo.completed = !todo.completed; 
      } 
AppComponent is this:
```

```ts
import { Component } from '@angular/core'; 
import { Todo } from './todo'; 
import { TodoService } from './todo.service'; 
@Component({ 
    selector: 'my-app', 
    templateUrl: './app.component.html', 
    providers: [TodoService] 
}) 
export class AppComponent { 
    todos: Array<Todo>; 
    todoService: TodoService; 
    newTodoText = ''; 
    title = 'Test My Todo App'; 
    constructor(todoService: TodoService) { 
        this.todoService = todoService; 
        this.todos = todoService.todos; 
    } 
    removeCompleted() { 
        this.todoService.removeCompleted(); 
    } 
    toggleCompletion(todo: Todo) { 
        this.todoService.toggleCompletion(todo); 
    } 
    remove(todo: Todo) { 
        this.todoService.remove(todo); 
    } 
    addTodo() { 
        if (this.newTodoText.trim().length) { 
            this.todoService.add(this.newTodoText); 
            this.newTodoText = ''; 
        } 
    } 
} 
```

现在我们已经准备好了`AppComponent`。此`AppComponent`的模板定义在一个模板文件`app.component.html`中。

### 编写 AppComponent 的规范

让我们使用 Jasmine 来编写测试 `AppComponent` 的规范：

1.  创建一个`app.component.spec.ts`文件来为`AppComponent`编写规范或测试。

1.  从 Angular 核心中导入模块，例如 `async`、`ComponentFixture`、`TestBed`、`FormsModule`、`By`、`DebugElement` 和 `AppComponent`。

1.  写以下的`describe`全局函数并声明必要的变量：

```ts
     describe('AppComponent (templateUrl)', () => {
       let comp:    AppComponent; 
       let fixture: ComponentFixture<AppComponent>; 
       let de:      DebugElement; 
       let el:      HTMLElement; 
     });
```

1.  然后，创建两个`beforeEach`函数：一个用于编译模板和 CSS，另一个用于获取组件的实例。代码段如下所示：

```ts
    // async beforeEach 
    beforeEach(async(() => { 
        TestBed.configureTestingModule({ 
          imports: [FormsModule], 
          declarations: [ AppComponent ], // declare the     
    test component 
        }) 
        .compileComponents();  // compile template and css 
     })); 
     // synchronous beforeEach 
     beforeEach(() => { 
        fixture = TestBed.createComponent(AppComponent); 
        comp = fixture.componentInstance; // AppComponent     
    test instance 
        // query for the title <h1> by CSS element    
           selector 
        de = fixture.debugElement.query(By.css('h1')); 
        el = de.nativeElement; 
     }); 
```

对于每个测试，我们可能会重复相同的代码来初始化或清除一些对象。为了简化开发者的工作，Jasmine 提供了在执行每个测试方法之前和之后运行的Â `beforeEach` 和 `afterEach` 全局功能。

1.  最后，添加`it`测试或规范函数来验证期望，如下所示：

```ts
    it('no title in the DOM until manually call     
    `detectChanges`', () => { 
    expect(el.textContent).toEqual(''); 
    }); 
    it('should display original title', () => { 
        fixture.detectChanges(); 
        expect(el.textContent).toContain(comp.title); 
    });
    it('should display a different test title', () => { 
        comp.title = 'Test My Todo'; 
        fixture.detectChanges(); 
        expect(el.textContent).toContain('Test My Todo'); 
    }); 
app.component.spec.ts is as follows:
```

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing'; 
import { FormsModule } from '@angular/forms'; 
import { By }              from '@angular/platform-browser'; 
import { DebugElement }    from '@angular/core'; 
import { AppComponent } from './app.component'; 
describe('AppComponent (templateUrl)', () => { 
  let comp:    AppComponent; 
  let fixture: ComponentFixture<AppComponent>; 
  let de:      DebugElement; 
  let el:      HTMLElement; 
  // async beforeEach 
  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      imports: [FormsModule], 
      declarations: [ AppComponent ], // declare the test component 
    }) 
    .compileComponents();  // compile template and css 
  })); 
  // synchronous beforeEach 
  beforeEach(() => { 
    fixture = TestBed.createComponent(AppComponent); 
    comp = fixture.componentInstance; // AppComponent test instance 
    // query for the title <h1> by CSS element selector 
    de = fixture.debugElement.query(By.css('h1')); 
    el = de.nativeElement; 
  });
  it('no title in the DOM until manually call `detectChanges`', () => { 
    expect(el.textContent).toEqual(''); 
  });
  it('should display original title', () => { 
    fixture.detectChanges(); 
    expect(el.textContent).toContain(comp.title); 
  });
  it('should display a different test title', () => { 
    comp.title = 'Test My Todo'; 
    fixture.detectChanges(); 
    expect(el.textContent).toContain('Test My Todo'); 
  }); 
}); 
```

### 运行 AppComponent 的规范或测试

在命令行窗口中执行`npm test`命令，应用程序将启动，并为您运行测试。以下截图显示了针对`AppComponent`运行的测试或规范的结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_08_002.png)

AppComponent 的测试结果

## 单元测试一个模拟服务

* * *

通过将服务注入到组件中保持组件的精简，使我们能够使用模拟服务编写单元测试。我们可以通过模仿服务行为使用其接口来模拟注入的服务：

```ts
class MockTodoService extends TodoService   {   
    getPending() {   
        return [];   
    }   
}      
```

在这里，我们通过扩展和覆盖`getPending`方法创建了一个现有待办服务的模拟，以返回一个空数组。

我们可以使用 `testBed` 来测试这一点，指示如何使用模拟服务 `MockTodoService` 而不是实际服务 `TodoService`，如下所示：

```ts
beforeEach(async(() => {   
      TestBed.configureTestingModule({   
        providers: [   
        {   
            provide: TodoService,   
            useClass:   MockTodoService   
        }   
    ]})   
    .compileComponents();   
}));   
```

在这里，我们指示如何使用 `MockTodoService` 而不是 `TodoService`，并且可以跳过测试的结果，如下所示：

```ts
it('should return empty array   when getPending method is fired', () => {   
   let service =   fixture.debugElement.injector.get(TodoService);   
   spyOn(service, 'getPending').and.returnValue([]);        
});
```

这里，它从 fixture 中获取模拟服务Â `MockTodoService`，并添加一个 spyOn 覆盖，假装列表中没有待办事项。

## 总结

* * *

万岁！我们学会了为 Angular 应用程序编写自动化测试的基础知识。

我们从介绍 Jasmine 框架开始这一章，学习如何编写有效的测试并自动运行它们。然后，我们学习了如何使用 Jasmine 框架测试组件和服务，并断言应用程序的行为。最后，我们讨论了模拟服务并使用 spyOn 进行测试。

在下一章中，我们将讨论一些关于 Angular 和 .NET Core 的新主题。


## 第九章：Angular 和 ASP.NET Core 中的新功能

我们从讨论 Angular、构建一个 Hello World 应用程序和 Angular 的核心架构开始了本书。然后，我们深入了解了 Angular 的构建块。接下来，我们讨论了 TypeScript 的基础知识以及如何在编写 Angular 应用程序时使用 TypeScript。之后，我们在 Visual Studio 中逐步创建了一个 Angular 单页面应用，并学习了 RESTful 服务以及如何使用 Web API 为 Angular 应用创建 RESTful 服务。之后，我们通过使用 Angular、ASP.NET MVC 和 Web API 在 Visual Studio 中逐步创建了一个应用程序。最后，我们学习了如何使用 Karma 和 Jasmine 测试 Angular 应用。

本章将讨论 Angular 和 ASP.NET Core 中的新功能。我们将涵盖以下话题：

+   预编译

+   模板更新

+   引入标题大小写管道

+   简化 HTTP 参数传递

+   在测试中覆盖模板

+   Meta 服务的引入

+   新的表单验证器

+   在路由器中引入 ParamMap

+   引入 .NET Core 1.0

+   .NET 执行环境下的跨平台开发

## Angular 的新功能

* * *

Angular 团队已经放弃了 Angular 3，并决定遵循语义化版本控制推进 Angular 4。这有助于标准化主要、次要和补丁版本的版本号。语义化版本控制的版本号将分为三个段。在语法或概念上的任何破坏性变化将被视为主要，第一个段的版本号将会递增。任何新增功能都将被视为次要，第二个段的版本号将会递增，并且对于任何 bug 修复，第三个段的版本号会递增，视它们为补丁：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_001.png)

图 01：语义化版本控制

### 预编译

Angular 引入了一个重大改变，即在构建应用程序时生成 JavaScript 代码。这样可以在构建时了解模板中是否存在任何错误，而不是在运行时被通知。此外，它还可以让应用程序运行得更快，因为在构建阶段已经完成了代码生成。新的 Angular 视图引擎在使用 **预编译**（**AoT**）时生成更少的代码。

### 模板更新

由于模板是 Web 组件的真实 HTML 标签，Angular 引入了一个新的 `ng-template` 标签来作为模板。Angular 允许我们在模板中使用 `ngIf` 的 `else`，如下所示：

```ts
<div *ngIf="isOld; then   content else new_content">placeholder</div>   
<ng-template   #content><h2>old content body.</h2></ng-template>   
<ng-template   #new_content><h2>body of new content.</h2></ng-template>   
```

如果 `isOld` 为 true，则会显示旧模板的内容。否则，将显示新模板的内容。

接下来让我们讨论模板语法中新增的 `as` 关键字。它被引入以简化 `let` 的语法，使我们能够将结果存储在模板变量中：

```ts
<ul>   
   <li *ngFor="let book of   books | slice:0:10 as topTenBooks; index as idx">   
      {{ topTenBooks.length - idx   }}: { book.name }}   
   </li>   
</ul>   
```

在这里，我们使用了`as`关键字来将切片的结果存储在`topTenBooks`变量中，并在`li`标签中进一步引用它。请注意，我们还给了一个别名`i`，用于索引，这是`let i = index`语法的简写。

我们也可以将`as`关键字和`async`一起使用，如下所示：

```ts
<ul>   
   <li *ngFor="let book of   books$ | async">   
      {{ book.name }}   
   </li>   
</ul>    
<h3>{{ ( books$ |   async)?.length }} books</h3>   
```

在这里，我们将我们的`books`集合作为 Observable。因此，我们已经遍历了从 Observable 返回的书籍数组。请注意，我们还显示了从 Observable 返回的书籍数量。然而，这会导致性能开销，因为使用的异步管道会在发生更改时重新运行。以下是进一步的改进，避免了这种性能开销：

```ts
<div *ngIf="books$ | async as   books">   
   <ul>   
      <li *ngFor="let book of   books">   
         {{ book.name }}   
      </li>   
   </ul>   
<div>   
<h3>{{  books.length }}   books</h3>   
```

在这里，我们使用了`as`关键字来在父组件中存储管道值。请注意，我们仅使用了一次 async。

### 介绍 titlecase 管道

titlecase 管道将单词的第一个字母变为大写。我们可以如下使用 titlecase：

```ts
<p>{{ 'rajesh gunasundaram'   | titlecase }}</p>      
 the parsed HTML will be    <p>Rajesh Gunasundaram</p>   
```

### 在 HTTP 中简化参数传递

```ts
sort parameter in the HTTP GET call:
```

```ts
http.get('http://www.programmerguide.net/api/articles`,   { params: { sort: 'ascending' } });   
```

### 在测试中重写模板

有时在测试期间需要重写模板。Angular 现在简化了重写模板，如下所示：

```ts
TestBed.overrideTemplate(BookComponent,   '<h1>{{book.title}}</h1>');   
```

在那之前，我们需要构建 JSON 并传递它。

## 介绍 Meta 服务

* * *

Angular 引入了一个名为 Meta 服务的新服务，简化了更新或获取`meta`标签：

```ts
@Component({   
  selector: 'book-list',   
  template: `<h1>Book   List</h1>`   
})   
export class BookComponent {   
  constructor(meta: Meta) {   
    meta.addTag({ name: 'author',   content: 'Rajesh Gunasundaram' });   
  }   
}   
```

### 新的表单验证器

新的验证器结合了现有的验证器，如`required`，`minLength`，`maxLength`，`email`和`pattern`。还介绍了一个新的指令`compareWith`，用于比较`select`控件中的选项，如下所示：

```ts
<select [compareWith]="byId"   [(ngModel)]="selectedBook">   
   <option *ngFor="let book of   books" [ngValue]="book">{{book.title}}</option>   
</select>   
byId(p1: BookModel, p2:   BookModel) {   
   return p1.id === p2.id;   
}   
```

### 介绍路由中的 ParamMap

Angular 引入了一个新的接口 ParamMap，用于映射 URL 中的参数。我们可以使用`paramMap`或`queryParamMap`来访问 URL 的参数。`ParamMap`具有诸如`get()`获取值或`getAll()`获取所有查询参数值的方法，如下所示：

```ts
const id =   this.route.snapshot.paramMap.get('bookId');   
this.bookService.get(id).subscribe(b   => this.book = b);   
```

在 observable 中，我们需要像下面这样使用`ParamMap`进行说明：

```ts
this.route.paramMap   
  .map((params: ParamMap) =>   params.get('bookId'))   
  .switchMap(id =>   this.bookService.get(id))   
  .subscribe(b => this.book =   b);   
```

## 介绍.NET Core 1.0

* * *

在本节中，我们将介绍.NET Core 1.0 作为一个平台的基础知识以及其中涉及的组件。

.NET Core 1.0 平台出于各种原因进行了改进。ASP.NET 的 Web 堆栈非常古老，始于.NET Framework 1.0。ASP.NET 存在大量古老和未使用的代码。即使代码不被使用，也难以避免加载它们。最大的问题是`System.Web`，它是老式 ASP.NET 和现在的 ASP.NET 之间的连接。MVC 和 Web API 正在试图与`System.Web`隔离。

ASP.NET、MVC 和 Web API 的自托管是其中一个目标，使它们能够独立于服务器平台进行托管。然而，它一直与 IIS 这个 Windows 平台绑定。当应用程序需要在更新到服务器时重新测试任何由于更新至新的.NET 版本而引入的新 bug 时，这就成了一个问题，因为它们依赖于机器级的.NET 版本，所以没有办法将.NET 版本与应用程序隔离开来，使其能够独立于新的.NET 版本运行。

由于必须加载大量代码、编译、写入磁盘、重新加载到内存中并执行，ASP.NET 团队决定从头开始重写代码，因为时间跨度受到了系统性能的影响。在 .NET Core 1.0 中，有很多事情发生了变化，它与任何其他版本的 ASP.NET 都有很大差异。这就是为什么给它起一个新的名字和新的版本号是合适的，因为它并不是一种渐进式的变化。

一个关键的区别是，.NET Core 1.0 是跨平台和开源的。.NET Core 1.0 是一个单一平台，将 MVC 和 Web API 的概念结合为一个坚实的 API 集，并且所有的遗留代码都消失了。在.NET Core 1.0 中一切都是一个依赖项。我们可以以我们想要的任何大小开发一个.NET 应用程序。.NET Core 的某些部分现在是一个 NuGet。因此，你可以从 NuGet 中仅加载所需的程序集，与之前版本的 ASP.NET 相比，这会导致内存占用更小。

在 .NET Core 1.0 中今天可以实现多个部署支持，这使我们能够部署到 Azure、AWS 和其他云服务中。你可以在 IIS 中进行托管，或者可以进行自托管，这使我们可以从命令行执行。.NET Core 1.0 支持真正的跨平台，并且可以在 Windows 和 OSX 或 Linux 上进行托管：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_002.png)

图 02：ASP.NET Core 1.0 的构建模块

如前述图所示，.NET Core 包括一个新的 CLR，在 OSX/Linux 和 Windows 上都得到支持。ASP.NET 也可以在 Mono 上运行。使用原生的 IIS 加载器，我们可以在 IIS 中加载和托管我们的应用程序。这个原生的 IIS 加载器直接将请求路由到 ASP.NET 而无需经过 ISAPI 过滤器等。在 Windows 平台上，你还可以使用一个叫做 `dotnet.exe` 的工具从命令行自托管应用程序。.NET Core 1.0 也支持在 Linux 和 OSX 上进行自托管，并且可以使用某种工具，比如 `dotnet.exe`，让应用程序只需使用命令行就可以运行。

自托管解决方案与 Node 很相似。在 Node 中运行，并且应用程序的根目录与 .NET Core 中的 `dotnet.exe` 工具的自托管方式非常相似。因此，跨平台支持，你编写的代码并不一定关心它在哪里被托管。

.NET Core 是新的跨平台.NET Framework 的子集。.NET Core 旨在尽可能小。CoreCLR 或.NET Core Framework 是.NET Framework 的子集。因此，.NET Core 中并不是所有功能都可用。例如，通过 System.Net 命名空间中的.NET Framework 内的邮件子系统来发送邮件。但是，这个功能并不存在，可以使用一些开源解决方案来实现。

.NET Core 团队希望通过 NuGet packages 来构建所有东西。因此，CLR 以及 C#和 VB 编译器之前的一切都是 NuGet 包。.NET Core 1.0 实际上是引导，CLR 并不完整。代码知道如何加载应用程序并启动它，然后 CLR 实际上管理该代码的执行。其他一切都将是 NuGet 包。MVC 查看静态文件进行日志记录、配置和身份验证；它们只是可以添加到项目的软件包。因此，在讨论创建厚或薄应用程序时，您可以决定在项目中包含什么。在 ASP.NET 中的所有内容都是可选的。

ASP.NET 5 团队已尝试采用 Node 包管理器，用于不同类型的工具支持，使用 npm 或 Bower 支持客户端库，使用 Grunt 和 Gulp 进行构建自动化，并使用 NuGet 进行.NET 包支持。

## 使用.NET Execution Environment 进行跨平台开发

* * *

在本节中，我们将讨论完整.NET 框架、Core CLR 和 DNX 的角色。我们将首先解释.NET 框架开发人员如何自.NET 开始就使用了执行环境。此外，我们将看到 Mono 和.NET Core。然后，我们将看到一些决定使用哪个框架的准则。最后，我们将看到 DNX 如何将一切绑在一起。

### 传统的.NET Framework

自.NET 开始以来，桌面和控制台应用程序已由可执行文件进行引导，传统的 ASP.NET 应用程序则通过 IIS 使用 ISAPI DLL 进行引导。在.NET 支持的任何语言中编写的应用程序都会被编译为程序集。程序集是包含**中间语言**（**IL**）的 EXE 或 DLL 文件。由于操作系统和 CPU 不理解 IL，因此需要将此 IL 文件编译为本机代码，这称为**即时**（**JIT**）编译。

JIT 在部署程序集的机器上执行之前，将 IL 代码编译为本机代码。JIT 功能是.NET CLR 或公共语言运行时的一部分。

CLR 负责加载程序集、检查类型和垃圾回收。因此，在应用程序运行的机器上安装.NET Framework 是必要的。大量的类和其他类型可用。它包含了所有 Windows Forms、WCF、WPF、web forms 所需的类型，以及在这些框架中可用的类型，例如文件处理、读取和操作 XML、绘图和密码。所有应用程序都使用其中的一些类。

CLR 专门设计用于在 Windows 上运行。此外，FCL 中的一些类专为 Windows 设计。`System.web`是一个包含与 IIS 和因此 Windows 相关联的类的程序集。传统.NET Framework 的构建模块包括以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_003.png)

图 03：传统.NET Framework 的构建模块

### Mono 跨平台.NET Framework

Mono 是由社区开发的.NET Framework 的开源版本。它使用了与 Microsoft .NET Framework 相同的原理。它与 Microsoft .NET Framework 兼容。即使你不使用 ASP.NET 5，你也可以在 Windows 机器上使用 Microsoft .NET Framework 和 Visual Studio 创建程序集，然后在 Linux 机器上使用 Mono 运行它们。所以，与 Microsoft .NET Framework 的一个重要区别是它是跨平台的。版本适用于 Windows、macOS 和 Linux。它还被用作 Xamarin 的基础，该基础在 Android 和 iOS 上运行.NET。

### NuGet 软件包管理器

Microsoft 引入了 NuGet 来管理包并方便地下载它们用于开发。NuGet 是获取库的中心位置。这些库和框架的开发人员可以轻松地向 NuGet 应用新版本或 bug 修复。Microsoft 开始在 FCL 中通常会出现的程序集中使用 NuGet。MVC 安装为应用程序中的 NuGet 包，而不像 FCL 那样在整个机器上安装。这使不同的应用程序可以使用不同版本的 MVC 而无需安装不同版本的.NET Framework。通过 NuGet 分发 MVC 使 Microsoft 能够在.NET Framework 之外"越分频"地更新 MVC，从而使 MVC 能够更快地演进并得到更频繁的更新。这是一个完全模块化的框架类库与.NET Core 的乐观预示。

### .NET Core 中的 CoreFx 和 CoreCLR

多年来，.NET 已经被重新发明多次。有一个用于 Windows 桌面、Windows 商店应用和 Windows Phone 的.NET Framework。我们还有一个我们一直用于 ASP.NET 4 和更早版本应用的框架。微软发明了一种方法，可以使用可移植类库和通用应用概念在所有不同平台之间共享代码。然而，如果我们有一个所有平台通用的.NET 版本，那不是更容易吗？不仅对于微软来说，要保持所有这些堆栈更新，而且对于我们这些必须学习和维护所有这些版本的开发者来说也是如此。.NET Core 的目的是成为统治所有版本的唯一.NET 版本，这一切都始于 ASP.NET！.NET Core 的另一个动机是减少总体占用空间。从 ASP.NET 的角度来看，使用`system.web`实际上已经不再是一个选项。此外，在一台机器上拥有一个庞大的.NET Framework，导致版本问题并包含许多不需要的东西是很麻烦的。在这个以云为驱动的世界里，被固定在 Windows 上已经不合时宜。.NET Core 最激动人心的功能是它可以使用新的 DNX 跨操作系统运行。

就像完整的.NET Framework 一样，.NET Core 也由两部分组成：一个是普通语言运行时，现在是可移植的，名为 CoreCLR，另一个是称为 CoreFX 的类库。CoreFX 包含一组类型，这些类型是所有.NET 应用程序通用的。它不包括像完整的.NET Framework 中的 FCL 那样的完整的框架，比如 WPF 或 Web forms。例如，它包含用于操作文件的类和类似列表的集合类。CoreFX 的不同程序集都是通过 NuGet 单独分发的。除了 CoreFX 之外，你还需要从 NuGet 中获取其他所需的一切，比如 MVC 框架。不仅 CoreFX 以 NuGet 包的形式分发，CoreCLR 也是如此。.NET Core 是微软所谓的云优化的。这基本上意味着它很轻量级。它不仅比完整的.NET Framework 小得多，而且包含了一些优化：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_004.png)

图 04: .NET Core 的构建模块

就像任何 NuGet 包一样，.NET Core 可以在每个项目中从 NuGet 中恢复。当你将应用程序发布到服务器时，你还可以将 CoreCLR 与你的应用程序一起发布。因此，不再需要进行机器范围的安装。服务器上的每个应用程序都可以具有自己的.NET Core 版本，而不会影响其他应用程序。.NET Core 以及 DNX 都是开源软件，这意味着除了微软之外，社区也在进行相关工作，而你也可以参与其中。这还确保了如果微软决定停止工作的话，这些项目也会继续进行下去：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_005.png)

图 05: .NET 应用程序框架

### 选择一个框架

如何选择要使用的框架？在必须全局安装正确版本的.NET Framework 或 Mono 以支持应用程序的计算机上，您可以在一个服务器上开发使用不同版本的.NET Core 的应用程序。您还可以更新一个应用程序以使用较新版本的.NET Core，而不影响其他应用程序。使用.NET Framework 或 Mono，您有最好的机会使用现有代码。它提供了大量的类和其他类型。 CoreFX 是一个不同的类库，当使用现有代码时，您可能需要重构。此外，CoreFX 具有更少可用类型的选择，并且不是您习惯于使用额外包都可以提供的所有内容。它是一个仍需发展的生态系统，其中 FCL 非常完整，而且是经过验证的技术。然而，它包含了许多您可能不需要的内容。如果您的应用程序必须跨平台运行，那么使用 Mono 或.NET Core 是您的选择。.NET Framework 仅在 Windows 上运行。如果您正在为自己的业务开发组件库，或者想要商业分发它们，那么针对多个框架开发组件库是有意义的。您的库可以被使用所有选择的框架的应用程序所使用。

或者，也许您现在必须编写一个应用程序，以后再决定它必须在哪个框架上运行。在下一节中，我们将看到 DNX 在所有这些过程中扮演的角色：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_006.png)

图 06：选择框架的标准

### Dotnet 执行环境- DNX

DNX 的主要作用是通过在框架中托管 CLR 来运行.NET 应用程序。新引入的命令行界面 dotnet cli 具有 DNX 的可执行部分。Dotnet cli 有助于运行应用程序，并还原`project.json`中指定的包。

DNX 命令行应用程序有自己的处理过程来执行应用程序，而不是 Windows 或 IIS 执行应用程序；DNX 托管 CLR 而不是操作系统。DNX 将寻找一个`Main`方法形式的入口点并从那里运行应用程序。由于独立进程运行应用程序，因此不再依赖于操作系统，DNX 命令行应用程序可以针对多个操作系统开发，如 Windows、Linux 和 macOS。现在，在 Visual Studio 中开发的应用程序可以跨平台运行。对于每个操作系统都有针对相应.NET Framework 的 DNX 版本。也可以有支持不同 CPU 架构的版本。例如，对于完整的.NET Framework，有 x86 版本和 x64 版本。

不同版本的 DNX 可以共存于一台机器上。你可以选择将它们安装在整个机器的中央位置，也可以选择将 DNX 作为应用程序部署的一部分。使用该方法完全不需要进行整机安装。如果你在 Visual Studio 中发布应用程序，你需要选择在`project.json`的框架部分中配置的 DNX 版本。该版本的 DNX 将随部署的应用程序一起分发：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_007.png)

图 07：DNX 的构建模块

DNX 是 dotnet cli 的一部分，它在 dotnet 命令行应用程序中公开其功能。当你在 Visual Studio 中运行一个 DNX 应用程序时，Visual Studio 只是执行一个命令行。例如，当你运行时，它将执行`dotnet run`，这将使 DNX 开始工作。在运行应用程序时，DNX 也支持调试。当你向`project.json`文件添加 NuGet 包时，它只会执行`dotnet restore`。此外，还有一些用于编译和发布应用程序的命令。Dotnet cli 只是在命令行上给出的一个命令，所以不需要使用 Visual Studio 来执行。你可以直接输入命令来执行，或者使用其他工具来调用它。这样的一个例子就是可以跨平台运行的 Visual Studio Code。`dotnet`命令将在 ASP.NET 5 版本 RC2 及更高版本中使用。不同的命令行应用程序，如 DNX 和 DNU，都统一在 dotnet 命令行中。例如，当你执行`dotnet restore`时，它将读取`project.json`文件，并根据需要下载和安装包。因此，DNX 不仅是一个运行时环境，它还是一个 SDK。当你在应用程序的文件夹中执行`dotnet run`时，运行时部分就会启动。

## 部署选项

* * *

有四个部署选项。所有选项都受到 dotnet 命令行界面的支持。你可以选择复制应用程序的项目，让 DNX 恢复包，并运行应用程序。必须预先安装兼容的 DNX 版本；使用 CLI 命令`dotnet run`。

你也可以让 CLI 在你的开发机上编译项目。复制程序集并运行：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_008.png)

图 08：部署选项

还有一个选项是使用命令行开关本地编译应用程序。这意味着生成的不是 IL 的程序集，而是可以直接在没有 DNX 或任何 .NET Framework 帮助下直接执行的本机二进制文件。

还有一个选项是将你的应用程序打包成一个 NuGet 包，以便使用`dotnet pack`轻松共享你的项目。该包将包含`project.json`文件中配置的所有框架的支持。然后你可以将其上传到全局的 NuGet feed，或者只针对你的公司上传。

最后一个选项是使用 dotnet cli 发布应用程序，使用`dotnet publish`。

所有所需的程序集和 DNX 本身都包括在部署中。由于部署的 DNX 是特定于操作系统的，如果您在不同操作系统上部署，则需要额外的工作才能使此选项起作用。

### 使用 Visual Studio 发布

我们将学习使用 Visual Studio 部署应用程序。如果我们右键单击项目的 web 节点，我们可以选择发布，然后发布将允许我们选择目标。Visual Studio 将要求您提供要创建和存储发布配置文件的名称，以备将来使用：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_009.png)

图 09：创建发布配置文件

我们可以选择 Azure Web 应用程序、文件系统和其他部署模式。在**`Settings`**中，我们还可以选择要使用的配置和要使用的 DNX 版本。在这里，您只会看到与您在`project.json`文件的 frameworks 部分中指定的匹配的选项。最后，我们可以发布应用程序：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_010.png)

图 10：选择 DNX 版本

发布时，它首先运行`prepare`语句，然后运行`prepublish`，以将所有内容打包到临时文件夹中，然后将其复制到文件系统。发布成功后，打开命令行界面并导航至发布文件夹。

请注意文件夹中包括在项目文件中定义的命令和 shell 脚本。还要注意`approot`文件夹包含应用程序所需的软件包和运行时。

如果您在 Windows 平台上，可以使用 web 命令启动应用程序。您只需打开浏览器并导航到带有`5000`端口的`localhost`，我们就可以看到我们的应用程序实际在运行。应用程序直接从命令 shell 而不是在 IIS 下运行。

### 使用 dotnet 命令行界面发布

让我们看看如何使用 dotnet 命令行界面进行发布。从 Visual Studio 中，在我们应用程序的项目文件夹中直接打开命令 shell。如果我们查看`DOTNET`命令，我们可以看到它有许多命令，您可以在其中构建您的项目并安装依赖项，尤其是基于 NuGet 的依赖项。您可以处理软件包并发布应用程序。以下是显示命令中各种选项和参数的 Windows 结果的命令：

`C:\Rajesh\Packt\Angular2>dotnet`.NET 命令行界面用法：dotnet [common-options] [command] [arguments]

+   参数：[command]：要执行的命令 [arguments]：要传递给命令的参数

+   常用选项：(在命令之前传递)：`-v|--verbose` 启用详细输出

+   常用命令:`new`: 初始化一个基本的.NET 项目`restore`: 恢复.NET 项目中指定的依赖项`compile`: 编译.NET 项目`publish`: 发布.NET 项目以供部署（包括`运行时)run`: 编译并立即执行.NET 项目`repl`: 启动交互式会话（读取、求职、打印、循环）`pack`: 创建一个 NuGet 包

dotnet 命令行界面非常有用，因为您实际上可以编写脚本来完成所有这些过程，您可以让其安装依赖项，运行构建，然后发布。因此，它提供了一种轻松的方式来自动化许多这些任务。事实上，Visual Studio 只是使用 Dotnet 工具来自动化这一切。

发布的文件夹包含应用程序的代码，所有依赖项，客户端依赖项，工具依赖项和 NuGet 依赖项，并且包含所需的整个版本的运行时。我们可以将此文件夹放在任何计算机上并运行。如果要为 Linux 或 OS 10 打包这个文件夹，您将需要适用于这些平台的运行时版本，如 CoreCLR。该文件夹包含独立的应用程序，并可以在任何浏览器上运行。这不使用安装在计算机上的任何框架；它全部包含在一个文件夹中，完全可移植。

### 部署到 IIS

当您部署到 IIS 服务器时，需要确保已安装作为反向代理的`HttpPlatformHandler`模块。当请求到来时，IIS 将其转发到另一个进程，通常是一个命令行应用程序。IIS 将根据需要启动和停止进程，并处理并发问题。

在 IIS 管理应用程序中，我们的应用程序被视为另一个网站，并且可以在 IIS 中进行配置。我们需要通知 IIS 在我们的应用程序收到请求时执行 DNX。我们可以使用项目文件夹中的`web.config`来实现。IIS 仍然使用`web.config`来使用`HttpPlatformHandler`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_011.png)

图 11：在 web.config 文件中配置 HttpPlatformHandler

`HttpPlatformHandler`扩展已经在 IIS 中注册，并被指示在收到请求时执行启动 DNX 进程的批处理文件。所以，让我们在 IIS 中配置应用程序。

要配置我们的应用程序，请启动 IIS 管理器。右键单击根服务器节点，选择**`添加网站`**，输入应用程序名称，应用程序池将自动生成：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_012.png)

图 12：向 IIS 添加网站

在物理路径文本框中设置发布应用程序的`wwwroot`文件夹的路径，然后点击**`OK`**。由于 CLR 正在独占进程中运行，我们需要在应用程序池下设置**`无托管代码`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_013.png)

图 13：在应用程序池中设置.NET CLR 中的无托管代码

我们这样做是因为我们不需要 IIS 为我们的应用程序托管 CLR。点击**`OK`**并浏览到端口`8080`的`localhost`将启动我们的应用程序。这样一来，我们就可以使用 IIS 的功能来为 DNX 应用程序提供动力，就像在 IIS 中托管任何其他 Web 应用程序一样。

### 部署到 Microsoft Azure

使用 Azure 的应用服务进行部署非常顺畅。当应用程序发布到 Azure 时，会创建一个新的虚拟机，或者它会托管在运行 IIS 的现有虚拟机上，该虚拟机装有`HttpPlatformHandler`。部署流程与在本地服务器上部署到 IIS 相同。

在 IIS 中必须创建一个新的网站，并且发布的内容必须上传到服务器。所有这些都可以通过在 Visual Studio 中创建一个发布配置文件来完成，选择**`Microsoft Azure App Service`**。我们可能需要登录 Azure 账户，选择一个订阅，然后通过给出一个名称在 Azure 中创建一个新的应用。URL 将是`yourappname.azurewebsites.net`。在**`设置`**下，我们需要选择 DNX 并点击**`发布`**。浏览到`yourappname.azurewebsites.net`将在 Azure 中运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_09_014.png)

图 14：选择发布目标

### 部署到 Linux 和 macOS

让我们看看如何从 Visual Studio 部署应用程序到 Linux 或 macOS 上。我们还可以使用 Visual Studio Code 在 Linux 或 macOS 平台上开发应用程序。

首先，为框架安装一个 DNX，.NET Core 或 Mono。然后，复制整个 Visual Studio 项目，包括源代码和`project.json`，但不包括任何程序集。

然后，使用 dotnet cli 来还原所有的 NuGet 包。这将包括 DNX 托管 CLR 在.NET Core 中所需的程序集。然而，NuGet 包可能依赖于其他包，因此在还原之前必须有某种包所需的所有包的列表。编制这样一个列表需要时间，因为所有的包都必须被检查，看看它们的依赖关系是什么。锁定文件包含了这个编制的列表，因此只需要做一次核实。所有后续的还原都使用锁定文件，前提是`project.json`中包的列表没有改变。

最后，指示 DNX 使用 Kestrel 作为 Web 服务器运行程序。DNX 将使用 Kestrel 作为入口点，然后 Kestrel 将托管应用程序。Kestrel 会通知我应用程序在端口`5000`上运行。通过使用端口`5000`的`localhost`作为域名浏览将在 Linux 或 macOS 中启动我们的应用程序。

## 摘要

* * *

这就是全部，伙计们！我们讨论了 Angular 和 .NET Core 1.0 中的新功能。我们首先介绍了 Angular 中引入的新特性。我们探讨了对 Angular 中各种现有方法的改进。最后，我们详细了解了 .NET Core 1.0 和 .NET Execution Environment 中的跨平台开发。我们了解了完整的 .NET Framework、.NET Core 和 Mono 之间的区别。此外，我们还介绍了 DNX 以及它在以全新方式开发 .NET 应用程序中的作用。
