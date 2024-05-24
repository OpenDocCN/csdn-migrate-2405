# Angular 设计模式（二）

> 原文：[`zh.annas-archive.org/md5/7218DB9929A7962C59313A052F4806F8`](https://zh.annas-archive.org/md5/7218DB9929A7962C59313A052F4806F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：导航模式

在本章中，我们将探讨一些最有用的导航面向对象模式，并学习如何在 Angular 方式中应用它们。导航模式用于组织与用户在我们应用程序上的导航相关的事件。

Angular 本身是一个面向对象的框架，它强制你以某种方式进行大部分开发。例如，你需要有组件、服务、管道等。强制这些构建块对你有利，有助于构建良好的架构，就像 Zend 框架对 PHP 或 Ruby on Rails 对 Ruby 所做的那样。当然，此外，框架还能让你的生活更轻松，加快开发时间。

虽然 Angular 的设计方式远远超出平均水平，但我们总是可以做得更好。我并不认为我在本章中提出的是最终设计，你将能够用它们解决从面包店单页到火星一号任务的仪表板的任何问题——不幸的是，这样的设计并不存在，但它肯定会提高你的工具箱。

在这一章中，我们将学习以下模式：

+   模型-视图-控制器

+   Redux

# MVC

哦，MVC，老朋友 MVC。多年来你为我们效力。现在，人们希望你退休，最好不要闹腾。即使我也能看到，年轻的、单向的用户界面架构可以比你更聪明，让你看起来像过去的遗物。

在本节中，我们将首先描述模型-视图-控制器是什么，不管用什么编程语言来实现它，然后我们将看到将 MVC 应用于前端编程的缺点。最后，我将介绍一种在 Angular 中实现 MVC 的方法，这种方法在实现、维护和性能方面是有意义的。

# 大型的模型-视图-控制器

模型-视图-控制器设计模式背后的整个原则相对简单。事实上，如下图所示，它由三个块组成：模型、视图和控制器：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/04b1d7a0-5b88-441d-9609-ff9d10b06920.png)模型-视图-控制器概述

组件如下：

+   模型根据控制器发送的命令存储应用程序所需的数据。

+   控制器接收用户的操作（例如按钮的点击）并相应地指导模型更新。它还可以在任何给定时刻切换使用的视图。

+   视图在模型更改时生成并更新。

就是这样。

让我们看看纯 TypeScript 中简单的 MVC 实现会是什么样子。

首先，让我们像在第三章中那样定义一个`Movie`类，*经典模式*。在这个版本的`Movie`类中，我们只有两个属性：`title`和`release_year`，它们是使用 TypeScript 构造函数定义的：

```ts
class Movie{ 

    constructor(private title:string, private release_year:number){} 

    public getTitle():string{ 
        return this.title; 
    } 
    public getReleaseYear():number{ 
        return this.release_year; 
    } 
} 
```

然后，我们定义一个`Model`类，它使用`reference`关键字导入包含`Movie`类的`movie.ts`文件。这个模型类将负责更新视图，它有一个电影数组和两个方法。第一个方法`addMovie(title:string, year:number)`是`public`的，它在`movies`属性的末尾添加一个新电影。它还调用类的第二个方法`appendView(movie:Movie)`，这个方法是`private`的。这个第二个方法按照模型-视图-控制器的定义来操作视图。视图操作相当简单：我们在视图的`#movie`元素中添加一个新的`li`标签。新创建的`li`标签的内容是电影标题和发行年份的连接。

```ts
/// <reference path="./movie.ts"/> 

class Model{ 

    private movies:Movie[] = []; 

    constructor(){ 
    } 

    public addMovie(title:string, year:number){ 
        let movie:Movie = new Movie(title, year); 
        this.movies.push(movie); 
        this.appendView(movie); 
    } 

    private appendView(movie:Movie){ 
        var node = document.createElement("LI");  
        var textnode = document.createTextNode(movie.getTitle() + "-" + movie.getReleaseYear());  
        node.appendChild(textnode); 
        document.getElementById("movies").appendChild(node); 
    } 

} 
```

现在我们可以为我们的纯 TypeScript 模型-视图-控制器定义一个控制器。控制器有一个`private model:Model`属性，在构造函数中初始化。此外，定义了一个`click`方法。此方法以参数形式接受`string`和`number`，分别用于标题和发行年份。正如你所看到的，`click`方法将标题和发行年份转发给模型的`addMovie`方法。然后，控制器的工作就完成了。它不操作视图。你还会注意到`controller.ts`文件的最后一行：`let controller = new Controller();`。这行允许我们创建一个控制器的实例，以便视图可以绑定到它：

```ts

/// <reference path="./model.ts"/> 

class Controller{ 

    private model:Model; 

    constructor(){ 

        this.model = new Model(); 
    } 

    click(title:string, year:number){ 

        console.log(title, year); 
        this.model.addMovie(title, year); 

    } 

} 
let controller = new Controller(); 
```

我们模型-视图-控制器实现的最后一部分将是视图。我们有一个简单的 HTML 表单，提交时会调用以下操作：`controller.click(this.title.value, this.year.value); return false;`。`controller`已在`controller.ts`文件中定义为`let controller = new Controller();`。然后，对于参数，我们发送`this.title.value`和`this.year.value`，其中`this`指的是`<form>`。`title`和`year`分别指电影的标题和发行年份的字段。我们还必须添加`return false;`以防止页面重新加载。确实，HTML 表单在提交时的默认行为是导航到操作 URL：

```ts
<html> 
    <head> 
        <script src="mvc.js"></script> 
    </head> 
    <body> 
        <h1>Movies</h1> 

        <div id="movies"> 

        </div> 

        <form action="#" onsubmit="controller.click(this.title.value, this.year.value); return false;"> 

            Title: <input name="title" type="text" id="title"> 
            Year: <input name="year" type="text" id="year"> 
           <input type="submit"> 
        </form> 

    </body> 
</html> 
```

在页眉中，我们添加了通过以下命令生成的`mvc.js`脚本：`tsc --out mvc.js controller.ts model.ts movie.ts`。生成的 JavaScript 如下所示：

```ts
var Movie = /** @class */ (function () { 
    function Movie(title, release_year) { 
        this.title = title; 
        this.release_year = release_year; 
    } 
    Movie.prototype.getTitle = function () { 
        return this.title; 
    }; 
    Movie.prototype.getReleaseYear = function () { 
        return this.release_year; 
    }; 
    return Movie; 
}()); 
/// <reference path="./movie.ts"/> 
var Model = /** @class */ (function () { 
    function Model() { 
        this.movies = []; 
    } 
    Model.prototype.addMovie = function (title, year) { 
        var movie = new Movie(title, year); 
        this.movies.push(movie); 
        this.appendView(movie); 
    }; 
    Model.prototype.appendView = function (movie) { 
        var node = document.createElement("LI"); 
        var textnode = document.createTextNode(movie.getTitle() + "-" + movie.getReleaseYear()); 
        node.appendChild(textnode); 
        document.getElementById("movies").appendChild(node); 
    }; 
    return Model; 
}()); 
/// <reference path="./model.ts"/> 
var Controller = /** @class */ (function () { 
    function Controller() { 
        this.model = new Model(); 
    } 
    Controller.prototype.click = function (title, year) { 
        console.log(title, year); 
        this.model.addMovie(title, year); 
    }; 
    return Controller; 
}()); 
var controller = new Controller(); 
```

在执行方面，在加载时，HTML 页面将如下截图所示：

加载点处的模型-视图-控制器

然后，如果您使用表单并添加电影，它将自动影响视图并显示新的电影：

使用表单后的模型-视图-控制器

# 前端的模型-视图-控制器的限制

那么，为什么模型-视图-控制器模式在前端编程中并不被广泛使用，尤其是在像 Angular 这样的框架支持的情况下？首先，如果您正在使用 Angular 开发提供服务的应用程序，您很可能会有一个后端，您需要与其交换某种信息。然后，如果您的后端也使用模型-视图-控制器设计模式，您将得到以下层次结构：

前端和后端的模型-视图-控制器

在这个层次结构中，我们在另一个 MVC 实现的顶部有一个 MVC 实现。这些实现通过一个 API 服务进行通信，该服务向后端控制器发送请求并解析生成的视图。具体示例是，如果用户需要在您的应用程序中登录，他们将在前端看到“登录”视图，该视图由“用户”模型和“登录”控制器提供支持。一旦所有信息（电子邮件地址，密码）都已输入，用户点击登录按钮。这个点击触发了模型更新，然后模型使用 API 服务触发 API 调用。API 服务向您的 API 的“用户/登录”端点发出请求。在后端，请求被“用户”控制器接收并转发到“用户”模型。后端“用户”模型将查询您的数据库，以查看是否有提供的电子邮件地址和密码匹配的用户。最后，如果登录成功，将输出一个视图，其中包含用户信息。回到前端，API 服务将解析生成的视图并将相关信息返回给前端“用户”模型。然后，前端“用户”模型将更新前端“视图”。

对于一些开发者来说，这么多层次以及架构在前端和后端之间的重复似乎有些不对，尽管它通过明确定义的关注点分离带来了可维护性。

双重模型-视图-控制器不是唯一的问题。另一个问题是，前端模型不会是*纯*模型，因为它们必须考虑到与 UI 本身相关的变量，比如可见标签、表单有效性等。因此，你的前端模型往往会变成代码的丑陋堆积，其中 UI 变量与用户的实际表示相互交织。

现在，像往常一样，你可以避免这些陷阱，并利用 MVC 模式的优势。让我们在下一节中看看如何做到这一点。

# Angular 的模型-视图-控制器

在这一部分，我提出了一个在 Angular 中证明有效的 MVC 架构。在过去的 18 个月里，我在`toolwatch.io`（Web、Android 和 iOS）上使用了这个架构。显然，我们在 Web 版本或移动应用上提出的功能是相同的，并且以相同的方式工作。改变的是视图和导航模式。

以下图表代表了整体架构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/5f5eae16-e4ec-49f1-b524-8fece9c61d58.png)Angular 的 MVC

从上到下，我们有后端、前端的可重用部分以及专门的前端（移动或 Web）。正如你所看到的，在后端，没有任何变化。我们保持了我们经典的 MVC。请注意，前端部分也可以与非 MVC 后端一起工作。

我们的模型将使用该服务通过一个假设的 JSON API 从远程数据库获取、放置和删除一个普通的 TypeScript 对象。

我们的`user` TypeScript 对象如下所示：

```ts
class User { 

    public constructor(private _email:string, private _password:string){} 

    get email():string{ 
        return this._password; 
    } 

    get password():string{ 
        return this._email; 
    } 

    set email(email:string){ 
        this._password = email; 
    } 

    set password(password:string){ 
        this._email = password; 
    } 
} 
```

这里没有太多花哨的东西；只是一个包含两个属性的普通 TypeScript 对象：`email:_string`和`password:_string`。这两个属性在构造函数中使用 TypeScript 内联声明样式进行初始化。我们还利用了 TypeScript 的 getter/setter 来访问`_password:string`和`_email:string`属性。你可能已经注意到，TypeScript 的 getter/setter 看起来像 C#属性。嗯，微软是 TypeScript 的主要工业研究者之一，所以这是有道理的。

我喜欢写作的简洁性，特别是与构造函数中的内联属性声明相结合时。然而，我不喜欢的是需要使用下划线变量名。问题在于，再一次强调，这个 TypeScript 将被转译为 JavaScript，在 JavaScript 中，变量和函数比如 Java 或 C#更加抽象。

实际上，在我们当前的示例中，我们可以调用`User`类的 getter 如下：

```ts
user:User = new User('mathieu.nayrolles@gmail.com', 'password');

 console.log(user.email); // will print mathieu.nayrolles@gmail.com
```

正如你所看到的，TypeScript 并不关心它调用的目标的类型。它可以是一个名为`email`的变量，也可以是一个名为`email()`的函数。无论哪种方式，它都可以工作。这些奇怪行为背后的基本原理是，对于面向对象的程序员来说，在 JavaScript 中，可以做以下操作是可以接受的：

```ts

 var email = function(){
 return "mathieu.nayrolles@gmail.com";
 }
 console.log(email);
```

因此，我们需要区分函数的实际变量与不同的名称，因此有了`_`。

现在我们有了一个经过验证的用户对象来操作，让我们回到我们的 MVC 实现。现在，我们可以有一个`user`模型来操作`user` POTO（普通的旧 TypeScript 对象）和图形界面所需的变量：

```ts
import { User } from '../poto/user'; 
import { APIService } from '../services/api.service'; 

export class UserModel{ 

    private user:User; 
    private _loading:boolean = false; 

 public constructor(private api:APIService){} 

    public signin(email:string, password:string){ 

        this._loading = true; 

        this.api.getUser(email, password).then( 

            user => { 
                this.user = user; 
                this._loading = false; 
            } 
        ); 
    } 

    public signup(email:string, password:string){ 

        this._loading = true; 
        this.api.postUser(email, password).then( 
            user => { 
                this.user = user; 
                this._loading = false; 
            }    
        ); 
    } 

    get loading():boolean{ 
        return this._loading; 
    } 

} 
```

我们的模型，名为`UserModel`，接收一个`APIService`的注入。`APIService`的实现留给读者作为练习。除了`APIService`之外，`UserModel`拥有`user:User`和`loading:bool`属性。`user:User`代表具体的用户，包括密码和电子邮件地址。然而，`loading:bool`将用于确定视图中是否应该显示加载旋转器。正如你所看到的，`UserModel`定义了`signin`和`signup`方法。在这些方法中，我们调用`APIService`的`getUser`和`postUser`方法，两者都接受一个用户作为参数，并返回一个包含已通过 JSON API 同步的用户的 promise。收到这些 promise 后，我们关闭`loading:bool`旋转器。

以下是`APIService`：

```ts
import { Injectable } from '@angular/core'; 
import { Http }  from '@angular/http'; 
import { User } from '../poto/user'; 
import { Observable } from 'rxjs/Rx'; 
import 'rxjs/Rx'; 
import { resolve } from 'dns'; 
import { reject } from 'q'; 

@Injectable() 
export class APIService { 

  private userURL:string = "assets/users.json"; 

  constructor(private http: Http) { } 

  /** 
   * Return a Promise to a USer matching id 
   * @param  {string}            email 
   * @param  {string}            password 
   * @return {Promise<User>}    
   */ 
  public getUser(email:string, password:string):Promise<User>{ 
      console.log('getUser', email, password); 

        return this.http.get(this.userURL) 
        /** 
         * Transforms the result of the http get, which is observable 
         * into one observable by item. */ 
        .flatMap(res => res.json().users) 
        /** 
         * Filters users by their email & password 
         */ 
        .filter((user:any)=>{ 
            console.log("filter", user); 
            return (user.email === email && user.password == password) 
        }) 
        .toPromise() 
        /** 
         * Map the json user item to the User model 
        */ 
        .then((user:any) => { 
            console.log("map", user);  
            return new User( 
                email, 
                password 
            ) 
        }); 
  }  

   /** 
   * Post an user Promise to a User 
   * @param  {string}            email 
   * @param  {string}            password 
   * @return {Promise<User>}    
   */ 
  public postUser(email:string, password:string):Promise<User>{ 

    return new Promise<User>((resolve, reject) => { 
        resolve(new User( 
            email, 
            password 
        )); 
    }); 
  } 

} 
```

`APIService`发出 HTTP 调用以解析包含用户信息的本地 JSON 文件：

```ts
{ 
    "users":[{ 
        "email":"mathieu.nayrolles@gmail.com", 
        "password":"password" 
    }] 
} 
```

`getUser(email:string, password:string):Promise<User>`和`postUser(email:string, password:string):Promise<User>`都使用了 promise，就像我们在上一章中展示的那样。

然后，还有控制器，它也将是 Angular 环境中的一个组件，因为 Angular 组件控制显示的视图等等：

```ts
@Component({
 templateUrl: 'user.html'
 })
 export class UserComponent{

 private model:UserModel;

 public UserComponent(api:APIService){

 this.model = new UserModel(api);
 }

 public signinClick(email:string, password:string){
 this.model.signin(email, password);
 }

 public signupClick(email:string, password:string){
 this.model.signup(email, password);
 }

 }
```

正如你所看到的，控制器（组件）非常简单。我们只有一个对模型的引用，并且我们接收一个注入的`APIService`来传递给模型。然后，我们有`signinClick`和`signupClick`方法，它们从视图接收用户输入并将其传递给模型。最后一部分，视图，看起来像这样：

```ts

 <h1>Signin</h1>

 <form action="#" onsubmit="signinClick(this.email.value, this.password.value); return false;">

 email: <input name="email" type="text" id="email">
 password: <input name="password" type="password" id="password">
 <input [hidden]="model.loading" type="submit">
 <i [hidden]="!model.loading" class="fa fa-spinner" aria-hidden="true"></i>
 </form>

 <h1>Signup</h1>

 <form action="#" onsubmit="signupClick(this.email.value, this.password.value); return false;">

 email: <input name="email" type="text" id="email">
 password: <input name="password" type="password" id="password">
 <input [hidden]="model.loading" type="submit">
 <i [hidden]="!model.loading" class="fa fa-spinner" aria-hidden="true"></i>
 </form>
```

在这里，我们有两种形式：一种用于登录，一种用于注册。这两种表单除了它们使用的`onsubmit`方法不同之外，它们是相似的。登录表单使用我们控制器的`signinClick`方法，注册表单使用`signupClick`方法。除了这两种表单，我们还在每个表单上有一个*font awesome*旋转器，只有当用户模型正在*加载*时才可见。我们通过使用`[hidden]`Angular 指令来实现这一点：`[hidden]="!model.loading"`。同样，当模型正在加载时，提交按钮也是隐藏的。

所以，这就是一个应用于 Angular 的功能性 MVC。

正如我在本节开头所说的，对我来说，Angular 中 MVC 模式的真正用处来自于它的可扩展性。事实上，利用 TypeScript 的面向对象方面（以及随之而来的内容）允许我们为不同的 Angular 应用程序专门化控制器和模型。例如，如果你像我一样有一个 Angular 网站和一个 Angular 移动应用程序，那么你可以在两边使用业务逻辑。当我们可以只有一个时，如果随着时间的推移，我们需要编写和维护两个登录、两个注册和两个所有内容，那将是一件遗憾的事情！

例如，在`toolwatch.io`，Web 应用程序使用标准的 Angular，我们使用 Ionic 和 Angular 构建了移动应用程序。显然，我们在移动应用程序（Android 和 iOS）和网站之间共享了大量前端逻辑。最终，它们倾向于实现相同的目的和功能。唯一的区别是使用的媒介来利用这些功能。

在下图中，我粗略地表示了一种更完整地利用 MVC 模式的方式，重点放在可重用性和可扩展性上：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/76a03142-0e91-49ae-bae9-33027d6fd7ce.png)Angular 的 MVC

再次强调，后端保持不变。我们在那里仍然有相同的 MVC 模式。作为提醒，后端的 MVC 模式完全取决于你，你可以利用前端的 MVC 模式与功能性的 Go 后端进行结合，例如。与此处公开的 MVC 的先前版本不同的是*可重用前端*部分的引入。在这部分中，我们仍然有一个负责消费我们的 JSON API 的 API 服务。然后，我们有一个实现了`IModel`接口的模型。

```ts

 export interface IModel{

 protected get(POTO):POTO;
 protected put(POTO):POTO;
 protected post(POTO):POTO;
 protected delete(POTO):boolean;
 protected patch(POTO):POTO;

 }
```

这个接口定义了必须在后续模型中实现的`put`、`post`、`delete`和`patch`方法。这些方法所接受的参数和返回的`POTO`类型是你程序中任何领域模型的母类。领域模型代表了你的业务逻辑中的可同步实体，比如我们之前使用的`User`。领域模型和模型-视图-控制器中的模型部分不应混淆。它们根本不是同一回事。在这种架构中，`User`会扩展`POTO`。

这次的模型（模型-视图-控制器）除了实现`IModel`接口之外，还包含了一个`POTO`。它还包含了你需要更新视图的变量和方法。模型本身的实现相当简单，就像我在本节前面展示的那样。然而，我们可以通过利用 TypeScript 的泛型特性来提升一些东西，设想以下情况：

```ts

 export class AbstractModel<T extends POTO> implements IModel{
 protected T domainModel;

 public AbstractModel(protected api:APIService){}

 protected get(POTO):T{
 //this.api.get ...
 };
 protected put(T):T{
 //this.api.put...
 };
 protected post(T):T{
 //this.api.post...
 };
 protected delete(T):boolean{
 //this.api.delete...
 };
 protected patch(T):T{
 //this.api.patch...
 };
 }

 export class UserModel extends AbstractModel<User>{

 public AbstractModel(api:APIService){
 super(api);
 }

 public signin(email:string, password:string){

 this._loading = true;

 this.get(new User(email, password)).then(

 user => {
 this.user = user;
 this._loading = false;
 }
 );
 }

 public signup(email:string, password:string){

 this._loading = true;
 this.post(new User(email, password)).then(
 user => {
 this.user = user;
 this._loading = false;
 } 
 );
 }
 //Only the code specialized for the UI ! 
 }
```

在这里，我们有一个通用的`AbstractModel`，它受到`POTO`的约束。这意味着`AbstractModel`泛型类的实际实例（在诸如 C++的语言中称为模板）受到了对专门化`POTO`的类的约束。换句话说，只有像`User`这样的领域模型才能被使用。到目前为止，关注点的分离以及其可重用性都非常出色。可重用部分的最后一部分是控制器。在我们的注册/登录示例中，它看起来会非常像这样：

```ts
export class UserController{

 public UserComponent(protected model:UserModel){
 }

 public signin(email:string, password:string){
 this.model.signin(email, password);
 }

 public signup(email:string, password:string){
 this.model.signup(email, password);
 }

 }
```

那么，为什么我们在这里需要一个额外的构建模块，为什么我们不能像我们在 Angular 模型-视图-控制器的简化版本中那样使用一个简单的 Angular 组件呢？嗯，问题在于，取决于你在 Angular 核心之上使用的是什么（Ionic、Meteor 等），组件并不一定是主要的构建模块。例如，在 Ionic2 世界中，你使用`Pages`，这是他们对经典组件的自定义版本。

因此，例如，移动部分会是这样的：

```ts
export class LoginPage extends UserController{

 public LoginPage(api:APIService){
 super(new UserModel(api));
 }

 //Only what's different on mobile !

 }
```

如果需要，您还可以扩展`UserModel`并添加一些专业化，就像前面的图表所示的那样。在浏览器端：

```ts
@Component({
 templateUrl: 'login.html'
 })
 export class LoginComponent extends UserController{

 public UserComponent(api:APIService){

 super(new UserModel(api));
 }

 //Only what's different on browser !

 }
```

您也可以再次扩展`UserModel`并添加一些专业化。唯一剩下的要涵盖的部分是视图。令我绝望的是，没有办法使用 extends 或样式文件。因此，除非移动应用程序和浏览器应用程序之间的 HTML 文件完全相同，否则我们注定会在客户端之间存在 HTML 文件的重复。根据经验，这种情况并不经常发生。

整个可重用的前端可以作为 Git 子模块、独立库或`NgModule`进行发布。我个人使用 git 子模块方法，因为它允许我在执行对共享前端进行修改时，在我正在工作的客户端上享受自动刷新，同时拥有两个单独的存储库。

请注意，这种模型-视图-控制器也适用于多个前端命中相同的后端，而不是多种类型的前端。例如，在电子商务设置中，您可能希望拥有不同品牌的网站来销售在同一个后端中管理的不同产品，就像 Magento 的视图所能实现的那样。

# Redux

Redux 是一种模式，可以让您以安全的方式管理事件和应用程序状态。它可以确保您的应用程序范围的状态，无论是由导航事件还是其他事件引起的，都在一个单一的不可访问的地方进行管理。

通常，应用程序的状态存储在 TypeScript 接口中。根据我们在上一节中使用的示例，我们将使用自定义的`APIService`来为用户实现登录/注销功能，该服务消耗 JSON。在我们的情况下，应用程序只有一个状态：`logged`。因此，接口看起来像这样：

```ts
export interface IAppState { 
    logged: boolean; 
} 
```

这个接口只包含一个单一的 logged 布尔值。对于这样一个常见的变量来说，拥有一个接口可能看起来有点多余，但是当您的应用程序开始增长时，您会发现它很方便。我们的应用程序的状态只能通过`Action`来操作。`Action`是 redux 框架中的一种事件类型，由`Reducer`触发和拦截。`Reducer`拦截这些动作并操作我们应用程序的状态。`Reducer`是唯一可以发生状态变化的地方。

现在我们已经快速概述了 redux 模式，现在是时候深入其实现了。首先，我们需要创建一个新的 Angular 项目并安装所需的包：

+   `**ng new ng-redux**`

+   `**cd ng-redux**`

+   `**npm install  – save redux @angular-redux/store**`

接下来，我们将创建我们的操作。作为提醒，操作是由应用程序触发的，并被`reducer`拦截，以便操作应用程序状态。在我们的应用程序中，我们只有两个操作，登录和注销：

```ts
import { Injectable } from '@angular/core'; 
import { Action } from 'redux'; 

@Injectable() 
export class LoginAction { 
  static LOGIN = 'LOGIN'; 
  static LOGOUT = 'LOGOUT'; 

  loggin(): Action { 
    return { type: LoginAction.LOGIN }; 
  } 

  logout(): Action { 
    return { type: LoginAction.LOGOUT }; 
  } 
} 
```

正如我们在前面的代码中所看到的，`LoginAction`类是一个 Angular 服务，因为它是可注入的。因此，我们架构的任何一个部分都可以通过 Angular 的自动依赖注入机制接收操作列表，这些机制在前一章中已经介绍过。还要注意的一点是，我们的两个操作都返回`Actions`。`action`类由一个`type`字段组成，我们使用静态字符串变量来填充它们。

列表上的下一个项目是`reducer`，它拦截触发的操作，并相应地操作我们应用程序的状态。`reducer`可以这样实现：

```ts
import { Action } from 'redux'; 
import { LoginAction } from './app.actions'; 

export interface IAppState { 
    logged: boolean; 
} 

export const INITIAL_STATE: IAppState = { 
  logged: false, 
}; 

export function rootReducer(lastState: IAppState, action: Action): IAppState { 
  switch(action.type) { 
    case LoginAction.LOGIN: return { logged: !lastState.logged }; 
    case LoginAction.LOGOUT: return { logged: !lastState.logged }; 
  } 

  // We don't care about any other actions right now. return lastState; 
}
```

目前，我们的`reducer`只管理两个操作：登录和注销。在接收到操作时，我们使用 switch 语句检查操作类型，然后简单地反转已登录状态的值。由于我们的接口，这是我们唯一可以修改应用程序状态的地方。乍一看，这可能被视为一个瓶颈和关注点分离不足。现在，瓶颈部分，也就是所有事情都发生在那里，是有意设计的。Redux 背后的主要思想是，复杂的有状态 JavaScript 应用程序很难管理，因为应用程序的状态可以以多种方式改变。例如，异步调用和导航事件都可以以微妙且难以调试的方式改变应用程序的整体状态。在这里，使用 Redux 功能，一切都在同一个地方管理。至于关注点分离的论点，这是非常有效的，没有什么能阻止我们在良好命名的、松散耦合的函数中操作状态（例如，在我们的情况下`return { logged: !lastState.logged };`）。

现在我们的商店、Redux 和操作已经实现，我们可以开始在我们的组件内操作它们：

```ts
import { Component, OnDestroy } from '@angular/core'; 

import { NgRedux } from '@angular-redux/store'; 
import { LoginAction } from './app.actions'; 
import { IAppState } from "./store"; 
import { APIService } from './api.service'; 

@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent implements OnDestroy {  
  title = 'app'; 
  subscription; 
  logged: boolean; 

  constructor(                           
    private ngRedux: NgRedux<IAppState>, 
    private api:APIService) { 

      this.subscription = ngRedux.select<boolean>('logged') 
      .subscribe(logged => this.logged = logged);    
    }  

  login(email:string, password:string) { 
    this.api.login(email, password); 
  } 

  logout() { 
    this.api.logout(); 
  } 

  ngOnDestroy() {                     
    this.subscription.unsubscribe();  
  }     
} 
```

这里发生了很多事情。让我们一点一点地分解。首先是构造函数：

```ts
constructor(                           
    private ngRedux: NgRedux<IAppState>, 
    private api:APIService) { 

      this.subscription = ngRedux.select<boolean>('logged') 
      .subscribe(logged => this.logged = logged);    
    } 
```

在这个构造函数中，我们期望接收一个 `NgRedux<IAppState>` 的注入，它可以操作我们的状态，以及稍微修改过的 `APIService`，以适应我们的新模式。在构造函数内部，我们有 `ngRedux.select<boolean>('logged')` 指令，它允许我们访问来自 `IAppState` 接口的 logged 变量的可观察对象。正如你所看到的，按设计，在这里无法更改 `logged` 的值，因为你只能获取它的可观察对象。作为一个可观察对象，我们可以订阅它，并在其值发生变化时定义一个组件。在我们的情况下，我们将 logged 类成员的值影响到 logged 状态的新值。

接下来是登录和注销方法，它们作为对 `ApiService` 调用的代理：

```ts
 login(email:string, password:string) { 
    this.api.login(email, password); 
  } 

  logout() { 
    this.api.logout(); 
  } 
```

最后，我们可以看到 `ngOnDestroy` 函数的实现，这是通过实现 `OnDestroy` 接口而成为强制性的。虽然不是强制性的，`ngOnDestroy` 函数会取消订阅 logged 观察者，这样如果 logged 状态发生变化并且组件不再存在，就会节省我们几毫秒：

```ts
 ngOnDestroy() {                     
    this.subscription.unsubscribe();  
  } 
```

让我们来看一下与我们的组件相关联的 HTML。它非常简单，只显示了 logged 状态的值和两个按钮，你猜对了，它们允许我们登录和退出我们的应用程序：

```ts
<div style="text-align:center"> 
  <p>{{logged}}</p> 
  <button (click)="login('foo', 'bar')">Login</button> 
  <button (click)="logout()">Logout</button> 
</div> 
```

看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/041bba5d-4211-471a-add8-a961cb2fb961.png)

列表中的下一个项目是修改 `APIService`，使其使用我们的新模式，而不是 MVC：

```ts
import { Injectable } from '@angular/core'; 
import { Http }  from '@angular/http'; 
import { User } from './user'; 
import 'rxjs/Rx'; 
import { NgRedux } from '@angular-redux/store'; 
import { LoginAction } from './app.actions'; 
import {IAppState } from './store'; 

@Injectable() 
export class APIService { 

  private userURL:string = "assets/users.json"; 

  constructor( 
      private http: Http,  
      private ngRedux: NgRedux<IAppState>,  
      private actions: LoginAction) { } 

  /** 
   * Return a Promise to a USer matching id 
   * @param  {string}            email 
   * @param  {string}            password 
   * @return {Promise<User>}    
   */ 
  public login(email:string, password:string){ 
        console.log('login', email, password); 

        this.http.get(this.userURL) 
        /** 
         * Transforms the result of the http get, which is observable 
         * into one observable by item. */ 
        .flatMap(res => res.json().users) 
        /** 
         * Filters users by their email & password 
         */ 
        .filter((user:any)=>{ 
            console.log("filter", user); 
            return (user.email === email && user.password == password) 
        }) 
        .toPromise() 
        /** 
         * Map the json user item to the User model 
        */ 
        .then((user:any) => { 
            console.log("map", user);  
            this.ngRedux.dispatch(this.actions.loggin()); 
        }); 
  }  

   /** 
   * Logout a User 
   */ 
  public logout(){ 
        this.ngRedux.dispatch(this.actions.logout()); 
  } 

} 
```

在这个版本中，我们使用相同的技术，只是不再返回 promises。实际上，在这个版本中，我们只是向我们的 reducer 分派动作，如下所示：

```ts
this.ngRedux.dispatch(this.actions.loggin()); 
```

还有：

```ts
this.ngRedux.dispatch(this.actions.logout()); 
```

再次强调，状态的修改是间接的；我们只是分派一个动作，这个动作将被 reducer 捕获，而不是直接操作状态。换句话说，这是安全的，并且集中在一个单一的点上。

最后，我们需要调整主应用模块以反映所有我们的更改：

```ts
import { BrowserModule } from '@angular/platform-browser'; 
import { NgModule } from '@angular/core'; 
import { HttpModule } from '@angular/http'; 

import { NgReduxModule, NgRedux } from '@angular-redux/store'; 
import { AppComponent } from './app.component'; 

import { rootReducer, IAppState, INITIAL_STATE } from './store'; 
import { LoginAction } from './app.actions'; 
import { APIService } from './api.service'; 

@NgModule({ 
  declarations: [ 
    AppComponent 
  ], 
  imports: [ 
    NgReduxModule, 
    HttpModule, 
  ], 
  providers: [APIService, LoginAction], 
  bootstrap: [AppComponent] 
}) 
export class AppModule {  

  constructor(ngRedux: NgRedux<IAppState>) { 
    // Tell @angular-redux/store about our rootReducer and our initial state. // It will use this to create a redux store for us and wire up all the 
    // events. ngRedux.configureStore( 
      rootReducer, 
      INITIAL_STATE); 
  } 
} 
```

我们首先导入了 `NgRedux` 模块和 `HttpModule`，它们将在应用程序中使用。然后，`AppModule` 的构造函数将接收一个注入的 `NgRedux` 实例，并配置我们的 Redux 存储。存储还接收了我们之前初始化的默认状态。

# 总结

在这一章中，我们看到了两种模式：Redux 和 MVC。Redux 和 MVC 可以用来实现相同的目的（在异步事件或用户操作的反应中管理应用程序的状态）。这两种模式都有优点和缺点。在我的观点中，Angular 应用程序中 MVC 的优点是一切都被很好地定义和分离。事实上，我们有一个领域对象（`User`），一个模型（`UserModel`），以及一个与组件相关联的视图。我们看到了相同的模型和领域对象在许多组件和视图中被重复使用。问题在于，在我们的应用程序中创建新功能可能会变得很昂贵，因为你将不得不创建或者至少修改大量的架构。

此外，无论是出于错误还是设计，如果您在多个组件和服务之间共享模型，要识别和消除错误的来源可能会非常痛苦。Redux 模式更加新颖，而且更适应 JavaScript 生态系统，因为它是为其创建的。在我们的应用程序中相对容易地添加状态功能，并以安全的方式操纵它们。根据经验，我可以向您保证，当使用 Redux 模式时，整个团队数天都被困惑的错误要少得多。然而，在应用程序内部的关注点分离不太明确，你可能最终会在最复杂的应用程序中得到一千行的 Redux。当然，我们可以创建几个额外的 reducer，将我们的存储与大功能分开，并创建辅助函数来操纵我们的状态。由于这些不是模式所强加的，我经常发现自己在审查昂贵的 reducer 时需要进行大量的重构。

在下一章中，我们将研究 Angular 应用程序的稳定性模式，这将确保我们的应用程序在面临一切困难时仍然可用。


# 第五章：稳定性模式

稳定性是软件工程的基石之一。无论如何，你都必须对你的环境和用户做最坏的打算，并做好准备。当你的后端处于燃烧状态时，你的 Angular 应用程序应该能够在降级模式下运行，并在其恢复在线时平稳恢复。

在本章中，我们将学习稳定性模式和反模式，例如以下内容：

+   超时

+   断路器

+   工厂

+   纪念品

+   原型和可重用池

# 超时

在之前的章节中，我们尝试了使用 API 服务，目的是消费由我们假设的后端创建的任何类型的内容的 API。如果我不得不分享我在网上冒险中学到的一句话，那就是*不要相信任何人...尤其不要相信自己*。我的意思是，你永远不能相信 API 会按预期工作，即使是你自己的 API。你应该始终期望一切可能出错的事情都会出错。在尝试与后端通信时可能发生的一件较不严重的事情是它不会响应。虽然这种单向通信对你的 Angular 应用程序是无害的，但对你的用户来说是最令人沮丧的。在这个配方中，我们将学习如何在我们的外部调用中实现超时，以及如何对不响应的 API 做出反应。

幸运的是，有一种非常简单的方法可以防止我们的用户对不响应的 API 感到沮丧：超时。超时是一种简单的防御机制，允许你的应用程序等待固定的时间，而不是一毫秒更多。让我们创建一个新的项目来测试一下：

```ts
    ng new timeout
    cd timeout
    ng g service API
```

这将创建一个新的项目和一个名为`API`的服务。乍一看，没有什么可看的：

```ts
import { Injectable } from '@angular/core'; 

@Injectable() 
export class ApiService { 

  constructor() { } 

} 
```

我们需要在`app.module.ts`中添加`HttpClient`组件如下：

```ts
import { BrowserModule } from '@angular/platform-browser'; 
import { NgModule } from '@angular/core'; 
import { HttpClientModule } from '@angular/common/http'; 

import { AppComponent } from './app.component'; 
import { ApiService } from './api.service'; 

@NgModule({ 
  declarations: [ 
    AppComponent 
  ], 
  imports: [ 
    BrowserModule, 
    HttpClientModule 
  ], 
  providers: [ApiService], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { } 
```

然后，我们希望将`HttpClient`组件注入到我们的 API 服务客户端中，以便可以访问其方法：

```ts
import { Injectable } from '@angular/core'; 
import { HttpClient } from '@angular/common/http'; 

@Injectable() 
export class ApiService { 

  constructor(private http:HttpClient) { } 

} 
```

我们将在我们的`APIService`中添加一个新的方法，简单地对包含本书代码的 GitHub 存储库进行`http.get`（[`github.com/MathieuNls/Angular-Design-Patterns-and-Best-Practices`](https://github.com/MathieuNls/Angular-Design-Patterns-and-Best-Practices)）：

```ts
import { Injectable } from '@angular/core'; 
import { HttpClient } from '@angular/common/http'; 

@Injectable() 
export class ApiService { 

  constructor(private http: HttpClient) { } 

  public getURL(url: string): void { 
    this.http.get(url) 
    .subscribe(data => { 
      console.log(data); 
    }); 
  }  

} 
```

接下来是对`ApiService`的注入，并在`AppComponent`中调用新的`getURL`方法：

```ts
import { Component } from '@angular/core'; 
import { ApiService } from './api.service'; 

@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  title = 'app'; 

  constructor(private api: ApiService){ 
    api.getURL("https://github.com/MathieuNls/Angular-Design-Patterns-and-Best-Practices") 
  } 
}
```

现在，如果我们执行这个操作，我们将得到一个优雅的 HTTP 响应，并且网页的 HTML 将被打印到控制台中。然而，问题在于，如果[github.com](http://www.github.com)宕机并且没有响应，我们没有采取任何对策：

```ts
import { Injectable } from '@angular/core'; 
import { HttpClient } from '@angular/common/http'; 

@Injectable() 
export class ApiService { 

  constructor(private http: HttpClient) { } 

  public getURL(url: string): void { 

    let timeout; 

    let sub = this.http.get(url) 
      .subscribe((res) => { 
        console.log(res); 
        clearTimeout(timeout) 
      }); 

    timeout = setTimeout( 
      () => { sub.unsubscribe() }, 1000 
    ); 
  } 

} 
```

在这个版本的`getURL`函数中，我们必须首先声明一个超时变量，该变量将包含一个 NodeJS 超时。然后，我们将订阅响应，而不是执行常规的`HTTP.get`。最后，在订阅结果后，我们使用`setTimeout`函数为超时变量赋值。我们使用这个函数在 1,000 毫秒后取消订阅响应。因此，我们只等待 1 秒钟的`http`回复。如果回复在这段时间内没有到达，我们将自动取消订阅并允许我们的应用程序继续。当然，我们的用户必须以某种方式被警告操作失败。

# 断路器

我们在上一节中实现的超时模式有效地保护了用户的耐心，最终也保护了我们的 Angular 应用程序。然而，如果 API 没有响应是因为服务器端出了问题，比如你的服务器 80%宕机，剩下的 20%在尝试管理负载，你的客户很可能会反复重试超时的操作。因此，这会给我们濒临崩溃的后端基础设施带来更大的压力。

电路是一种自动装置，用于作为安全措施停止电路中的电流流动。断路器用于检测故障并封装防止故障不断发生的逻辑（在维护期间、临时外部系统故障或意外系统困难期间）。

具体来说，在 Angular 应用程序的框架内，断路器将在出现太多故障时阻止客户端执行 API 请求。在一定时间后，电路将允许一些查询通过并使用 API。如果这些查询没有任何问题返回，那么电路将关闭自身并允许所有请求通过：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/c2200dc4-5325-466a-837a-2c4a731d5d4e.png)

在上图中，我们可以看到断路器是如何运作的。所有请求都经过断路器，如果供应商及时回应请求，断路器保持关闭状态。当问题开始出现时，断路器会注意到，如果足够多的请求超时，那么断路器就会打开，阻止请求通过。

最后，在给定的时间后，断路器尝试重新发送请求给供应商：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/ba406e26-efc0-4531-ab10-e3aafad6bade.png)

从实现的角度来看，我们需要`ApiStatus`和`Call`类，它们负责跟踪我们对不同 API 的调用。

```ts
//ApiStatus class 
class ApiStatus { 

  public lastFail: number 
  public calls: Call[] 

  constructor(public url: string) { } 

  //Compute the fail percentage 
  public failPercentage(timeWindow: number): number { 

    var i = this.calls.length - 1; 
    var success = 0 
    var fail = 0; 

    while (this.calls[i].time > Date.now() - timeWindow && i >= 0) { 
      if (this.calls[i].status) { 
        success++; 
      } else { 
        fail++; 
      } 
   i--; 
    } 

    return fail / (fail + success) 
  } 

} 
```

`APIStatus`包含了根 API 的统计信息。我们要考虑到我们的应用程序可能会使用多个 API。每个 API 都必须与自己的断路器相连。首先，我们有`lastFail`变量，其中包含了上次调用此 API 失败的日期。然后，我们有一个`calls`数组，其中包含了对给定 API 的所有调用。除了定义 URL 属性的构造函数之外，我们还有`failPercentage`函数。这个函数负责计算在`timeWindows`时间内失败的调用百分比。为了做到这一点，我们以相反的时间顺序迭代所有的调用，直到达到`Date.now()` - `timeWindow`或`calls`数组的末尾。在`while`循环内，我们根据当前调用的状态递增两个名为`success`和`fail`的数字变量。最后，我们返回失败调用的百分比。这个百分比将用于确定断路器的状态。

`Call`类非常简单：

```ts
//An Api Call 
class Call { 
  constructor(public time: number, public status: boolean) { } 
} 
```

它只包含两个属性：时间和状态。现在，我们准备为我们的*Angular*应用程序实现一个实现断路器的 API 客户端。首先，我们必须创建这个类：

```ts
import { Injectable } from '@angular/core'; 
import { HttpClient } from '@angular/common/http'; 

@Injectable() 
export class ApiwithBreakerService { 

  constructor(private http: HttpClient) { } 
```

然后，我们必须为`ApiwithBreakerService`添加属性：

```ts
 private apis: Map<string, ApiStatus>; 
  private failPercentage: number = 0.2; 
  private timeWindow : number = 60*60*24; 
  private timeToRetry : number = 60;
```

这些属性将允许我们实现断路器模式。首先，我们有一个`string`和`ApiStatus`的映射，用于存储许多 API 的 API 状态。然后，我们有`failPercentage`，它定义了在打开电路之前有多少调用可以失败，作为百分比。`timeWindow`变量定义了用于计算`failPercentage`的时间量。在这里，我们在 24 小时窗口内最多可以有 20%的调用失败，然后我们打开这个电路并阻止其他调用。最后，我们有`timeToRetry`，它规定了在尝试重新关闭电路之前我们需要等待多长时间。

以下是来自超时部分的修改后的`getURL`函数：

```ts
 //Http get an url 
  public getURL(url: string): void { 

    var rootUrl = this.extractRootDomain(url); 

    if(this.isClosed(rootUrl) || this.readyToRetry(rootUrl)){ 
      let timeout; 

      let sub = this.http.get(url) 
        .subscribe((res) => { 
          console.log(res); 
          clearTimeout(timeout); 
          this.addCall(rootUrl, true); 
        }); 

      timeout = setTimeout( 
        () => {  
          sub.unsubscribe(); 
          this.addCall(rootUrl, false); 
        }, 1000 
      ); 
    } 
  } 
```

我们保留了前一部分中的超时的核心功能，但将其嵌入到了一个`if`语句中：

```ts
if(this.isClosed(rootUrl) || this.readyToRetry(rootUrl)) 
```

`if`语句检查电路是否关闭，或者我们是否准备在打开的电路上重试。

我们还添加了对`addCall`函数的调用：

```ts
 //Add a call 
  private addCall(url: string, status: boolean) { 

    let res = this.apis.get(url); 

    if (res == null) { 
      res = new ApiStatus(url); 
      this.apis.set(url, res); 
    } 

    res.calls.push(new Call(Date.now(), status)); 

    if(!status){ 
      res.lastFail = Date.now(); 
    } 
  } 
```

`addCall`函数将一个新的调用添加到存储在`apis`映射内的`ApiStatus`中。如果调用不成功，它还会更新`ApiStatus`实例的`lastFail`属性。

剩下的是`readyToRetry`和`isClosed`函数：

```ts
 //Are we ready to retry 
  private readyToRetry(url:string): boolean { 

    return this.apis.get(url).lastFail < (Date.now() - this.timeToRetry) 
  } 

  //Is it closed ? private isClosed(url :string) : boolean { 

    return this.apis.get(url) == null ||  
      !(this.apis.get(url).failPercentage(this.timeWindow) > this.failPercentage); 
  } 
```

在`readyToRetry`函数中，我们只需检查最新的失败是否比现在减去`timeToRetry`的时间早。在`isClosed`函数中，我们检查在时间窗口内失败调用的百分比是否大于允许的最大值。以下是完整的实现：

```ts
import { Injectable } from '@angular/core'; 
import { HttpClient } from '@angular/common/http'; 

//ApiStatus class 
class ApiStatus { 

  public lastFail: number 
  public calls: Call[] 

  constructor(public url: string) { } 

  //Compute the fail percentage 
  public failPercentage(timeWindow: number): number { 

    var i = this.calls.length - 1; 
    var success = 0 
    var fail = 0; 

    while (this.calls[i].time > Date.now() - timeWindow && i >= 0) { 
      if (this.calls[i].status) { 
        success++; 
      } else { 
        fail++; 
      } 
      i--; 
    } 
```

```ts
 return fail / (fail + success) 
  } 

} 

//An Api Call 
class Call { 
  constructor(public time: number, public status: boolean) { } 
} 

@Injectable() 
export class ApiwithBreakerService { 

  constructor(private http: HttpClient) { } 

  private apis: Map<string, ApiStatus>; 
  private failPercentage: number = 0.2; 
  private timeWindow : number = 60*60*24; 
  private timeToRetry : number = 60; 

  //Http get an url 
  public getURL(url: string): void { 

    var rootUrl = this.extractRootDomain(url); 

    if(this.isClosed(rootUrl) || this.readyToRetry(rootUrl)){ 
      let timeout; 

      let sub = this.http.get(url) 
        .subscribe((res) => { 
          console.log(res); 
          clearTimeout(timeout); 
          this.addCall(rootUrl, true); 
        }); 

      timeout = setTimeout( 
        () => {  
          sub.unsubscribe(); 
          this.addCall(rootUrl, false); 
        }, 1000 
      ); 
    } 
  } 

  //Add a call 
  private addCall(url: string, status: boolean) { 

    let res = this.apis.get(url); 

    if (res == null) { 
      res = new ApiStatus(url); 
      this.apis.set(url, res); 
    } 

    res.calls.push(new Call(Date.now(), status)); 

    if(!status){ 
      res.lastFail = Date.now(); 
    } 
  } 

  //Are we ready to retry 
  private readyToRetry(url:string): boolean { 

    return this.apis.get(url).lastFail < (Date.now() - this.timeToRetry) 
  } 

  //Is it closed ? private isClosed(url :string) : boolean { 

    return this.apis.get(url) == null ||  
      !(this.apis.get(url).failPercentage(this.timeWindow) > this.failPercentage); 
  } 

  private extractHostname(url: string) : string { 
    var hostname; 
    //find & remove protocol (http, ftp, etc.) and get hostname 

    if (url.indexOf("://") > -1) { 
      hostname = url.split('/')[2]; 
    } 
    else { 
      hostname = url.split('/')[0]; 
    } 

    //find & remove port number 
    hostname = hostname.split(':')[0]; 
    //find & remove "?" hostname = hostname.split('?')[0]; 

    return hostname; 
  } 

  private extractRootDomain(url: string) : string{ 
    var domain = this.extractHostname(url), 
      splitArr = domain.split('.'), 
      arrLen = splitArr.length; 

    //extracting the root domain here 
    //if there is a subdomain  
    if (arrLen > 2) { 
      domain = splitArr[arrLen - 2] + '.' + splitArr[arrLen - 1]; 
      //check to see if it's using a Country Code Top Level Domain (ccTLD) (i.e. ".me.uk") 
      if (splitArr[arrLen - 1].length == 2 && splitArr[arrLen - 1].length == 2) { 
        //this is using a ccTLD 
        domain = splitArr[arrLen - 3] + '.' + domain; 
      } 
    } 
    return domain; 
  } 
} 
```

请注意，我们有两个辅助函数，它们并不直接参与电路模式的实现，只是提取调用的根 URL，以便通过根 API 计算共享状态。由于这些辅助函数，我们可以使[`someapi.com/users`](http://someapi.com/users)和[`someapi.com/sales`](http://someapi.com/sales)共享相同的状态，而[`anotherapi.com/someCall`](http://anotherapi.com/someCall)则有其自己分离的`ApiStatus`。

超时和断路器模式并行工作，以减少自我否认。自我否认是自己毁灭后端服务器的艺术。当您的应用程序表现不当并且每秒向后端架构发出数千次调用时，这种情况往往会发生。

# 工厂

假设我们有一个`User`类，有两个私有变量：`lastName:string`和`firstName:string`。此外，这个简单的类提供了`hello`方法，打印`"Hi I am", this.firstName, this.lastName`：

```ts
class User{
 constructor(private lastName:string, private firstName:string){
 }
 hello(){
 console.log("Hi I am", this.firstName, this.lastName);
 }
 }
```

现在，考虑我们通过 JSON API 接收用户。它很可能看起来像这样：

```ts
[{"lastName":"Nayrolles","firstName":"Mathieu"}...]. 
```

通过以下代码片段，我们可以创建一个`User`：

```ts
let userFromJSONAPI: User = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')[0]; 
```

到目前为止，TypeScript 编译器还没有抱怨，并且它执行得很顺利。这是因为`parse`方法返回`any`（例如，Java 对象的 TypeScript 等价物）。当然，我们可以将`any`转换为`User`。然而，`userFromJSONAPI.hello();`将产生以下结果：

```ts
json.ts:19
 userFromJSONAPI.hello();
 ^
 TypeError: userFromUJSONAPI.hello is not a function
 at Object.<anonymous> (json.ts:19:18)
 at Module._compile (module.js:541:32)
 at Object.loader (/usr/lib/node_modules/ts-node/src/ts-node.ts:225:14)
 at Module.load (module.js:458:32)
 at tryModuleLoad (module.js:417:12)
 at Function.Module._load (module.js:409:3)
 at Function.Module.runMain (module.js:575:10)
 at Object.<anonymous> (/usr/lib/node_modules/ts-node/src/bin/ts-node.ts:110:12)
 at Module._compile (module.js:541:32)
 at Object.Module._extensions..js (module.js:550:10)
```

为什么？嗯，赋值的左侧被定义为`User`，但当我们将其转译为 JavaScript 时，它将被抹去。

在 TypeScript 中进行类型安全的方式如下：

```ts
let validUser = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')
 .map((json: any):User => {
 return new User(json.lastName, json.firstName);
 })[0];
```

有趣的是，`typeof`函数也无法帮助你。在这两种情况下，它都会显示`Object`而不是`User`，因为`User`的概念在 JavaScript 中根本不存在。

虽然直接的类型安全方法有效，但它并不是非常可扩展或可重用的。事实上，每当你接收一个 JSON `user`时，`map`回调方法都必须在各处重复。最方便的方法是通过`Factory`模式来做到这一点。`Factory`用于创建对象，而不将实例化逻辑暴露给客户端。

如果我们要创建一个用户的`factory`，它会像这样：

```ts

 export class POTOFactory{

 /**
 * Builds an User from json response
 * @param  {any}  jsonUser
 * @return {User} 
 */
 static buildUser(jsonUser: any): User {

 return new User(
 jsonUser.firstName,
 jsonUser.lastName
 );
 }

 }
```

在这里，我们有一个名为`buildUser`的静态方法，它接收一个 JSON 对象，并从 JSON 对象中获取所有必需的值，以调用一个假想的`User`构造函数。该方法是静态的，就像工厂的所有方法一样。事实上，在工厂中我们不需要保存任何状态或实例绑定的变量；我们只需要封装用户的创建过程。请注意，你的工厂可能会在你的 POTOs 的其余部分中共享。

# 备忘录

备忘录模式在 Angular 的上下文中是一个非常有用的模式。在由 Angular 驱动的应用程序中，我们经常过度使用两种方式绑定领域模型，比如`User`或`Movie`。

让我们考虑两个组件，一个名为`Dashboard`，另一个名为`EditMovie`。在`Dashboard`组件上，你有一个电影列表，显示在我们的类似 IMDb 的应用程序的上下文中。这样的仪表板视图可能如下所示：

```ts

 <div *ngFor="let movie of model.movies">
 <p>{{movie.title}}</p>
 <p>{{movie.year}}</p>
 </div>
```

这个简单的视图拥有一个`ngFor`指令，它遍历模型中包含的电影列表。然后，对于每部电影，它分别显示包含标题和发行年份的两个`p`元素。

现在，`EditMovie`组件访问`model.movies`数组中的一部电影，并允许用户对其进行编辑：

```ts
<form>
 <input id="title" name="title" type="text" [(ngModel)]="movie.title" />
 <input id="year" name="year" type="text" [(ngModel)]="movie.year" />
 </form>

 <a href="/back">Cancel</a>
```

感谢在这里使用的双向绑定，对电影标题和年份的修改将直接影响仪表板。正如你所看到的，我们这里有一个“取消”按钮。虽然用户可能期望修改是“实时”同步的，但他也期望取消按钮/链接可以取消对电影所做的修改。

这就是备忘录模式发挥作用的地方。这种模式允许在对象上执行撤消操作。它可以以许多种方式实现，但最简单的方式是使用克隆。使用克隆，我们可以在给定时刻存储对象的一个版本，并且在需要时返回到它。让我们按照以下方式增强我们的`Movie`对象从“原型”模式：

```ts
export class Movie implements Prototype {

 private title:string;
 private year:number;
 //...

 public constructor()
 public constructor(title:string = undefined, year:number = undefined)
 {
 if(title == undefined || year == undefined){
 //do the expensive creation
 }else{
 this.title = title;
 this.year = year;
 }
 }

 clone() : Movie {
 return new Movie(this.title, this.year);
 }

 restore(movie:Movie){
 this.title = movie.title;
 this.year = movie.year;
 }
 }
```

在这个新版本中，我们添加了`restore(movie:Movie)`方法，它以`Movie`作为参数，并将本地属性影响到接收到的电影的值。

然后，在实践中，我们的`EditMovie`组件的构造函数可能如下所示：

```ts

 private memento:Movie;

 constructor(private movie:Movie){

 this.memento = movie.clone();
 }

 public cancel(){
 this.movie.restore(this.memento);
 }
```

有趣的是，你不限于随时间只有一个备忘录，你可以有任意多个。

# 总结

在本章中，我们看到的模式旨在提高我们的 Angular 应用程序的稳定性。值得注意的是，事实上，大部分目的是为了保护我们的后端基础设施免受过热。事实上，当超时和断路器结合在一起时，它们可以让我们的后端得到休息，同时它们重新上线。此外，备忘录和可重用池旨在保留我们可能已经从后端重新请求的客户端信息，如果我们不存储它们的话。

在下一章中，我们将介绍性能模式和改进应用程序运行速度的最佳实践。


# 第六章：性能模式

在上一章中，我们调查了稳定性模式。稳定性模式是为了使您的应用程序能够在出现错误时生存下来。期望应用程序在没有任何错误的情况下发货是荒谬的，而试图实现这一点将使您的团队筋疲力尽。相反，我们学会了如何与之共存，并确保我们的应用程序足够弹性，可以经受住错误。在本章中，我们将专注于性能模式和反模式。这些模式定义了架构和实践，对您的应用程序的性能产生积极或消极的影响。

具体来说，我们将学习以下内容：

+   AJAX 过度使用

+   无限结果集

+   代理

+   过滤器和管道

+   循环

+   变更检测

+   不可变性

+   原型和可重用池

# AJAX 过度使用

如果您的应用程序不仅仅是一个一次性的原型或一个华丽的单页应用程序，那么您可能正在处理远程 API。这些远程 API 又在与后端层（例如 PHP、Ruby 或 Golang）和数据库（例如 MySQL、MS SQL 或 Oracle）进行通信。

虽然本书侧重于*Angular*应用程序，但我们不能忽视它们通常不会单独存在的事实。事实上，任何有意义的应用程序都需要从某个地方拉取和推送数据。

考虑到这一点，让我们想象一下，您的应用程序是某种在线电子商务网站（如亚马逊）的前端。这个虚构的应用程序肯定会有一个个人资料页面，用户可以在其中查看他们的过去和正在进行的命令。

让我们进一步指定我们的应用程序，假设您的 API，端点如下所示：

```ts
GET /orders
```

这将返回已登录用户的订单。

以下是一个 JSON 返回调用的示例：

```ts
{
 "orders":[
 {
 "id":"123",
 "date": "10/10/10",
 "amount": 299,
 "currency": "USD"
 },
 {
 "id":"321",
 "date": "11/11/11",
 "amount": 1228,
 "currency": "USD"
 },
 {
 "id":"322",
 "date": "11/12/11",
 "amount": 513,
 "currency": "USD"
 },

 ...

 ]
}
```

为了清晰和简洁起见，我们将假设我们的用户被神奇地认证，并且他们访问特定 API 端点的授权也是神奇的。

对于每个命令，您可以访问一个`GET` /`command_details` API，在其中，您可以检索给定 ID 的命令的详细信息：

```ts
{
 "items":[
 {
 "id":123,
 "qty":1,
 "price": 2,
 "tax_rate": 0.19,
 "currency": "USD",
 "shipped_at": "10/10/10",
 "received_at": "11/10/10"
 },
 {
 "id":124,
 "qty":2,
 "price": 3,
 "tax_rate": 0.19,
 "currency": "USD",
 "shipped_at": "10/10/10",
 "received_at": "11/10/10"
 }
 ...
 ]
}
```

在 Angular 方面，可以是一个简单的扩展面板，使用 Google Material Design 组件套件的扩展面板实现，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/5f2d0dda-baa9-4314-8de2-0c40b3e25fa4.png)

我们还可以添加一个`GET` /`items_details`，返回项目的详细信息，但现在让我们暂停在这里。

现在，让我们假设每个 API 调用需要 100 毫秒才能完成，另外需要 10 毫秒来将 JSON 转换为 TypeScript 对象。有经验的开发人员肯定会首先获取给定用户的所有命令，并预先获取每个命令的细节，这样用户在展开给定面板时就不必等待。如果我们的 API 能够处理每秒 100 个请求，这是令人尊敬的，那么我们每秒只能为九个客户提供服务，假设他们每个人都有十个命令。每秒只能为九个客户提供服务听起来并不令人印象深刻...

事实上，同时点击*订单简历*页面的 10 个客户将耗费我们 1/10 的容量，并引发额外的 100 次调用（10 个客户×10 个命令）。因此，第十个客户在第一秒内将得不到服务。这可能听起来并不那么令人担忧，但是，我们只谈论了 10 个用户。

这种效果被称为 AJAX 过度性能反模式。作为前端开发人员，我可以访问满足我所有需求的 API，并且我使用它们来让我的客户满意。然而，预加载每个命令的每个细节，甚至可能是每个项目的每个细节，都是一个糟糕的主意。你会在后端架构上施加不必要的压力，只是因为你的客户可能想立即访问最后命令的细节。

出于后端基础设施的考虑，当用户真正想要查看命令的详细信息时，只请求命令的细节可能是值得的。

这与无限制的 API 密切相关。再次强调，后端架构不在本书的范围内，但是，如果我们要谈论 Angular 应用程序的性能，我们就必须提到它。如果你能控制你使用的 API，那么确保它们暴露出某种分页，并且你要正确地使用它。

# 代理模式

在我们对无限制的 API 和 AJAX 过度的调查中，我们在前一篇文章中确定了两者都应该避免，但是解决这个问题的方法是使 API 在 API 没有分页的情况下发生变化。这假设你能访问这些 API 或者能够找到有这种访问权限的人。虽然这是一个合理的假设，但并非在所有情况下都成立。

除了不发出请求（显然），我们还能做什么来保护那些设计不良且失控的 API？嗯，解决这个问题的一个优雅方式是使用代理模式。代理模式用于控制对对象的访问。您肯定知道 Web 代理可以根据用户的凭据控制对网页的访问。在这个示例中，我们不会讨论 Web 代理，而是面向对象的代理。在面向对象的代理中，我们不太关心对象的安全访问，而是关心功能访问。

例如，图像处理软件要列出并显示文件夹中的高分辨率照片对象，但用户并不总是会查看给定文件夹中的所有图像。因此，一些图像将会被无谓地加载。

然而，这与我们的 API 问题有什么关系呢？使用代理模式，我们可以控制我们实际想要执行 API 请求的时间，同时保持我们的命令集合整洁有序。首先，让我们看一下代理 UML：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/2f6547fa-c386-4fdf-b702-83c66c3bf60a.png)

首先，我们有一个定义`doOperation()`方法的`Subject`接口。这个接口由`Proxy`和`RealSubject`类实现。`Proxy`类包含对`realSubject`类的引用，该引用将在适当的时候填充。对于我们的目的，它可能是什么样子呢？

首先，我们有一个名为`OnlineCommand`的简单接口：

```ts
import { Item } from "./item";
export interface OnlineCommand {
fetchItems() : Item[]
}
```

在这个接口中，只定义了一个方法：`fetchItems()`。这个方法返回命令中包含的项目。

然后，我们的组件有一个代表我们客户命令的命令数组：

```ts
import { Component } from '@angular/core';
import { OnlineCommand } from './online-command';

@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})
export class AppComponent {
title = 'app';
private commands:OnlineCommand[]
}
```

在这个简短的组件中，我们只有我们客户的命令，以及使 Angular 组件成为组件的内容。

对于 HTML 部分，我们只需遍历命令集合，并在点击时调用`fetchItems`函数：

```ts
<ul>
 <li *ngFor="let item of commands; let i = index" (click)="item.fetchItems()">
 {{i}} {{item}}
 </li>
</ul>
```

然后，我们有一个实现`OnlineCommand`接口的`RealCommand`类：

```ts
import { OnlineCommand } from "./online-command";
import { Item } from "./item";

//RealCommand is a real command that has the right to do
//API calls
export class RealCommand implements OnlineCommand{

 public fetchItems() : Item[] {
 //This would come from an API call
 return [new Item(), new Item()];
 }
}
```

谜题的最后一部分，尽管是最重要的一部分，是在线命令的代理版本：

```ts
import { OnlineCommand } from "./online-command";
import { RealCommand } from "./real-command";
import { Item } from "./item";

//A Proxified Command
export class ProxyfiedCommand implements OnlineCommand{

 //Reference to the real deal
 private real:RealCommand;

 //Constructor
 constructor() {
 this.real = new RealCommand();
 }

 //The Proxified fetchItems.
 //It only exists as a placeholder and if we need it
 //we' ll the real command.
 public fetchItems() : Item[] {
 console.log("About the call the API");
 let items = this.real.fetchItems();
 console.log("Called it");
 return items;
 }
}
```

如前所述，在线命令的代理版本包含对实际命令的引用，实际上就是我们的实际命令。关键在于，昂贵的操作是我们只在真正需要时才想要访问的功能。在 HTML 方面，一切都优雅地隐藏在封装后。在 TypeScript 方面，我们只在用户请求详细信息时才执行调用，而不是之前。

# 循环计数

任何类型的网络应用程序通常都充满了循环。它可能是 *Amazon.com* 上的产品循环，银行网站上的交易循环，电话运营商网站上的电话循环等等。最糟糕的是，页面上可能有很多循环。当这些循环遍历静态集合时，在生成页面时肯定需要花费时间，除非你无能为力。你仍然可以应用我们在本章前面看到的模式，来减少集合深度，并节省每个项目的大量调用。然而，真正的性能问题出现在这些循环与异步发展的集合绑定时。确实，Angular 和所有允许这种绑定的框架，每次集合发生变化时都会重新绘制集合。它现在可以显示集合中哪些项目已被修改，以及如何在 DOM 中选择它们。因此，如果集合中有 1,000 个元素，如果其中一个元素被修改，那么整个集合都必须重新绘制。实际上，这对用户和开发人员来说是相当透明的。然而，根据 JavaScript 集合的值选择和更新 1,000 个 DOM 元素在计算上是昂贵的。

让我们模拟一组书籍：

```ts
export class Book {
 public constructor(public id:number, public title:string){

 this.id = id;
 this.title = title;
 }
}
```

`Book` 类很简单。它只包含两个属性：`id` 和 `title`。在默认的应用组件中，我们添加了一系列书籍和一些方法。在构造函数中，我们填充了书籍。我们还有一个刷新方法，它会随机选择一本书并更新其标题。最后，`makeid` 方法生成一个随机字符串 ID，我们可以用它来填充书名：

```ts
import { Component } from '@angular/core';
import { Book } from './books'
@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})
export class AppComponent {
 title = 'app';
 books: Book[] = [];
 constructor(){
 for (let i = 0; i < 10; i++) {

 this.books.push(new Book(i, this.makeid()))
 }
 }
 refresh(){
 let id =Math.floor(Math.random() * this.books.length)
 this.books[id].title = this.makeid();
 console.log(id, "refreshed")
 }
 private makeid(): string {
 var text = "";
 var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
 for (var i = 0; i < 15; i++)
 text += possible.charAt(Math.floor(Math.random() * possible.length));
 return text;
 }
}
```

我们实验的最后一部分是下面的 HTML 模板：

```ts
<ul>
 <li *ngFor="let book of books; let i = index">{{book.id}} - {{book.title}}</li>
</ul>
<button (click)="refresh()">Refresh</button>
```

我们的书籍类、应用组件和 `html` 模板放在一起，创建了以下页面：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/b3862bcb-3535-49a5-a703-69654d994d70.png)

我们有我们的 10 本书和我们的刷新按钮，它链接到`refresh`函数。按下时，将随机选择并更新一本书。现在，默认情况下，整个列表都必须重新计算。当然，这里的*刷新*机制是手动的，但在更现实的情况下，刷新将是异步的，例如来自远程 API 的更新。为了帮助 Angular 找出哪个元素已更改并需要刷新，我们可以使用`ngFor`的`trackBy`选项，如下所示：

```ts
<ul>
 <li *ngFor="let book of books; trackBy: trackByFn; let i = index">{{book.id}} - {{book.title}}</li>
</ul>
<button (click)="refresh()">Refresh</button>
The trackBy: trackByFn;we added references a function of our component named trackByFn
  trackByFn(index, item) {
returnindex; // or item.id
 }
```

这个函数帮助 Angular 知道如何跟踪我们书集合中的元素。现在，当按下刷新按钮时，只有修改过的元素将被重新计算和重绘。换句话说，只有一个 DOM 元素将被操作。再次强调，对于 10 个元素，差异是不明显的。然而，对于几十个元素，根据硬件的不同，页面可能会变得有点迟缓。我们可以通过使用 Chrome 开发工具来确认`trackByFn`函数的操作方式。在检查 DOM 时，如果单击刷新按钮，那么只有一个`<li>`标记会亮起。DOM 元素在修改时会亮起。在下面的截图中，您可以看到只有索引 6 的元素被重新计算，而不是列表中的所有元素：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/649968bd-d2da-4677-915e-743005b4079d.png)

# 变更检测和不可变状态

我们在上一篇文章中提到的问题是任何映射某种视图和模型的框架固有的。这不是 Angular 的特殊性。也就是说，这个问题虽然在循环中被加剧，但也存在于其他地方。准确地说，它存在于我们的模型和视图之间的每一个绑定的地方。换句话说，每当我们的 HTML 模型中有`{{ myValue }}`时，这对我们的应用程序来说都是性能上的打击。

那么，解决方案是什么呢？完全停止使用绑定吗？嗯，这并不是非常实际的，因为这样我们就放弃了 JavaScript 最初的吸引力。不，真正的解决方案是使我们的对象不可变。然而，要理解为什么需要这样做，我们需要看一下 Angular 是如何实现变更检测的。变更检测就像它的名字所暗示的那样，是 Angular 执行的用于检测是否有任何变化的过程。如果有变化，对象将被重新处理并重新绘制到 DOM 中。Angular 默认的做法是将一个*watcher*附加到我们的模型上。观察者会观察模型，并为视图中绑定的每个值保留一些信息。它会保留绑定对象的引用，对象的每个属性的旧值和新值。当对象的状态发生变化时，旧值和新值就会被使用。在上一节的书籍示例中，我们的模型的观察者会为每本书保留其引用、旧 ID 和新 ID，以及旧标题和新标题。在每个检测周期，Angular 都会检查对象的旧属性和新属性是否匹配，如下所示：

```ts
book == book ? No; repaintBook.title == Book.title? No; repaintBook.id == Book.it ? No; repaint
```

通常情况下，单独进行这些操作并不会有太大的影响。但是，当页面中有数百个对象，每个对象都有几十个映射属性时，性能就会受到影响。正如我之前所说，解决这个问题的方法就是不可变性。对象的不可变性意味着我们的对象不能改变它们的属性。如果我们想要改变视图中显示的值，那么我们必须整体改变对象。如果你遵循不可变性的原则，那么之前的控制流将如下所示：

```ts
book == book ? No; repaint
```

这样可以节省我们在应用程序中到处使用的大量条件语句，但这也意味着我们在模型中绑定变量的修改，比如 `book.title = "qwerty"`，不会在视图中反映出来。为了使这种修改可见，我们需要用一个新的书籍对象来更新视图。让我们用这个新概念做一些实验。这是我们的 HTML 模板：

```ts
{{ book.id }} - {{ book.title }}<br/><button (click)="changeMe()">CHANGE</button>
```

这是我们的组件：

```ts
import { Component } from '@angular/core';
import { Book } from './book'
@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})
export class AppComponent {
 title = 'app';
 book: Book;
 constructor(){
 this.book = new Book(1, "Some Title");
 }
 changeMe(){
 this.book.title = "Some Other Title";
 }
}
```

书籍类保持在上一节中所呈现的状态。现在，在提供此应用程序时，您将会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/42b05852-662d-4166-a3d8-f64162fe9034.png)

按下“CHANGE”按钮将会改变显示的标题，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/ae34d832-bc9b-4fd6-b953-4e84b67fa122.png)

如果我们告诉 Angular，我们更希望只检查引用是否发生了变化，而不是通过使用`ChangeDetection.OnPush`方法检查每个属性的值，那么按钮将不再对视图产生任何影响。实际上，模型的值已经发生了变化，但是变化不会被变化检测算法捕捉到，因为书的引用仍然是相同的，正如我们之前解释的那样。因此，如果你确实想要将你的变化传播到视图中，你必须改变引用。考虑到所有这些，我们的组件看起来是这样的：

```ts
import { Component, Input } from '@angular/core';
import { Book } from './book'
import { ChangeDetectionStrategy } from '@angular/core';
@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css'],
 changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppComponent {
 title = 'app';
 @Input() book: Book;
 constructor(){
 this.book = new Book(1, "Some Title");
 }
 changeMe(){
 this.book = new Book(this.book.id, "Some Other Title");
 }
}
```

我们向我们的组件添加了`changeDetection: ChangeDetectionStrategy.OnPush`，并修改了`changeMe`方法，使其创建一个新的书，而不是更新旧的书。当然，创建一个新对象比更新现有对象更昂贵。然而，这种技术为 Angular 应用程序带来了更好的性能，因为有无数个周期，什么都没有发生，但是每个对象的属性仍然与它们的旧值进行比较，比实际发生变化的周期要多得多。

通过这种技术，我们显著提高了应用程序的性能，但代价是必须考虑何时希望将对象的更新传播到视图中。请注意，这也适用于过滤器和管道。如果你的应用程序只有一个从模型到视图的绑定值，你可能会认为这并不重要，你可以一路使用可变的方式。如果你的应用程序确实只有一个绑定值，并且这个值从未使用`{{ myValue | myPipe }}`符号进行管道或过滤，那么你是对的。

事实上，每个管道都是由我们的应用程序异步处理的。实际上，如果你调用了 100 次`myPipe`，你实际上创建了相当于 100 个观察者来观察`myValue`的值，并将你的管道应用到它。这是有道理的，因为你的管道无法知道它将要处理什么，并且无法预料到其计算结果对于这 100 次调用来说是相同的。因此，它会根据需要观察和执行多次。如果你发现自己的模板中充满了返回相同值的管道调用，最好是创建一个带有该值作为输入的虚拟组件，或者完全将转换后的值存储在你的模型中。

# 原型和可重用池

面向对象的开发人员寻找减少创建对象成本的方法-特别是当这些对象因为需要数据库拉取或复杂的数学运算而昂贵时。减少特定对象创建成本的另一个原因是当你创建大量对象时。如今，后端开发人员倾向于忽视优化的这一方面，因为按需的 CPU/内存已经变得便宜且易于调整。每月多花几美元就可以在后端拥有额外的核心或 256 MB 的 RAM。

这对于桌面应用程序开发人员来说曾经也是一个大问题。在客户端桌面上，没有办法按需添加 CPU/RAM，但是相当节奏的四核处理器和消费级 PC 上可怕的大量 RAM 使这个问题变得不那么棘手。如今，似乎只有游戏和密集的分析解决方案开发人员才关心这个问题。那么，毕竟为什么你应该关心对象的创建时间呢？嗯，你正在构建的东西很可能会被旧设备访问（我仍然在厨房或沙发上使用 iPad 1 进行休闲浏览）。虽然桌面应用程序开发人员可以发布最低和推荐配置，并通过拒绝安装它们来强制执行它们，但是作为 Web 开发人员，我们没有这种奢侈。现在，如果你的网站表现不佳，用户不会质疑他们的设备，而是质疑你的技能...最终，即使在一台性能强大的机器上，他们也不会使用你的产品。让我们看看如何使用“原型”设计模式。首先，我们需要一个“原型”接口，如下所示：

```ts
export interface Prototype{
 clone():Prototype;
}
```

“原型”接口只定义了返回符合“原型”标准的对象的“克隆”方法。你已经猜到了，创建对象的优化方式是在需要时克隆它们！所以，假设你有一个名为“电影”的对象，由于某些原因，需要花费时间来构建：

```ts
export class Movie implements Prototype {

 private title:string;
 private year:number;
 //...

 public constructor()
 public constructor(title:string = undefined, year:number = undefined)
 {
 if(title == undefined || year == undefined){
 //do the expensive creation
 }else{
 this.title = title;
 this.year = year;
 }
 }

 clone() : Movie {
```

```ts
 return new Movie(this.title, this.year);
 }
 }

 expansiveMovie:Movie = new Movie();
 cheapMovie = expansiveMovie.clone();
```

正如你所看到的，TypeScript 中覆盖函数的方式与大多数语言不同。在这里，构造函数的两个签名位于彼此之上，并共享相同的实现。这就是`Prototype`模式的全部内容。另一个经常与`Prototype`模式一起使用的模式是对象池模式。在处理昂贵的创建对象时，克隆它们确实会产生巨大的差异。更大的差异是根本不做任何事情：不创建，不克隆。为了实现这一点，我们可以使用池模式。在这种模式中，我们有一组对象池，可以被任何客户端或组件共享，特别是在 Angular 2 应用程序的情况下。池的实现很简单：

```ts
export class MoviePool{

 private static movies:[{movie:Movie, used:boolean}] = [];
 private static nbMaxMovie = 10;
 private static instance:MoviePool;

 private static constructor(){}

 public static getMovie(){

 //first hard create
 if(MoviePool.movies.length == 0){

 MoviePool.movies.push({movie:new User(), used:true});
 return MoviePool.movies[0].movie;

 }else{

 for(var reusableMovie:{movie:Movie, used:boolean} of MoviePool.movies){
 if(!reusableMovie.used){
 reusableMovie.used = true;
 return reusableMovie.movie;
 }
 }
 }

 //subsequent clone create
 if(MoviePool.movie.length < MoviePool.nbMaxMovie){

 MoviePool.movies.push({movie:MoviePool.movies[MoviePool.movies.length - 1].clone(), used:true});
 return MoviePool.movies[MoviePool.movies.length - 1].movie;
 }

 throw new Error('Out of movies');
 }

 public static releaseMovie(movie:Movie){
 for(var reusableMovie:{movie:Movie, used:boolean} of MoviePool.movies){
 if(reusableMovie.movie === movie){
 reusableMovie.used = false;
 }
 return;
 }
 }
 }
```

首先，这个池也是一个单例。实际上，如果任何人都可以随意创建池，那么这种昂贵的可重用设计就没有多大意义。因此，我们有静态属性`instance:MoviePool`和私有构造函数，以确保只能创建一个池。然后，我们有以下属性：`private static movies:[{movie:Movie, used:boolean}] = [];`。

`movies`属性存储了一系列电影和一个布尔值，用于确定当前是否有人在使用任何给定的电影。由于假设电影对象在内存中创建或维护是很耗费资源的，因此有必要对我们的对象池中可以拥有多少这样的对象进行硬性限制。这个限制由私有静态属性`nbMaxMovie = 10;`来管理。要获取电影，组件必须调用`getMovie():Movie`方法。这个方法在第一部电影上进行硬性创建，然后利用`Prototype`模式来创建任何后续的电影。每当从池中取出一部电影时，`getMovie`方法会将`used`布尔值更改为 true。需要注意的是，在池满了并且没有空闲电影可供分配的情况下，会抛出错误。

最后，组件需要一种方法来将他们的电影归还给池，以便其他人可以使用它们。这是通过`releaseMovie`方法实现的。这个方法接收一个假设已经取出的电影，并遍历池中的电影，根据布尔值将它们设置为 false。因此，电影对其他组件变得可用。

# 摘要

在本章中，我们学习了如何通过限制我们的 AJAX 调用和代理设计模式来避免在*Angular*应用程序中遇到主要性能问题。我们还学习了如何在性能方面控制循环的不良影响。然后，我们深入研究了 Angular 的变更检测过程，以使其与不可变对象很好地配合，以应对对象数量过高的情况。最后，我们还学习了关于原型和可重用池模式，这可以帮助减少应用程序所需资源的占用空间。

在下一章中，我们将学习关于我们 Angular 应用程序的操作模式。操作模式是帮助监视和诊断实时应用程序的模式。


# 第七章：操作模式

在这最后一章中，我们将专注于改进企业规模的 Angular 应用程序的操作模式。虽然前几章侧重于稳定性、性能和导航，但如果我们无法顺利操作我们的应用程序，这一切可能都会崩溃。在操作应用程序时，有几个值得考虑的理想情况，例如：

+   透明度

+   日志记录

+   诊断

现在，后端应用的操作策略和模式可以更容易实现。虽然后端应用可以在不同类型的容器、虚拟机甚至裸机中运行，但与前端应用相比，操作它们更容易。事实上，您可以注册正在进行的程序、CPU 使用率、内存使用率、磁盘使用率等，这是因为您直接或间接（通过您的服务提供商）可以访问这些服务器。对于前端应用程序，这些统计数据仍然是可取的。假设我们有一个用 Angular 编写的前端应用程序，在测试期间在各个方面表现良好，但在实际运行时失败。为什么会发生这种情况呢？例如，如果您开发的 Angular 应用程序正在使用本地部署的 API，您必须考虑到您的用户遭受网络延迟。这些延迟可能导致您的应用程序表现异常。

# 通用健康指标

我们可以采取的第一步行动是监视一些通用健康指标，以实现我们的 Angular 应用程序的可观察性。我们将要处理的通用健康指标分为几类。首先，我们有两个来自 Angular 分析器的指标：

+   `msPerTick`：每个滴答所需的平均`ms`。滴答可以被视为刷新操作或重绘。换句话说，重新绘制所有变量所需的毫秒数。

+   `numTicks`：经过的滴答数。

我们收集的其他类型的指标与客户端工作站相关：

+   `core`：逻辑核心数

+   `appVersion`：所使用的浏览器

我们还可以提取有关连接的信息：

+   `cnxDownlink`：下行连接速度

+   `cnxEffectiveType`：连接类型

最后，最后一组指标涉及 JavaScript 堆本身的大小：

+   `jsHeapSizeLimit`：堆的最大大小。

+   `totalJSHeapSize`：这是 JavaScript 堆的当前大小，包括未被任何 JavaScript 对象占用的空闲空间。这意味着`usedJsHeapSize`不能大于`totalJsHeapSize`。

+   `usedJSHeapSize`：JavaScript 对象使用的内存总量，包括 V8 内部对象。

为了收集这些指标，我们将创建一个专门的 Angular 服务。该服务将负责访问正确的变量，将它们组装成一个完美的对象，并通过 API post 将它们发送回我们的基础设施。

第一组指标可以通过 Angular 分析器访问。分析器注入了一个名为`ng`的变量，可以通过浏览器命令行访问。大多数用于监视 Angular 应用程序性能的工具都是在开发过程中使用的。为了访问这些工具，我们可以使用`window`变量并像这样抓取它：

```ts
window["ng"].profiler
```

然后，我们可以访问`timeChangeDetection`方法，该方法为我们提供了`msPerTick`和`numTicks`指标。

在一个方法中，这可以转化为以下内容：

```ts
var timeChangeDetection = window["ng"].profiler.timeChangeDetection()
```

在任何 JavaScript 应用程序中都可以找到的另一个有用的变量是 navigator。navigator 变量暴露了有关用户使用的浏览器的信息。`window.navigator.hardwareConcurrency`和`window.navigator.appVersion`分别给出了逻辑核心数和应用程序版本。

虽然前面提到的变量可以在任何能够运行*Angular*应用程序的浏览器上访问，但在撰写本文时，其余的指标只在 Chrome 上可用。如果我们的用户使用的不是 Chrome，那么我们将无法访问这些指标。然而，Chrome 仍然是最常用的浏览器，目前没有迹象表明这种情况会很快改变。因此，对于我们的大部分用户群，我们将能够检索到这些指标。

下一批指标与我们应用程序的内存性能有关：`jsHeapSizeLimit`、`totalJSHeapSize`和`usedJSHeapSize`。在 Chrome 上，它们是`window.performance["memory"]`对象的属性。然而，在其他浏览器上，我们需要提供一个 polyfill：

```ts
var memory:any = window.performance["memory"] ? window.performance["memory"] : {
"jsHeapSizeLimit":0,
"totalJSHeapSize":0,
"usedJSHeapSize":0,
}
```

在前面的代码中，我们检查了`memory`对象是否存在。如果对象存在，我们将其赋值给本地的`memory`变量。如果对象不存在，我们提供一个简单的 polyfill，其中指标的值为 0。

最后一组指标与用户连接有关。与内存对象一样，它只能在 Chrome 上访问。我们将使用与之前相同的技术：

```ts
var connection:any = window.navigator["connection"] ? window.navigator["connection"] : {
"effectiveType": "n/a",
"cnxDownlink": 0,
}
```

这是`Monitor`服务的实现，其中在`metric`方法中收集指标。在方法结束时，我们将指标发送到 API 端点：

```ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
@Injectable()
export class MonitorService {
constructor(private http:HttpClient) { }
public metrics(){
var timeChangeDetection = window["ng"].profiler.timeChangeDetection()
var memory:any = window.performance["memory"] ? window.performance["memory"] : {
"jsHeapSizeLimit":0,
"totalJSHeapSize":0,
"usedJSHeapSize":0,
}
var connection:any = window.navigator["connection"] ? window.navigator["connection"] : {
"effectiveType": "n/a",
"cnxDownlink": 0,
}
var perf = {
"msPerTick": timeChangeDetection.msPerTick,
"numTicks": timeChangeDetection.numTicks,
"core": window.navigator.hardwareConcurrency,
"appVersion": window.navigator.appVersion,
"jsHeapSizeLimit": memory.jsHeapSizeLimit,
"totalJSHeapSize": memory.totalJSHeapSize,
"usedJSHeapSize": memory.usedJSHeapSize,
"cnxEffectiveType": connection.effectiveType,
"cnxDownlink": connection.downlink,
}
this.http.post("https://api.yourwebsite/metrics/", perf)
return perf;
}
}
```

这是`perf`对象中的变量的示例：

+   `msPerTick`: 0.0022148688576149405

+   `numTicks`: 225747

+   `core`: 12

+   `appVersion`: `5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537....L, like Gecko) Chrome/66.0.3359.139 Safari/537.36" jsHeapSizeLimit: 2190000000, ...}appVersion: "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36`

+   `cnxDownlink`: 10

+   `cnxEffectiveType`: `4g`

+   `core`: 12

+   `jsHeapSizeLimit`: 2190000000

+   `msPerTick`: 0.0022148688576149405

+   `numTicks`: 225747

+   `totalJSHeapSize`: 64000000

+   `usedJSHeapSize`: 56800000

在服务器端，这些指标可以被馈送到 ELK 堆栈或您选择的类似堆栈中，并增强您的应用程序的可观察性。

# 特定指标

除了我们之前查看的指标，我们可以在我们的服务中添加一个方法，以便我们能够发送特定的指标，如下所示：

```ts
public metric(label:string, value:any){
this.http.post("https://api.yourwebsite/metric/", {
label:label,
value:value,
})
}
```

# 错误报告

增强应用程序的透明度和可观察性的另一种方法是报告在客户端发生的每一个 JavaScript 错误。在 JavaScript 中，这样做相对简单；你只需要将一个回调函数附加到`window.onerror`事件上，如下所示：

```ts
window.onerror = function myErrorHandler(errorMsg, url, lineNumber) {
alert("Error occured: " + errorMsg);
}
```

这将简单地在每次发生错误时创建一个警报。然而，使用 Angular 时，你不能使用相同的简单技术——不是因为它很复杂，而是因为它需要创建`ne`类。这个新类将实现 Angular 错误处理程序接口，如下所示：

```ts
class MyErrorHandler implements ErrorHandler {
handleError(error) {
// do something with the exception
}
}
```

我们将继续改进`monitor`服务，以便它也可以成为我们的`ErrorHandler`：

```ts
import { Injectable, ErrorHandler } from '@angular/core';
import { HttpClient } from '@angular/common/http';
@Injectable()
export class MonitorService implements ErrorHandler{
constructor(private http:HttpClient) { }
handleError(error) {
this.http.post("https://api.yourwebsite/errors/", error)
}
...
}
```

然后，这些错误可以被馈送到您的`ELK`堆栈，甚至直接插入到您的 Slack 频道中，就像我们在[Toolwatch.io](http://www.toolwatch.io)中所做的那样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/bc5e08d9-3cf7-4eba-96b8-46d75956f9dd.png)

为了使用这个错误处理程序来替代 Angular 的默认错误处理程序，你需要在声明模块时提供它：

```ts
providers : [{ provide : ErrorHandler, useClass : MonitorService }]
```

# 使用 AOP 的方法指标

到目前为止，我们只能在特定时刻监控我们的系统：调用度量、度量和发生的错误。在我们的应用程序中监控所有内容的一种可靠方法是在*Angular*应用程序中使用**AOP**（**面向方面的编程**）。AOP 并不是一种新技术，但在 JavaScript 生态系统中并不广泛使用。AOP 包括定义方面。方面是与我们应用程序的指定部分相关联的子程序。方面在编译时编织到方法中，并在编织到的方法之前和/或之后执行。在基于 Angular 的应用程序中，该方法将在从 TypeScript 到 JavaScript 的转译时编织。在纯 JavaScript 中将方面编织到方法是很简单的。考虑以下示例：

```ts
function myFunc(){
Console.log("hello");
}
function myBeforeAspect(){
Console.log("before...")
}
function myAfterAspect(){
Console.log("after");
}
var oldFunc = myFunc;
myFunc = function(){
myBeforeAspect();
oldFunc();
myAfterAspect();
}
```

在这个片段中，我们声明了三个函数：`myBeforeAspect`，`myFunc`和`myAfterAspect`。在它们各自的声明之后，我们创建了`oldFunc`变量，并将其赋值为`myFunc`。然后，我们用新的实现替换了`myFunc`的实现。在这个新的实现中，除了`oldFunc`之外，我们还调用了`myBeforeAspect`和`myAfterAspect`。这是在 JavaScript 中实现方面的一种简单方法。我们已经添加了行为到`myFunc`的调用中，而不会破坏我们的内部 API。实际上，如果在程序的另一个部分中调用了`myFunc`函数，那么我们的程序仍然是有效的，并且会执行得就像没有改变一样。此外，我们还可以继续向增强函数添加其他方面。

在 Angular-flavored TypeScript 中也可以实现这一点：

```ts
constructor(){
this.click = function(){
this.before();
this.click();
this.after();
}
}
after(){
console.log("after")
}
before(){
console.log("before");
}
click(){
console.log("hello")
}
```

在这里，我们的构造函数将两个方面编织到`click`方法中。`click`方法将执行其行为，以及方面的行为。在 HTML 中，AOP 的任何内容都不会显现出来：

```ts
<button (click)="click()">click</button>
```

现在，我们可以手动将这种技术应用到所有的方法上，并调用我们监控服务的`metric`方法。幸运的是，存在各种库可以为我们处理这个问题。到目前为止，最好的一个叫做`aspect.js`（[`github.com/mgechev/aspect.js`](https://github.com/mgechev/aspect.js)）。

`aspect.js`利用了 ECMAScript 2016 的装饰器模式。

我们可以使用`npm install aspect.js -save`来安装它，然后我们可以定义一个类似这样的方面：

```ts
class LoggerAspect {
@afterMethod({
classNamePattern: /^someClass/,
methodNamePattern: /^(some|other)/
})
invokeAfterMethod(meta: Metadata) {
console.log(`Inside of the logger. Called ${meta.className}.${meta.method.name} with args: ${meta.method.args.join(', ')}.`);
@beforeMethod({
classNamePattern: /^someClass/,
methodNamePattern: /^(get|set)/
})
invokeBeforeMethod(meta: Metadata) {
console.log(`Inside of the logger. Called ${meta.className}.${meta.method.name} with args: ${meta.method.args.join(', ')}.`);
}
}
```

在这方面，我们有几个部分。首先，我们有一个`@afterMethod`方法，它接受一个`classNamePattern`和一个`methodNamePattern`。这些模式是正则表达式，用于定义编织到特定方面的哪些类和方法。然后，在`invokeAfterMethod`中，我们定义要应用的行为。在这个方法中，我们只是记录调用的方法以及调用该方法的参数值。

我们使用`@beforeMethod`重复这个操作。

如果我们保持这样的情况，日志将在客户端打印出来。如果我们想获得这些日志，我们将不得不再次修改我们的`Monitor`服务。

我们将添加一个名为`log`的静态方法和一个静态的`HTTP`客户端。这些是静态的，因为我们可能会编织不接收`Monitor`服务注入的组件。这样，所有服务，无论是否注入，都将能够发送它们的日志：

```ts
static httpStatic:HttpClient
constructor(private http:HttpClient) {
MonitorService.httpStatic = http;
}
static sendLog(log:string){
MonitorService.httpStatic.post("https://api.yourwebsite/logs/", log)
}
```

在`Monitor`服务的构造函数中，我们填充了静态客户端。这将在我们的应用程序启动并且服务是单例时完成。因此，我们只做一次。

这是`Monitor`服务的完整实现：

```ts
import { Injectable, ErrorHandler } from '@angular/core';
import { HttpClient } from '@angular/common/http';
@Injectable()
export class MonitorService implements ErrorHandler{
static httpStatic:HttpClient
constructor(private http:HttpClient) {
MonitorService.httpStatic = http;
}
public static log(log:string){
MonitorService.httpStatic.post("https://api.yourwebsite/logs/", log)
}
handleError(error) {
this.http.post("https://api.yourwebsite/metrics/", error)
}
public metric(label:string, value:any){
this.http.post("https://api.yourwebsite/metric/", {
label:label,
value:value,
})
}
public metrics(){
var timeChangeDetection = window["ng"].profiler.timeChangeDetection()
var memory:any = window.performance["memory"] ? window.performance["memory"] : {
"jsHeapSizeLimit":0,
"totalJSHeapSize":0,
"usedJSHeapSize":0,
}
var connection:any = window.navigator["connection"] ? window.navigator["connection"] : {
"effectiveType": "n/a",
"cnxDownlink": 0,
}
this.metric("msPerTick", timeChangeDetection.msPerTick);
this.metric("numTicks", timeChangeDetection.numTicks);
this.metric("core", window.navigator.hardwareConcurrency);
this.metric("appVersion", window.navigator.appVersion);
this.metric("jsHeapSizeLimit", memory.jsHeapSizeLimit);
this.metric("totalJSHeapSize", memory.totalJSHeapSize);
this.metric("usedJSHeapSize", memory.usedJSHeapSize);
this.metric("cnxEffectiveType", connection.effectiveType);
this.metric("cnxDownlink", connection.downlink);
}
}
```

该方面可以修改为调用新的静态方法：

```ts
class LoggerAspect {
@afterMethod({
classNamePattern: /^SomeClass/,
methodNamePattern: /^(some|other)/
})
invokeBeforeMethod(meta: Metadata) {
MonitorService.log(`Called ${meta.className}.${meta.method.name} with args: ${meta.method.args.join(', ')}.`);
}
@beforeMethod({
classNamePattern: /^SomeClass/,
methodNamePattern: /^(get|set)/
})
invokeBeforeMethod(meta: Metadata) {
MonitorService.log(`Inside of the logger. Called ${meta.className}.${meta.method.name} with args: ${meta.method.args.join(', ')}.`);
}
}
```

除了`className`，`methodName`和`args`之外，我们可以使用`@Wove`语法填充每个组件的元变量，如下面的代码所示：

```ts
@Wove({ bar: 42, foo : "bar" })
class SomeClass { }
```

自定义元变量的一个有趣用例是使用它们来存储每个方法的执行时间，因为元变量值从 before 方法传递到 after 方法。

因此，我们可以在我们的`@Wove`注释中有一个名为`startTime`的变量，并像这样使用它：

```ts
@Wove({ startTime: 0 })
class SomeClass { }
class ExecutionTimeAspect {
@afterMethod({
classNamePattern: /^SomeClass/,
methodNamePattern: /^(some|other)/
})
invokeBeforeMethod(meta: Metadata) {
meta.startTime = Date.now();
}
@beforeMethod({
classNamePattern: /^SomeClass/,
methodNamePattern: /^(get|set)/
})
invokeBeforeMethod(meta: Metadata) {
MonitorService.metric(`${meta.className}.${meta.method.name`,
Date.now() - meta.startTime;
}
}
```

现在，我们有另一个方面将被编织到我们的类中，它将测量其执行时间并使用`MonitorService`的`metric`方法报告它。

# 总结

操作 Angular 应用程序可能很复杂，因为在运行时观察我们的应用程序相对困难。虽然观察后端应用程序很简单，因为我们可以访问运行环境，但我们习惯使用的技术不能直接应用。在本章中，我们看到了如何通过使用收集性能指标、自定义指标和日志，并通过面向方面的编程自动应用所有这些来使 Angular 应用程序监视自身。

虽然本章介绍的技术可以提供对应用程序的 100%可观察性，但它们也有一些缺点。实际上，如果您的应用程序很受欢迎，您将不仅需要为您的页面提供服务并回答您的 API 调用，还需要接受日志和指标，这将过度消耗您的后端基础设施。另一个缺点是，恶意的人可能会通过您的 API 向您提供错误的指标，并为您提供关于当前正在发生的实时应用程序情况的偏见图片。

这些缺点可以通过仅监视客户端的子集来解决。例如，您可以根据随机生成的数字仅为 5%的客户端激活日志记录和跟踪。此外，您可以通过为每个请求提供 CSRF 令牌来验证希望向您发送指标的用户的真实性。
