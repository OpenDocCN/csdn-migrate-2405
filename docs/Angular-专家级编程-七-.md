# Angular 专家级编程（七）

> 原文：[`zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9`](https://zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Angular 中的设计模式

TypeScript 是一种面向对象的编程语言，因此我们可以利用几十年的面向对象架构知识。在这一章中，我们将探讨一些最有用的面向对象设计模式，并学习如何在 Angular 中应用它们。

Angular 本身是一个面向对象的框架，它强制你以某种方式进行大部分开发。例如，你需要有组件、服务、管道等。强制你使用这些构建块有助于构建良好的架构。这很像 Zend 框架为 PHP 或 Ruby on Rails 为 Ruby 所做的事情。框架的存在是为了让你的生活更轻松，加快开发时间。

虽然 Angular 的设计方式远远超出平均水平，但我们总是可以做得更好。我并不是说我在这一章中提出的设计是最终的，你可以用它来解决从面包店的一页纸到火星一号任务的仪表板的任何问题--这样的设计并不存在--但它确实会提高你的工具箱。

在这一章中，我们将学习使用以下模式：

+   模型-视图-控制器（MVC）

+   单例

+   依赖注入

+   原型

+   可重用池

+   工厂

+   备忘录

# 模型-视图-控制器（MVC）

哦，MVC，好老的 MVC。多年来你为我们服务得很好。现在，人们希望你退休，最好不要有麻烦。此外，即使我也能看到，更年轻的单向用户界面架构可以比你更聪明，让你看起来像是过去的遗物。

在本节中，我们将首先描述 MVC 是什么，不管用什么编程语言来实现它，然后我们将看到将 MVC 应用于前端编程的缺点。最后，我将介绍一种在 Angular 中实现有意义的 MVC 的方法，这种方法考虑了实现的便利性、维护性和性能。

# MVC 的大局

MVC 设计模式的整体原则非常简单。事实上，如下图所示，它由三个部分组成：模型、视图和控制器。更具体地说，MVC 的意图是定义对象之间的一对多依赖关系，以便当一个对象改变状态时，所有依赖它的对象都会被通知并自动更新：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/bbc1e9fd-1446-480e-aad3-bb764a93e5d1.png)MVC 概述

让我们逐块分析前面的图像：

+   **模型**根据**控制器**发送的命令存储应用程序所需的数据。

+   **控制器**接收**用户**的操作（即点击按钮）并相应地指导**模型**更新。它还可以设置在任何给定时刻使用哪个**视图**。

+   **视图**在**模型**更改时生成和更新。

就是这样。

让我们看看纯 TypeScript 中一个简单的 MVC 实现会是什么样子。

首先，让我们像我们在第十章中所做的那样定义一个`Movie`类，*在 Angular 中的 Material Design*。在这个版本的`Movie`类中，我们只有两个属性，`title`和`release_year`，它们是使用 TypeScript 构造函数定义的：

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

然后，我们定义一个`Model`类，导入包含`Movie`类的`movie.ts`文件，使用引用关键字。这个`Model`类将负责更新视图，它有一个电影数组和两个方法。第一个方法`addMovie(title:string, year:number)`是公共的，它在 movies 属性的末尾添加一个新的电影。它还调用类的第二个方法：`appendView(movie:Movie)`，这个方法是私有的。这个第二个方法根据 MVC 定义操纵视图。视图操纵相当简单；我们在视图的`movie`元素中添加一个新的`li`标签。新创建的`li`标签的内容是电影标题和发行年份的连接：

```ts
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
         var textnode = document.createTextNode(movie.getTitle() +
              "-" + movie.getReleaseYear()); 
         node.appendChild(textnode);
         document.getElementById("movies").appendChild(node);
     }

 }

```

我们现在可以为我们的纯 TypeScript MVC 定义一个控制器。控制器有一个私有的`model:Model`属性，在构造函数中初始化。此外，定义了一个`click`方法。这个方法接受一个字符串和一个数字作为参数，分别用于标题和发行年份。正如你所看到的，`click`方法将标题和发行年份转发给模型的`addMovie`方法。然后，控制器的工作就完成了。它不会操纵视图。你还会注意到`controller.ts`文件的最后一行：`let controller = new Controller()`;。这行允许我们创建一个`Controller`类的实例，视图可以绑定到它：

```ts

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

我们 MVC 实现的最后一部分是视图。我们有一个简单的 HTML 表单，提交时会调用以下内容：`controller.click(this.title.value, this.year.value); return false;.` 控制器在`controller.ts`文件中已经定义为`let controller = new Controller()`*;*。然后，对于参数，我们发送`this.title.value`和`this.year.value`，其中 this 指的是`<form>`。

标题和年份分别指的是电影的标题和发行年份字段。我们还必须添加`return false`以防止页面重新加载。实际上，HTML 表单的默认行为是在提交时导航到操作 URL：

```ts
<html>
     <head>
         <script src="mvc.js"></script>
     </head>
     <body>
         <h1>Movies</h1>
         <div id="movies">
         </div>

         <form action="#" onsubmit="controller.click(this.title.value,
              this.year.value); return false;">
             Title: <input name="title" type="text" id="title">
             Year: <input name="year" type="text" id="year">
            <input type="submit">
         </form>

     </body>
 </html>

```

在页眉中，我们添加了通过以下命令生成的`mvc.js`脚本：`tsc--out mvc.jscontroller.ts model.ts movie.ts`。生成的 JavaScript 如下所示：

```ts
var Movie = (function () {
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
 var Model = (function () {
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
         var textnode = document.createTextNode(movie.getTitle() +
                 "-" + movie.getReleaseYear());
         node.appendChild(textnode);
         document.getElementById("movies").appendChild(node);
     };
     return Model;
 }());
 /// <reference path="./model.ts"/>
 var Controller = (function () {
     function Controller() {
         this.model = new Model();
     }
     Controller.prototype.add = function (title, year) {
         console.log(title, year);
         this.model.addMovie(title, year);
     };
     return Controller;
 }());
 var controller = new Controller();

```

在执行方面，在加载时，HTML 页面将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/94456d7f-cf35-4038-b636-0d9d10e7873c.png)加载时的 MVC。

然后，如果您使用表单并添加电影，它将自动影响视图，并显示新的电影，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/0b4638a6-1dd7-4c1e-9442-76905de0f3d7.png)在使用表单后的 MVC。

# 前端的 MVC 限制

那么，为什么在前端编程中使用 MVC 模式不那么常见，尤其是在像 Angular 这样的框架支持下？首先，如果您正在为提供服务的应用程序使用 Angular，您很可能会有一个与之交换一些信息的后端。然后，如果您的后端也使用 MVC 设计模式，您将得到以下层次结构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e0d23afd-59e0-4cf6-9c19-6145cc717c47.png)前端和后端的 MVC。

在这个层次结构中，我们在另一个 MVC 实现的顶部有一个 MVC 实现。这两种实现通过一个 API 服务进行通信，该服务向后端控制器发送请求并解析生成的视图。具体示例是，如果用户必须登录您的应用程序，他们将在由用户模型和登录控制器提供支持的前端上看到登录视图。一旦输入了所有信息（电子邮件、密码），用户就会点击登录按钮。

这个点击触发了模型更新，然后模型使用 API 服务触发 API 调用。API 服务向您的 API 的`user/signin`端点发出请求。在后端，请求被用户控制器接收并转发到用户模型。后端用户模型将查询您的数据库，以查看是否有提供的用户和密码匹配的用户。最后，如果登录成功，将输出一个包含用户信息的视图。回到前端，API 服务将解析生成的视图并将相关信息返回给前端用户模型。依次，前端用户模型将更新前端视图。

对于一些开发人员来说，这么多层以及架构在前端和后端上的重复似乎不太对，尽管它通过明确定义的关注点分离带来了可维护性。

双重 MVC 并不是唯一的问题。另一个问题是，前端模型不会是纯模型，因为它们必须考虑 UI 本身的变量，比如可见标签、表单有效性等等。因此，你的前端模型往往会变成一团丑陋的代码，其中 UI 变量与用户的实际表示相互交织。

现在，像往常一样，你可以避免这些陷阱，利用 MVC 模式的优势。让我们在下一节中看看如何做到这一点。

# Angular 是 MVC

在本节中，我提出了一个在 Angular 中证明有效的 MVC 架构。我在`toolwatch.io`（Web、Android 和 iOS）过去的八个月中使用了这个架构。显然，我们在 Web 版本或移动应用上提出的功能是相同的，工作方式也相同；不同的是视图和导航方案。

下图展示了整体架构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/65d357c3-82da-4505-a136-94c7a3791815.png)Angular 的 MVC。

从上到下，我们有后端、可重用的前端部分和专门的前端（即移动端或 Web 端）。正如你所看到的，在后端，没有任何变化。我们保留了传统的 MVC。请注意，前端部分也可以与非 MVC 后端一起工作。

我们的模型将使用该服务通过假想的 JSON API 从远程数据库获取、放置和删除一个简单的 TypeScript 对象。

我们的用户 TypeScript 对象如下所示：

```ts
export class User {

     public constructor(private _email:string, private _password:string){}

     get email():string{
         return this._password;
     }

     get password():string{
         return this._email;
     }

     set email (email:string){
         this._password = email;
     }

     set password (password:string){
         this._email = password;
     }

 }

```

这里没有太多花哨的东西。只是一个简单的 TypeScript 对象，包含两个属性：`email:_string`和`password:_string`。这两个属性在构造函数中使用 TypeScript 内联声明样式进行初始化。我们还利用了 TypeScript 的 getter/setter 来访问`password:string`和`_email:string`属性。你可能已经注意到，TypeScript 的 getter/setter 看起来像 C#属性。嗯，微软是 TypeScript 的主要工业调查者之一，所以这是有道理的。

我确实喜欢写作的简洁性，特别是在构造函数中与内联属性声明结合在一起时。然而，我不喜欢的是必须使用下划线变量名。问题在于，再次，这个 TypeScript 将被转译成 JavaScript，在 JavaScript 中，变量和函数比如说 Java 或 C#更加抽象。

实际上，在我们当前的示例中，我们可以调用`user`类的 getter 如下：

```ts
user:User = new User('mathieu.nayrolles@gmail.com', 'password');

console.log(user.email); // will print mathieu.nayrolles@gmail.com

```

正如你所看到的，TypeScript 并不关心它调用的目标的类型。它可以是一个名为 email 的变量，也可以是一个名为`email()`的函数。无论哪种方式，它都可以工作，产生不同的结果，但它可以工作。这种奇怪行为背后的基本原理是，在面向对象的程序中，在 JavaScript 中，这是可以接受的：

```ts
var email = function(){
     return "mathieu.nayrolles@gmail.com";
 }
 console.log(email);

```

因此，我们需要用不同的名称区分函数的实际变量。因此有了下划线。

现在我们有一个完全可靠的用户对象来操作，让我们回到我们的 MVC 实现。现在我们可以有一个`UserModel`来操作用户**普通旧 TypeScript 对象**（**POTO**）和图形界面所需的变量：

```ts
export class UserModel{

     private user:User;
     private _loading:boolean = false;

     public constructor(private api:APIService){}

     public signin(email:string, password:string){

         this._loading = true;

         this.api.getUser(new User(email, password)).then(

             user => {
                 this.user = user;
                 this._loading = false;
             }
         );
     }

     public signup(email:string, password:string){

         this._loading = true;
         this.api.postUser(new User(email, password)).then(
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

我们的模型，名为`UserModel`，接收了一个`APIService`的注入。`APIService`的实现留给读者作为练习。然而，它将非常类似于我们在第九章中看到的*Angular 2 中的高级表单*。除了`APIService`，`UserModel`拥有`user:User`和`loading:bool`属性。`user:User`代表了实际的用户及其密码和电子邮件。然而，`loading:bool`将用于确定视图中是否应该显示加载旋转器。正如你所看到的，`UserModel`定义了`signin`和`signup`方法。在这些方法中，我们调用了假设的`APIService`的`getUser`和`postUser`方法，它们都接受一个 User 作为参数，并返回一个包含所述用户通过 JSON API 同步的 Promise。收到 Promise 后，我们关闭`loading:bool`旋转器。

然后，让我们来看看控制器，它也将是 Angular 环境中的一个组件，因为 Angular 组件控制显示的视图等等。

```ts
@Component({
     templateUrl: 'user.html'
 })
 export class UserComponent{

     private model:UserModel;

     public constructor(api:APIService){

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

正如你所看到的，控制器（组件）很简单。我们只有一个对模型的引用，并且我们接收一个注入的`APIService`以传递给模型。然后，我们有`signinClick`和`signupClick`方法，从视图接收用户输入并将其传递给`model`。最后一部分，视图，看起来像这样：

```ts

 <h1>Signin</h1>

 <form action="#" onsubmit="signinClick(this.email.value, this.password.value); return false;">

     email: <input name="email" type="text" id="email">
     password: <input name="password" type="password" id="password">
    <input [hidden]="model.loading" type="submit">
    <i [hidden]="!model.loading" class="fa fa-spinner" 
         aria-hidden="true">loading</i>
 </form>

 <h1>Signup</h1>

 <form action="#" onsubmit="signupClick(this.email.value,
      this.password.value); return false;">

     email: <input name="email" type="text" id="email">
     password: <input name="password" type="password" id="password">
     <input [hidden]="model.loading" type="submit">
     <i [hidden]="!model.loading" class="fa fa-spinner" 
       aria-hidden="true">loading</i>
 </form>

```

在这里，我们有两个表单，一个用于登录，一个用于注册。这两个表单除了它们使用的`onsubmit`方法不同之外，都是相似的。登录表单使用我们控制器的`signinClick`方法，注册表单使用`signupClick`方法。除了这两个表单，我们还在每个表单上有一个 Font Awesome 旋转器，只有在用户模型正在加载时才可见。我们通过使用`[hidden]` Angular 指令来实现这一点：`[hidden]="!model.loading"`。同样，当模型正在加载时，提交按钮也是隐藏的。

所以，这就是一个应用于 Angular 的功能性 MVC。

正如我在本节开头所说的，对我来说，MVC 模式在 Angular 中的实际用处来自于它的可扩展性。事实上，利用 TypeScript 的面向对象的特性（以及随之而来的内容）允许我们为不同的 Angular 应用程序专门定制控制器和模型。例如，如果你有一个 Angular 网站和一个 Angular 移动应用程序，就像我在`toolwatch.io`中所做的那样，那么你可以在两边重用业务逻辑。当我们本可以只有一个时，如果随着时间的推移，我们需要编写和维护两个登录、两个注册和两个所有内容，那将是一件遗憾的事情！

例如，在`toolwatch.io`，Web 应用程序使用标准的 Angular，我们使用 Ionic2 和 Angular 构建移动应用程序。显然，我们在移动应用程序（Android 和 iOS）和网站之间共享了许多前端逻辑。最终，它们倾向于实现相同的目的和功能。唯一的区别是用于使用这些功能的媒介。

在下图中，我粗略地表示了一种利用 MVC 模式实现重用和可扩展性的完整方式：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/055395a5-090b-468e-bf7e-211dc47a51ad.png)可重用的 Angular MVC。

后端保持不变。我们在那里有相同的 MVC 模式。作为提醒，后端上的 MVC 模式完全取决于您，例如，您可以利用前端 MVC 模式与功能性的 Go 后端。在此处公开的 MVC 的先前版本不同的是引入了可重用的前端部分。在这部分中，我们仍然有一个负责消费我们的 JSON API 的 API 服务。然后，我们有一个实现`IModel`接口的模型：

```ts
export interface IModel{

     protected get(POTO):POTO;
     protected put(POTO):POTO;
     protected post(POTO):POTO;
     protected delete(POTO):boolean;
     protected patch(POTO):POTO;

 }

```

该接口定义了必须在随后的模型中实现的`put`、`post`、`delete`和`patch`方法。这些方法接受和返回的`POTO`类型是您程序中任何领域模型的母类。领域模型代表您的业务逻辑中可同步的实体，例如我们之前使用的用户。领域模型和 MVC 的模型部分不应混淆。它们根本不是同一回事。在这种架构中，用户将扩展`POTO`。

这次的模型（MVC 模式）也包含一个`POTO`来实现`IModel`接口。此外，它包含您需要更新视图的变量和方法。模型本身的实现如我在本节前面所示，相当简单。然而，我们可以通过利用 TypeScript 的通用方面并设想以下内容来提高一些东西：

```ts
export class AbstractModel<T extends POTO> implements IModel{
     protected T domainModel;

     public constructor(protected api:APIService){}

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

     public constructor(api:APIService){
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
     //Only the code specialized for the UI! 
 }

```

在这里，我们有一个通用的`AbstractModel`，它受到`POTO`的约束。这意味着`AbstractModel`通用类的实际实例（在诸如 C++之类的语言中称为模板）受到类专门化的`POTO`的约束。换句话说，只有诸如`User`之类的领域模型才能被使用。到目前为止，关注点的分离以及可重用性都非常出色。可重用部分的最后一部分是控制器。在我们的注册/登录示例中，它看起来会非常像这样：

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

现在，为什么我们在这里需要一个额外的构建块，不能像我们在 Angular MVC 的简化版本中那样使用简单的 Angular 组件呢？嗯，问题在于，取决于您在 Angular 核心之上使用的内容（Ionic、Meteor 等），组件并不一定是主要的构建块。例如，在 Ionic2 世界中，您使用的是页面，这是经典组件的自定义版本。

因此，例如，移动部分会是这样的：

```ts
export class LoginPage extends UserController{

     public LoginPage(api:APIService){
         super(new UserModel(api));
     }

     //Only what's different on mobile!

 }

```

如果需要的话，你也可以扩展`UserModel`并添加一些专业化，就像在 Angular 的可重用 MVC 图中所示的那样。在浏览器端，添加这段代码：

```ts
@Component({
     templateUrl: 'login.html'
 })
 export class LoginComponent extends UserController{

     public UserComponent(api:APIService){

         super(new UserModel(api));
     }

     //Only what's different on the browser !

 }

```

再一次，你也可以扩展`UserModel`并添加一些专业化。唯一剩下的要涵盖的部分是视图。令我绝望的是，没有办法扩展或添加样式文件。因此，除非 HTML 文件在移动应用和浏览器应用之间是相同的，否则我们注定要在客户端之间有 HTML 文件的重复。根据经验，这种情况并不经常发生。

整个可重用的前端可以作为 Git 子模块、独立库或`NgModule`进行发布。我个人喜欢使用 Git 子模块的方法，因为它允许我在进行对共享前端进行修改时，享受客户端自动刷新的同时拥有两个独立的存储库。

请注意，如果你有几个前端同时访问同一个后端，而不是几种类型的前端，这个 MVC 也是有效的。例如，在电子商务设置中，你可能希望拥有不同品牌的网站来销售在同一个后端中管理的不同产品，就像 Magento 的视图所能实现的那样。

# 单例模式和依赖注入

前端应用程序中使用的另一个方便的模式是单例模式。单例模式确保程序中只存在一个给定对象的实例。此外，它提供了对对象的全局访问点。

实际上看起来是这样的：

```ts
export class MySingleton{

     private static instance:MySingleton = null;

   //This constructor is private in order to prevent new creation  
   //of MySingleton objects    private constructor(){

     }

     public static getInstance():MySingleton{
         if(MySingleton.instance == null){
             MySingleton.instance = new MySingleton();
         }         return MySingleton.instance;    }

 }

 let singleton:MySingleton = MySingleton.getInstance();

```

我们有一个类，它有一个`private static instance:MySingleton`属性。然后，我们有一个`private`构造函数，使以下操作失败：

```ts
let singleton:MySingleton = new MySingleton(); 

```

请注意，它失败是因为你的 TypeScript 转译器抱怨可见性。然而，如果你将`MySingleton`类转译为 JavaScript 并在另一个 TypeScript 项目中导入它，你将能够使用新的操作符，因为转译后的 JavaScript 根本没有可见性。

这种单例模式的相当简单的实现的问题是并发。确实，如果两个进程同时调用`getInstance():MySingleton`，那么程序中将会有两个`MySingleton`的实例。为了确保这种情况不会发生，我们可以使用一种称为早期实例化的技术：

```ts
export class MySingleton{

     private static instance:MySingleton = new MySingleton();

     private constructor(){

     }
 }

 singleton:MySingleton = MySingleton.getInstance();

```

虽然你可以在 TypeScript 中实现你的单例，但你也可以利用 Angular 创建单例的方式：服务！确实，在 Angular 中，服务只被实例化一次，并注入到需要它们的任何组件中。这里有一个通过`NgModule`进行服务和注入的例子，我们在本书中之前已经看过：

```ts
// ./service/api.service.ts
 import { Injectable } from '@angular/core';

 @Injectable()
 export class APIService {

     private increment:number = 0;

     public constructor(){
         this.increment++;
     }

     public toString:string{
         return "Current instance: " + this.increment;
     }
 }

 // ./app.component.ts

 @Component({
   selector: 'app-root',
   templateUrl: './app.component.html',
   styleUrls: ['./app.component.css'],
 })
 export class AppComponent {

     public constructor(api:APIService){
         console.log(api);
     }

 }

 // ./other.component.ts

 @Component({
   selector: 'other-root',
   templateUrl: './other.component.html',
   styleUrls: ['./other.component.css'],
 })
 export class OtherComponent {

     public constructor(api:APIService){
         console.log(api);
     }
 }

 //app.module.ts

 import { BrowserModule } from '@angular/platform-browser';
 import { NgModule } from '@angular/core';
 import { FormsModule, ReactiveFormsModule  } from '@angular/forms';
 import { HttpModule } from '@angular/http';
 import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
 import { APIService } from './services/api.service'

 import { AppComponent } from './app.component';
 import { OtherComponent } from './other.component';

 @NgModule({
   declarations: [
     AppComponent,
     OtherComponent
   ],
   imports: [
     BrowserModule,
     FormsModule,
     HttpModule,
     ReactiveFormsModule,
     NgbModule.forRoot()
   ],
   providers: [APIService],
   bootstrap: [AppComponent]
 })
 export class AppModule { }

```

在上述代码中，我们有：

+   `APIService`显示了`@Injectable()`注解，使其可以被注入。另外，`APIService`有一个`increment:number`属性，每次创建新实例时都会增加。`increment:number`是静态的，它将告诉我们程序中有多少个实例。最后，`APIService`有一个`toString:string`方法，返回当前实例编号。

+   `AppComponent`是一个经典组件，它接收了`APIService`的注入。

+   `OtherComponent`是另一个经典组件，它接收了`APIService`的注入。

+   `/app.module.ts`包含我们的`NgModule`。在`NgModule`中，这里显示的大部分声明已经在本书中讨论过。新颖之处来自于`providers: [APIService]`部分。在这里，我们声明了`APIService`本身的提供者。由于`APIService`并没有做什么太疯狂的事情，它可以通过引用类来提供。更复杂的服务，例如需要注入的服务，需要定制的提供者。

现在，如果我们导航到这两个组件，结果是：

```ts
Current instance: 1
Current instance: 1

```

这证明只创建了一个实例，并且相同的实例已被注入到两个组件中。因此，我们有一个单例。然而，这个单例虽然方便，但并不安全。你为什么这样问。嗯，`APIService`也可以在组件级别提供，就像这样：

```ts
// ./app.component.ts

 @Component({
   selector: 'app-root',
   templateUrl: './app.component.html',
   styleUrls: ['./app.component.css'],
   providers: [APIService],
 })
 export class AppComponent {

     public constructor AppComponent(APIService api){
         console.log(api);
     }

 }

 // ./other.component.ts

 @Component({
   selector: 'other-root',
   templateUrl: './other.component.html',
   styleUrls: ['./other.component.css'],
   providers: [APIService],
 })
 export class OtherComponent {

     public constructor OtherComponent(APIService api){
         console.log(api);
     }
 }

```

在这种情况下，将创建两个单独的实例，导致以下输出：

```ts
Current instance: 1
Current instance: 2

```

因此，使用 Angular 服务，你无法强制实施单例模式，与其普通的 TypeScript 对应相反。另外，普通的 TypeScript 会比 Angular 服务快上一个数量级，因为我们完全跳过了注入过程。确切的数字严重依赖于你的机器的 CPU/RAM。

在单例的情况下，唯一剩下的问题是何时使用它。单例强制程序中给定类的唯一实例。因此，它非常适合与后端或任何硬件访问进行通信。例如，在与后端通信的情况下，可能希望只有一个`APIService`处理 API 密钥、API 限制和跨站请求伪造令牌，而无需确保我们在所有组件、模型等中传递相同的服务实例。在硬件访问的情况下，可能希望确保只有一个连接打开到用户的网络摄像头或麦克风，这样在使用完毕后可以正确释放它们。

# 原型和可重用池

面向对象的开发人员寻找减少创建对象成本的方法，特别是当这些对象因为需要进行数据库拉取或复杂的数学运算而昂贵时。减少特定对象创建成本的另一个原因是当你创建大量对象时。如今，后端开发人员倾向于忽视优化的这一方面，因为按需的 CPU/内存已经变得便宜且易于调整。在你的后端上每月多花几美元就可以获得额外的核心或 256MB 的 RAM。

这对于桌面应用程序开发人员来说曾经是一个大问题。在客户端桌面上，没有办法按需添加 CPU/RAM，但是相当规律的四核处理器和消费级 PC 上*荒谬*的大量 RAM 使这个问题变得不那么棘手。

如今，似乎只有游戏和密集型分析解决方案开发人员似乎关心这个问题。那么，毕竟为什么你应该关心对象的创建时间呢？嗯，你正在构建的东西很可能会被旧设备访问（我仍然在厨房或沙发上使用 iPad 1 进行休闲浏览）。虽然桌面应用程序开发人员可以发布最低和推荐配置，并通过拒绝安装来强制执行它们，但作为 Web 开发人员，我们没有这种奢侈。现在，如果你的网站表现不佳，用户不会质疑他们的设备，而是质疑你的技能。最终，即使在一台性能强大的机器上，他们也不会使用你的产品。

让我们看看如何使用`Prototype`设计模式。`Prototype`设计模式允许对象创建定制对象，而无需知道它们的类或任何创建它们的详细信息。其目的是通过复制这个原型来创建新对象，而不是实际实例化一个新对象。首先，我们需要一个`Prototype`接口，如下所示：

```ts
export interface Prototype{

     clone(): Prototype;
 }

```

`Prototype`接口只定义了一个`clone`方法，该方法返回一个符合`Prototype`的对象。您已经猜到了，创建对象的优化方式是在需要时进行克隆！所以假设您有一个`Movie`对象，由于某种原因，需要花费时间来构建：

```ts
export class Movie implements Prototype {

     private title:string;
     private year:number;
     //...

     public constructor(); 
     public constructor(title?: string, year?: number); 
     public constructor(title?: string, year?: number) { 
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
 }

 let expensiveMovie:Movie = new Movie();
 cheapMovie = expensiveMovie.clone();

```

正如您所看到的，TypeScript 中的覆盖函数与大多数语言不同。在这里，构造函数的两个签名叠在一起，并共享相同的实现。

此外，这就是`Prototype`模式的全部内容。

通常与原型模式一起使用的另一个模式是对象池模式。在使用昂贵的创建对象时，克隆它们确实会有所不同。更大的不同之处在于根本不做任何事情：不创建，不克隆。为了实现这一点，我们可以使用池模式。在这种模式下，我们有一组对象池，可以被任何客户端或组件共享，例如在 Angular 应用程序的情况下。池的实现很简单：

```ts
export class MoviePool{

     private static movies:[{movie:Movie, used:boolean}];
     private static nbMaxMovie = 10;
     private static instance:MoviePool;

     private constructor(){}

     public static getMovie(){

         //first hard create
         if(MoviePool.movies.length == 0){

             MoviePool.movies.push({movie:new Movie(), used:true});
             return MoviePool.movies[0].movie;

         }else{

             for(var reusableMovie of MoviePool.movies){
                 if(!reusableMovie.used){
                     reusableMovie.used = true;
                     return reusableMovie.movie;
                 }
             }
         }

         //subsequent clone create
         if(MoviePool.movie.length < MoviePool.nbMaxMovie){

             MoviePool.movies.push({movie:MoviePool.movies[MoviePool.movies.
                length - 1].movie.clone(), used:true});
             return MoviePool.movies[MoviePool.movies.length - 1].movie;
         }

         throw new Error('Out of movies');
     }

     public static releaseMovie(movie:Movie){
         for(var reusableMovie of MoviePool.movies){
             if(reusableMovie.movie === movie){
                 reusableMovie.used = false;
             }
             return;
         }
     }
 }

```

首先，池也是一个单例。事实上，如果任何人都可以随意创建池，那么将不会有太多意义。因此，我们有`static instance:MoviePool`和私有构造函数，以确保只能创建一个池。然后，我们有以下属性：

```ts
private static movies:[{movie:Movie, used:boolean}];  

```

`movies`属性存储了一系列电影和一个布尔值，用于确定当前是否有人在使用任何给定的电影。由于电影对象在理论上很费力创建或在内存中维护，因此有必要对我们的池中可以拥有多少这样的对象进行硬性限制。这个限制由私有的`static nbMaxMovie = 10`属性管理。要获取电影，组件必须调用`getMovie():Movie`方法。这个方法在第一部电影上进行了硬性创建，然后利用原型模式来创建任何后续的电影。

每当从池中检出一部电影时，`getMovie`方法会将使用的布尔值更改为 true。请注意，在池已满且我们没有任何空闲电影可供赠送的情况下，将抛出错误。

最后，组件需要一种方法来将它们的电影归还到池中，以便其他组件可以使用它们。这是通过`releaseMovie`方法实现的。该方法接收一个已检出的电影，并遍历池中的电影，将相应的布尔值设置为 false。因此，电影可以供其他组件使用。

# 工厂模式

假设我们有一个`User`类，其中有两个私有变量：`lastName:string`和`firstName:string`。此外，这个简单的类提供了一个打印“Hi I am”，this.firstName，this.lastName 的方法 hello：

```ts
class User{
     constructor(private lastName:string, private firstName:string){
     }
     hello(){
         console.log("Hi I am", this.firstName, this.lastName);
     }
 }

```

现在，考虑到我们通过 JSON API 接收用户。很可能会是这样的：

```ts
[{"lastName":"Nayrolles","firstName":"Mathieu"}...].  

```

通过以下代码片段，我们可以创建一个`User`：

```ts
let userFromJSONAPI: User = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')[0]; 

```

到目前为止，TypeScript 编译器没有抱怨，并且执行顺利。这是因为解析方法返回`any`（即 Java 对象的 TypeScript 等价物）。当然，我们可以将`any`转换为`User`。然而，`userFromJSONAPI.hello()`将产生：

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
     at Object.<anonymous> (/usr/lib/node_modules/ts-node/
        src/bin/ts-node.ts:110:12)
     at Module._compile (module.js:541:32)
     at Object.Module._extensions..js (module.js:550:10)

```

为什么？嗯，=语句的左侧被定义为`User`，但当我们将其转译为 JavaScript 时，它将被擦除。

使用类型安全的 TypeScript 方法来做这件事将是：

```ts
let validUser = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')
 .map((json: any):User => {
     return new User(json.lastName, json.firstName);
 })[0];

```

有趣的是，`typeof`函数也无法帮助你。在这两种情况下，它都会显示`Object`而不是`User`，因为 JavaScript 中并不存在`User`的概念。

虽然直接的类型安全方法可以工作，但它并不是非常可扩展或可重用的。实际上，无论何时接收到一个 JSON 用户，都必须在每个地方重复使用 map `callback`方法。最方便的方法是使用`Factory`模式来做到这一点。`Factory`用于创建对象，而不会将实例化逻辑暴露给客户端。

如果我们要有一个工厂来创建一个用户；它会是这样的：

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

在这里，我们有一个名为`buildUser`的静态方法，它接收一个 JSON 对象，并从 JSON 对象中获取所有必需的值，以调用一个假设的`User`构造函数。该方法是静态的，就像工厂的所有方法一样。实际上，我们不需要在工厂中保存任何状态或实例绑定的变量；我们只需要封装用户的创建过程。请注意，您的工厂可能会与您的 POTO 的其余部分共享。

# 备忘录模式

在 Angular 的上下文中，备忘录模式是一个非常有用的模式。在由 Angular 驱动的应用程序中，我们过度使用双向数据绑定，例如`User`或`Movie`等领域模型。

让我们考虑两个组件：一个名为`Dashboard`，另一个名为`EditMovie`。在 Dashboard 组件上，您有一个电影列表显示在我们类似 IMDB 的应用程序的上下文中。这样的仪表板视图可能如下所示：

```ts
<div *ngFor="let movie of model.movies"> 
   <p>{{movie.title}}</p> 
   <p>{{movie.year}}</p> 
</div> 

```

这个简单的视图拥有一个`ngFor`指令，它遍历模型中包含的电影列表。然后，对于每部电影，它显示两个包含标题和发行年份的 p 元素。

现在，`EditMovie`组件访问`model.movies`数组中的一部电影，并允许用户对其进行编辑：

```ts
<form> 
   <input id="title" name="title" type="text" [(ngModel)]="movie.title" /> 
   <input id="year" name="year" type="text" [(ngModel)]="movie.year" /> 
</form> 
<a href="/back">Cancel</a> 

```

由于这里使用了双向数据绑定，对电影标题和年份的修改将直接影响仪表板。正如您所注意到的，我们这里有一个取消按钮。虽然用户可能期望修改是实时同步的，但他/她也期望取消按钮/链接取消对电影所做的修改。

这就是备忘录模式发挥作用的地方。这种模式允许您对对象执行撤消操作。它可以以许多种方式实现，但最简单的方式是使用克隆。使用克隆，我们可以在给定时刻存储对象的一个版本，并在需要时取回它。让我们根据`Prototype`模式来增强我们的`Movie`对象：

```ts
export class Movie implements Prototype { 
   private title:string; 
   private year:number; 
   //... 
       public constructor(); 
         public constructor(title?: string, year?: number); 

         public constructor(title?: string, year?: number) { 

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

在这个新版本中，我们添加了`restore(movie:Movie)`方法，它接受一个`Movie`作为参数，并将本地属性设置为接收到的电影的值。

然后，在实践中，我们的`EditMovie`组件的构造函数可能如下所示：

```ts
import { Component } from '@angular/core'; 
import { Movie } from './movie'; 
@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  title = 'app works!'; 

  private memento: Movie; 

  constructor(){ 
    this.memento = new Movie("Title", 2015); 
    let movieTmp = this.memento.clone(); 
    this.memento.setTitle("Another Title"); 
    //Prints Another title 
    console.log(this.memento.getTitle()); 
    this.memento.restore(movieTmp); 
    //Prints Title 
    console.log(this.memento.getTitle()); 
  } 
} 

```

有趣的是，您不限于一次性保存状态；您可以拥有尽可能多的状态。

# 摘要

在本章中，我们学习了如何使用一些经典的面向对象模式，这些模式适用于可重用和易于维护/扩展的现实世界应用程序。MVC 被调整为 Angular，并扩展以在不同应用程序之间实现高度可重用的业务逻辑。然后，我们看到如何使用单例模式以及依赖注入和原型模式与池相结合来控制对象的创建，以限制系统中昂贵对象的数量。最后，我们学习了如何使用工厂模式来避免在 JSON 到 TypeScript 自动（和部分）对象转换中的陷阱，并看到如何使用备忘录模式执行*撤消*操作。

如果你想学习更多关于模式来提高你的性能、操作成本和可维护性，你可以查看即将推出的 Packt Publishing 出版的《Angular 设计模式与最佳实践》一书。这本书深入探讨了模式及其实施，以找到最适合你的应用程序。
