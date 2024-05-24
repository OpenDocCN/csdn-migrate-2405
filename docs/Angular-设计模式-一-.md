# Angular 设计模式（一）

> 原文：[`zh.annas-archive.org/md5/7218DB9929A7962C59313A052F4806F8`](https://zh.annas-archive.org/md5/7218DB9929A7962C59313A052F4806F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Angular 是谷歌推出的用于构建 Web 应用程序的框架。与 AngularJS 相比，这是一个全新的产品。

AngularJS 以性能问题而闻名，并且并不一定很容易上手。只要你了解框架的具体细节和潜在瓶颈，一切都可能顺利进行。此外，AngularJS 通常被视为一个大工具箱，里面有很多工具，让你可以以多种不同的方式构建应用程序，最终导致同一逻辑的各种实现取决于开发人员。

Angular 在性能方面带来了巨大的改进，同时也是一个更简单、更直接的框架。Angular 简单地让你用更少的代码做更多的事情。

谷歌从 Angular 开发的开始就宣布，该框架将是一个全新的产品，不兼容 AngularJS，尽管他们可能会尝试提供一些工具来简化过渡。通常情况下，从头开始重写应用程序可能是迁移的最佳解决方案。在这种情况下，开发人员需要学习 Angular 框架的关键部分，以启动应用程序和开发它的最佳实践，以及调试和基准应用程序的现有工具。

通过对最有价值的设计模式进行全面的介绍，并清晰地指导如何在 Angular 中有效地使用它们，本书为你提供了学习 Angular 和将其用于满足当今 Web 开发所需的稳定性和质量的最佳途径之一。

我们将带领读者走进 Angular 在现实世界中的设计之旅，结合案例研究、设计模式和要遵循的反模式。

在本书结束时，你将了解 Angular 的各种特性，并能够在工作中应用广为人知的、经过行业验证的设计模式。

# 本书的受众

本书适用于希望增进对 Angular 的理解并将其应用于实际应用程序开发的新手 Angular 开发人员。

# 本书涵盖的内容

第一章《TypeScript 最佳实践》描述了 TypeScript 语言的一些最佳实践。虽然 Angular 与其他编程语言兼容，但在本书中我们使用 TypeScript。TypeScript 功能强大且表达力强，但也有一些需要避免的“坑”。

第二章，*Angular 引导*，允许我们使用最佳可用工具来创建、构建和部署我们的应用程序。

第三章，*经典模式*，在 Angular 的上下文中重新审视了一些众所周知的面向对象模式。

第四章，*导航模式*，侧重于不同的导航 Angular 应用程序的方式。

第五章，*稳定性模式*，介绍了可以用来确保实际 Angular 应用程序稳定性的不同稳定性模式。

第六章，*性能模式*，基于谷歌对 Angular 进行的巨大性能改进，并描述了适用于改进应用程序性能的模式。

第七章，*操作模式*，侧重于在使用众所周知的设计模式实现功能并使用一些性能和稳定性模式后，使我们的应用程序准备好进行操作。

# 为了充分利用本书

为了充分利用本书，读者需要了解 Angular、Typescript 和面向对象编程。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Angular-Design-Patterns`](https://github.com/PacktPublishing/Angular-Design-Patterns)。我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/AngularDesignPatterns_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/AngularDesignPatterns_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“`APIService`，显示了`@Injectable()`注释，使其可以注入。”

代码块设置如下：

```ts
interface Animal{ 
   eat():void; 
   sleep():void; 
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体设置：

```ts
 ReferenceError: window is not defined
```

任何命令行输入或输出都是这样写的：

```ts
$ curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
$ sudo apt-get install -y Node.js
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“`Model`根据控制器发送的命令存储应用程序所需的数据。”

警告或重要说明是这样出现的。提示和技巧是这样出现的。


# 第一章：TypeScript 最佳实践

我一直讨厌 JavaScript。当然我会用它，但只是在必要的时候。我清楚地记得我的第一次实习面试，那时我还是法国计算机工程学校 eXia.Cesi 的大一新生。我只知道 C 和一些 Java，被要求帮助一个主要使用自制 Ajax 库的内部网络。那纯粹是疯狂，有点让我暂时远离了计算机工程的 Web 方面。我对以下内容一无所知。

```ts
var r = new XMLHttpRequest();  
r.open("POST", "webservice", true); 
r.onreadystatechange = function () { 
   if (r.readyState != 4 || r.status != 200) return;  
   console.log(r.responseText); 
}; 
r.send("a=1&b=2&c=3"); 
```

一个本地的 Ajax 调用。多丑陋啊？

当然，使用 jQuery 模块和一些关注点分离，它是可以使用的，但仍然不像我想要的那样舒适。你可以在下面的截图中看到关注点是分离的，但并不那么容易：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/16cbc831-2677-40cc-bfaa-2d73c10587fa.png)使用 PHP5 和 Codeigniter 的已弃用的 toolwatch.io 版本

然后，我学习了一些 RoR（基于 Ruby 的面向对象的 Web 应用程序框架：[`rubyonrails.org/`](http://rubyonrails.org/)）和 Hack（Facebook 的一种带类型的 PHP：[`hacklang.org/`](http://hacklang.org/)）。这太棒了；我拥有了我一直想要的一切：类型安全、工具和性能。第一个，类型安全，相当容易理解：

```ts
<?hh 
class MyClass { 
  public function alpha(): int { 
    return 1; 
  } 

  public function beta(): string { 
    return 'hi test'; 
  } 
} 

function f(MyClass $my_inst): string { 
  // Fix me! return $my_inst->alpha(); 
} 
```

另外，有了类型，你可以拥有很棒的工具，比如强大的自动完成和建议：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/47a5355f-21db-45a0-9216-f98a21caba1e.png)Sublime Text 在 toolwatch.io 移动应用程序（Ionic2 *[5]* + Angular 2）上的自动完成

Angular 可以与 CoffeeScript、TypeScript 和 JavaScript 一起使用。在本书中，我们将专注于 TypeScript，这是 Google 推荐的语言。TypeScript 是 JavaScript 的一种带类型的超集；这意味着，使用 TypeScript，你可以做任何你以前在 JavaScript 中做的事情，还有更多！举几个优点：用户定义的类型、继承、接口和可见性。最好的部分是，TypeScript 被转译成 JavaScript，所以任何现代浏览器都可以运行它。

事实上，通过使用 polyfill，甚至我们那个老旧的 IE6 几乎可以执行最终的输出。我们将在下一章回到这个问题。转译与编译不同（例如，从 C 到可执行文件或从`.java`到`.class`），因为它只是将 TypeScript 转换成 JavaScript。

在本章中，我们将学习 TypeScript 的最佳实践。对于了解 JavaScript 和面向对象语言的任何人来说，TypeScript 语言的语法都非常容易掌握。如果您对面向对象编程一无所知，我建议您将这本书放在一边，花几分钟时间查看这个快速的 Udacity 课程：[`www.udacity.com/wiki/classes`](https://www.udacity.com/wiki/classes)。

总结一下涉及的主题：

+   TypeScript 语法

+   TypeScript 最佳实践

+   TypeScript 的缺点

# 环境设置

对于环境设置，我将涵盖所有三个主要平台：Debian 风格的 Linux，macOS 和 Windows。我们将要使用的所有工具都是跨平台的。因此，随意选择您最喜欢的那个；以后您将能够做任何事情。

接下来，我们将安装`Node.js`，`npm`和 TypeScript。

# Linux 的 Node.js 和 npm

```ts
$ curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
$ sudo apt-get install -y Node.js
```

这个命令会将一个脚本直接下载到您的`bash`中，它将获取您需要的每一个资源并安装它。在大多数情况下，它会正常工作并安装`Node.js` + `npm`。

现在，这个脚本有一个缺陷；如果您有不再可用的 Debian 存储库，它将失败。您可以利用这个机会清理您的 Debian 存储库，或者稍微编辑一下脚本。

```ts
$ curl https://deb.nodesource.com/setup_6.x > node.sh 
$ sudo chmod +x node.sh 
$ vim node.sh //Comment out all apt-get update 
//Save the file $ sudo apt-get update 
$ ./node.sh 
$ sudo apt-get update 
$ sudo apt-get install -y Node.js 
```

然后，前往[`Node.js.org/en/download/`](https://Node.js.org/en/download/)，下载并安装最新的`.pkg`或`.msi`（分别用于 Linux 或 Windows）。

# TypeScript

现在，您应该可以在终端中访问`node`和`npm`。您可以使用以下命令测试它们：

```ts
$ node -v 
V8.9.0 

$ npm -v 
5.5.1  
```

请注意，这些命令的输出（例如 v6.2.1 和 3.9.3）可能会有所不同，当您阅读这些内容时，您的环境中的 node 和 npm 的最新版本可能会有所不同。但是，如果您至少有这些版本，您将在本书的其余部分中表现良好：

```ts
    $ npm install -g TypeScript
```

`-g`参数代表全局。在 Linux 系统中，根据您的发行版，您可能需要`sudo`权限来安装全局包。

与 node 和 npm 非常相似，我们可以使用以下命令测试安装是否顺利进行：

```ts
    $ tsc -v
    Version 2.6.1

```

目前我们拥有的是 TypeScript 转译器。您可以这样使用：

```ts
    tsc --out myTranspiledFile.js myTypeScriptFile.ts

```

这个命令将转译`myTypeScriptFile.ts`的内容并创建`myTranspiledFile.js`。然后，您可以在控制台中使用 node 执行生成的`js`文件。

```ts
    node myTranspiledFile.js

```

为了加快我们的开发过程，我们将安装`ts-node`。这个 node 包将 TypeScript 文件转译成 JavaScript，并解决这些文件之间的依赖关系：

```ts
    $ npm install -g ts-node
    $ ts-node -v
    3.3.0
```

创建一个名为`hello.ts`的文件，并添加以下内容：

```ts
console.log('Hello World'); 
```

现在，我们可以使用我们的新包：

```ts
    $ ts-node hello.ts 
    Hello World

```

# 快速概述

在这一部分，我将简要介绍 TypeScript。这个介绍并不是详尽无遗的，因为我会在遇到特定概念时进行解释。但是，这里有一些基础知识。

TypeScript 是我提到的 JavaScript 的一个有类型的超集。虽然 TypeScript 是有类型的，但它只提供了四种基本类型供您直接使用。这四种类型分别是`String`、`number`、`Boolean`和`any`。这些类型可以使用`:`运算符，对变量或函数参数进行类型标记，比如`var name: string`，或者返回`add(a:number, b:number):number`类型的函数。此外，`void`可以用于函数，指定它们不返回任何内容。在面向对象的一面，string、number 和 boolean 是 any 的特例。`Any`可以用于任何类型。它是 Java 对象的 TypeScript 等价物。

如果您需要更多的类型，那么您将不得不自己创建！幸运的是，这非常简单。这是一个包含一个属性的用户类的声明：

```ts
class Person{
name:String;
}
```

您可以使用这里显示的简单命令创建一个新的`Person`实例：

```ts
var p:Person = new Person();
p.name = "Mathieu"
```

在这里，我创建了一个`p`变量，它在静态（例如左侧）和动态（例如右侧）方面都代表一个人。然后，我将`Mathieu`添加到`name`属性中。属性默认是公共的，但您可以使用`public`、`private`和`protected`关键字来定义它们的可见性。它们会像您在任何面向对象的编程语言中所期望的那样工作。

TypeScript 以非常简单的方式支持接口、继承和多态。这里有一个由两个类和一个接口组成的简单层次结构。接口`People`定义了将被任何`People`实现继承的字符串。然后，`Employee`实现了`People`并添加了两个属性：`manager`和`title`。最后，`Manager`类定义了一个`Employee`数组，如下面的代码块所示：

```ts
interface People{ 
   name:string; 
} 

class Employee implements People{ 
   manager:Manager; 
   title:string; 
} 

class Manager extends Employee{ 
   team:Employee[]; 
} 
```

函数可以被具有相同签名的函数覆盖，并且`super`关键字可以用来引用父类的实现，如下面的代码片段所示：

```ts
Interface People { 

   name: string; 
   presentSelf():void; 
} 

class Employee implements People { 

   name: string; 
   manager: Manager; 
   title: string; 

   presentSelf():void{ 

         console.log( 

               "I am", this.name,  
               ". My job is title and my boss is",  
               this.manager.name 

         ); 
   } 
} 

class Manager extends Employee { 

   team: Employee[]; 

   presentSelf(): void { 
         super.presentSelf(); 

         console.log("I also manage", this.team.toString()); 
   } 
} 
```

在我们继续讨论最佳实践之前，您需要了解有关 TypeScript 的最后一件事是`let`和`var`之间的区别。在 TypeScript 中，您可以使用这两个关键字来声明变量。

现在，TypeScript 中变量的特殊之处在于它允许您使用 var 和 let 关键字为变量选择函数作用域和块作用域。Var 将为您的变量提供函数作用域，而 let 将产生一个块作用域的变量。函数作用域意味着变量对整个函数可见和可访问。大多数编程语言都有变量的块作用域（如 C＃，Java 和 C ++）。一些语言也提供了与 TypeScript 相同的可能性，例如 Swift 2。更具体地说，以下代码段的输出将是`456`：

```ts
var foo = 123; 
if (true) { 
    var foo = 456; 
} 
console.log(foo); // 456
```

相反，如果您使用 let，输出将是`123`，因为第二个`foo`变量只存在于`if`块中：

```ts
let foo = 123; 
if (true) { 
    let foo = 456; 
} 
console.log(foo); // 123 
```

# 最佳实践

在本节中，我们将介绍 TypeScript 的最佳实践，包括编码约定、使用技巧、以及要避免的功能和陷阱。

# 命名

Angular 和 definitely typed 团队提倡的命名约定非常简单：

+   类：`CamelCase`。

+   接口：`CamelCase`。此外，您应该尽量避免在接口名称前加大写 I。

+   变量：`lowerCamelCase`。私有变量可以在前面加上`_`。

+   函数：`lowerCamelCase`。此外，如果一个方法不返回任何内容，您应该指定该方法返回`void`以提高可读性。

# 接口重新定义

TypeScript 允许程序员多次使用相同的名称重新定义接口。然后，所述接口的任何实现都继承了所有接口的定义。官方原因是允许用户增强 JavaScript 接口，而无需在整个代码中更改对象的类型。虽然我理解这种功能的意图，但我预见到在使用过程中会遇到太多麻烦。让我们来看一个微软网站上的示例功能：

```ts
interface ICustomerMerge 
{ 
   MiddleName: string; 
} 
interface ICustomerMerge 
{ 
   Id: number; 
} 
class CustomerMerge implements ICustomerMerge 
{ 
   id: number; 
   MiddleName: string; 
} 
```

撇开命名约定不被遵守的事实，我们得到了`ICustomerMerge`接口的两个不同的定义。第一个定义了一个字符串，第二个定义了一个数字。自动地，`CustomerMerge`有这些成员。现在，想象一下你有十二个文件依赖，你实现了一个接口，你不明白为什么你必须实现这样那样的函数。嗯，某个地方的某个人决定重新定义一个接口并一下子破坏了你所有的代码。

# 获取器和设置器

在 TypeScript 中，您可以使用`?`运算符指定可选参数。虽然这个特性很好，我将在接下来的章节中不加节制地使用它，但它也会带来以下的丑陋：

```ts
class User{ 
   private name:string; 
   public  getSetName(name?:string):any{ 
         if(name !== undefined){ 
               this.name = name; 
         }else{ 
               return this.name 
         } 
   } 
} 
```

在这里，我们测试可选的名称参数是否通过`!== undefined`传递。如果`getSetName`函数接收到了某些东西，它将作为 setter，否则作为 getter。函数在作为 setter 时不返回任何内容是被允许的。

为了清晰和可读性，坚持受 ActionScript 启发的 getter 和 setter：

```ts
class User{
private name:_string = "Mathieu";
get name():String{
return this._name;
}
set name(name:String){
this._name = name;
}
}
```

然后，您可以这样使用它们：

```ts
var user:User = new User():
if(user.name === "Mathieu") { //getter
 user.name = "Paul" //setter
}
```

# 构造函数

TypeScript 构造函数提供了一个非常不寻常但节省时间的特性。事实上，它们允许我们直接声明一个类成员。因此，不需要这么冗长的代码：

```ts
class User{ 

   id:number; 
   email:string; 
   name:string; 
   lastname:string; 
   country:string; 
   registerDate:string; 
   key:string; 

   constructor(id: number,email: string,name: string, 
         lastname: string,country: string,registerDate:  
         string,key: string){ 

         this.id = id; 
         this.email = email; 
         this.name = name; 
         this.lastname = lastname; 
         this.country = country; 
         this.registerDate = registerDate; 
         this.key = key; 
   } 
} 
```

你可以有：

```ts
class User{ 
   constructor(private id: number,private email: string,private name: string, 

         private lastname: string,private country: string, private            registerDate: string,private key: string){} 
} 
```

前面的代码实现了相同的功能，并且将被转译为相同的 JavaScript。唯一的区别是它以一种不会降低代码清晰度或可读性的方式节省了您的时间。

# 类型保护

在 TypeScript 中，类型保护为给定值定义了一系列类型。如果您的变量可以被赋予一个特定的值或一组特定的值，那么考虑使用类型保护而不是枚举器。它将实现相同的功能，同时更加简洁。这里有一个关于`People`人的虚构例子，他有一个性别属性，只能是`MALE`或`FEMALE`：

```ts
class People{
gender: "male" | "female";
}
```

现在，考虑以下内容：

```ts
class People{
gender:Gender;
}
enum Gender{
MALE, FEMALE
}
```

# 枚举器

与类型保护相反，如果您的类有一个变量可以从有限的值列表中同时取多个值，那么考虑使用基于位的枚举器。这里有一个来自[`basarat.gitbooks.io/`](https://basarat.gitbooks.io/)的绝佳例子：

```ts
class Animal{ 
   flags:AnimalFlags = AnimalFlags.None 
} 

enum AnimalFlags { 
    None           = 0, 
    HasClaws       = 1 << 0, 
    CanFly         = 1 << 1, 
} 

function printAnimalAbilities(animal) { 
    var animalFlags = animal.flags; 
    if (animalFlags & AnimalFlags.HasClaws) { 
        console.log('animal has claws'); 
    } 
    if (animalFlags & AnimalFlags.CanFly) { 
        console.log('animal can fly'); 
    } 
    if (animalFlags == AnimalFlags.None) { 
        console.log('nothing'); 
    } 
} 

var animal = { flags: AnimalFlags.None }; 
printAnimalAbilities(animal); // nothing 
animal.flags |= AnimalFlags.HasClaws; 
printAnimalAbilities(animal); // animal has claws 
animal.flags &= ~AnimalFlags.HasClaws; 
printAnimalAbilities(animal); // nothing 
animal.flags |= AnimalFlags.HasClaws | AnimalFlags.CanFly; 
printAnimalAbilities(animal); // animal has claws, animal can fly 
```

我们使用`<<`移位运算符在`AnimalFlags`中定义了不同的值，然后使用`|=`来组合标志，使用`&=`和`~`来移除标志，使用`|`来组合标志。

# 陷阱

在本节中，我们将讨论我在编写 Angular 2 应用程序时遇到的两个 TypeScript 陷阱。

# 类型转换和 JSON

如果您计划构建不仅仅是一个 Angular 2 的游乐场，显然您会对性能、稳定性和操作的模式感兴趣，那么您很可能会使用 API 来为您的应用程序提供数据。很可能，这个 API 将使用 JSON 与您通信。

假设我们有一个`User`类，有两个私有变量：`lastName:string`和`firstName:string`。此外，这个简单的类提供了`hello`方法，打印出`Hi I am`，`this.firstName`，`this.lastName`：

```ts
class User{
 constructor(private lastName:string,         private firstName:string){
 }

 hello(){
 console.log("Hi I am", this.firstName,         this.lastName);
 }
}
```

现在，考虑到我们通过 JSON API 接收用户。很可能，它看起来像*`[{"lastName":"Nayrolles","firstName":"Mathieu"}...]`*。通过以下代码片段，我们可以创建一个`User`：

```ts
let userFromJSONAPI: User = JSON.parse('[*{"lastName":"Nayrolles","firstName":"Mathieu"}]'*)[0];
```

到目前为止，TypeScript 编译器没有抱怨，并且执行顺利。这是因为`parse`方法返回`any`（即 Java 对象的 TypeScript 等价物）。毫无疑问，我们可以将`any`转换为`User`。然而，接下来的`userFromJSONAPI.hello();`将产生：

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

为什么？嗯，赋值的左侧被定义为`User`，当我们将其转译为 JavaScript 时，它将被*擦除*。进行类型安全的 TypeScript 方式是：

```ts
let validUser = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]') 
.map((json: any):User => { 
return new User(json.lastName, json.firstName); 
})[0]; 
```

有趣的是，`typeof`函数也无法帮助您。在这两种情况下，它都会显示`Object`而不是`User`，因为`User`的概念在 JavaScript 中根本不存在。

当参数列表变得越来越多时，这种类型的 fetch/map/new 可能会变得非常乏味。您可以使用工厂模式，我们将在第三章中看到，*经典模式*，或者创建一个实例加载器，比如：

```ts
class InstanceLoader { 
    static getInstance<T>(context: Object, name: string, rawJson:any): T { 
        var instance:T = Object.create(context[name].prototype); 
        for(var attr in instance){ 
         instance[attr] = rawJson[attr]; 
         console.log(attr); 
        } 
        return <T>instance; 
    } 
} 
InstanceLoader.getInstance<User>(this, 'User', JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')[0]) 
```

`InstanceLoader`只能在 HTML 页面内使用，因为它依赖于`window`变量。如果您尝试使用`ts-node`执行它，您将收到以下错误：

```ts
    ReferenceError: window is not defined
```

# 继承和多态

假设我们有一个简单的继承层次结构如下。我们有一个定义了`eat():void`和`sleep(): void`方法的接口`Animal`：

```ts
interface Animal{ eat():void; sleep():void; }
```

然后，我们有一个实现了`Animal`接口的`Mammal`类。这个类还添加了一个构造函数，并利用了我们之前看到的私有`name: type`符号。对于`eat():void`和`sleep(): void`方法，这个类打印出`"Like a mammal"`：

```ts
class Mammal implements Animal{ 

   constructor(private name:string){ 
         console.log(this.name, "is alive"); 
   } 

   eat(){ 
         console.log("Like a mammal"); 
   } 

   sleep(){ 
         console.log("Like a mammal"); 
   } 
} 
```

我们还有一个`Dog`类，它扩展了`Mammal`并重写了`eat(): void`，所以它打印出`"Like a Dog"`：

```ts
class Dog extends Mammal{ 
   eat(){ 
         console.log("Like a dog") 
   } 
} 
```

最后，我们有一个期望`Animal`作为参数并调用`eat()`方法的函数。

```ts
let mammal: Mammal = new Mammal("Mammal"); 
let dolly: Dog = new Dog("Dolly"); 
let prisca: Mammal = new Dog("Prisca");  
let abobination: Dog = new Mammal("abomination"); //-> Wait. WHAT ?! function makeThemEat (animal:Animal):void{ 
   animal.eat(); 
}
```

输出如下：

```ts
    ts-node class-inheritance-polymorhism.ts

    Mammal is alive 
    Dolly is alive
 Prisca is alive
 abomination is alive
 Like a mammal
 Like a dog
 Like a dog
 Like a mammal
```

现在，我们的最后一个创建，`let abomination: Dog = new Mammal("abomination");` 应该不可能，根据面向对象的原则。事实上，赋值语句的左侧比右侧更具体，这是 TypeScript 编译器不应该允许的。如果我们查看生成的 JavaScript，我们可以看到发生了什么。类型消失了，被函数替换。然后，变量的类型在创建时被推断：

```ts
var __extends = (this && this.__extends) || function (d, b) { 
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; 
    function __() { this.constructor = d; } 
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __()); 
}; 
var Mammal = (function () { 
    function Mammal() { 
    } 
    Mammal.prototype.eat = function () { 
        console.log("Like a mammal"); 
    }; 
    Mammal.prototype.sleep = function () { 
        console.log("Like a mammal"); 
    }; 
    return Mammal; 
}()); 
var Dog = (function (_super) { 
    __extends(Dog, _super); 
    function Dog() { 
        _super.apply(this, arguments); 
    } 
    Dog.prototype.eat = function () { 
        console.log("Like a dog"); 
    }; 
    return Dog; 
}(Mammal)); 
function makeThemEat(animal) { 
    animal.eat(); 
} 
var mammal = new Mammal(); 
var dog = new Dog(); 
var labrador = new Mammal(); 
makeThemEat(mammal); 
makeThemEat(dog); 
makeThemEat(labrador); 
```

当有疑问时，查看转译后的 JavaScript 总是一个好主意。您将看到执行时发生了什么，也许会发现其他陷阱！另外，TypeScript 转译器在这里被愚弄了，因为从 JavaScript 的角度来看，`Mammal`和`Dog`并没有不同；它们具有相同的属性和函数。如果我们在`Dog`类中添加一个属性（比如`private race:string`），它将不再转译。这意味着覆盖方法并不足以被识别为类型；它们必须在语义上有所不同。

这个例子有点牵强，我同意这种 TypeScript 的特殊性不会每天都困扰你。然而，如果我们在使用一些有严格层次结构的有界泛型，那么你就必须了解这一点。事实上，以下例子不幸地有效：

```ts
function makeThemEat<T extends Dog>(dog:T):void{ 
   dog.eat(); 
} 

makeThemEat<Mammal>(abomination); 
```

# 总结

在这一章中，我们完成了 TypeScript 的设置，并审查了大部分的最佳实践，包括代码规范、我们应该和不应该使用的功能，以及需要避免的常见陷阱。

在下一章中，我们将专注于 Angular 以及如何使用全新的 Angular CLI 入门。


# 第二章：Angular 引导

在第一章之后，*Typescript 最佳实践*，我们可以深入了解 Angular 本身。Angular 的一个重点是大幅提高 Angular 应用程序的性能和加载时间，与 AngularJS 相比。性能改进是非常显著的。根据 Angular 团队和各种基准测试，Angular 2 比 Angular 1 快 5 到 8 倍。

为了实现这种改进，谷歌工程师并没有在 AngularJS 的基础上进行开发；相反，他们从头开始创建了 Angular。因此，如果你已经使用 Angular 1 一段时间，这并不会在开发 Angular 应用程序时给你带来很大的优势。

在这一章中，我们将做以下事情：

+   我将首先介绍 Angular 背后的主要架构概念。

+   然后，我们将使用新引入的 Angular CLI 工具引导一个 Angular 应用程序，这将消除大部分入门的痛苦。网上有数百种 Angular 样板，选择一个可能会耗费大量时间。你可以在 GitHub 上找到各种风格的样板，带有测试、带有库、用于移动设备、带有构建和部署脚本等等。

尽管社区的多样性和热情是一件好事，但这意味着没有两个 Angular 项目看起来一样。事实上，这两个项目很可能是用不同的样板创建的，或者根本没有使用样板。为了解决这个问题，Angular 团队现在提出了 angular CLI。Angular CLI 是一个命令行 node 包，允许开发人员基于官方样板创建新的应用程序。这个工具还提供了一些有用的功能，比如创建 Angular 应用程序的不同构建模块，构建、测试和压缩你的应用程序。它甚至支持用一个简短的命令将你的应用程序部署到 GitHub 页面上。

这仍然是一个新工具，它有许多缺点和未完善的行为。

# 架构概述

在这一部分，我将介绍 Angular 应用程序的主要构建模块：服务、组件、模板和指令。我们还将学习依赖注入、装饰器和区域解决了哪些问题。

现在，如果你从（虚拟）书架上拿起这本书，你很可能有一些关于 Angular 的经验，并希望通过良好的实践和设计模式来改进你的应用程序。因此，你应该对 Angular 构建块的一般架构有一些了解。

然而，一个快速而务实的提醒不会有太大的伤害，我们可以确信我们有一个坚实的架构基础来构建我们的模式。

以下是主要的 Angular 2 构建块如何相互交互的概述：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/dbbe6f43-adec-4ebb-a6cf-590c1c876429.png)Angular 2 应用程序的高级架构

接下来，我将通过创建一个操作 Floyd 数组的应用程序来介绍每个 Angular 2 构建块的示例。以下是一个基于字母的 Floyd 数组的示例：

```ts
 a 
 b c 
 d e f 
 g h i j 

```

我同意你不太可能在不久的将来构建处理 Floyd 数组的应用程序。然而，当学习新语言或框架时，Floyd 数组是一个很好的编程练习，因为它涉及用户输入、显示结果、循环和字符串操作。

# 组件

组件是我们 Angular 应用程序的视图，它们控制屏幕上的内容、时间和方式。它们采用一个简单的类的形式，定义了视图所需的逻辑。以下是一个简单组件的示例：

```ts
export class FloydComponent implements OnInit { 

 private floydString:string = ""; 
 private static startOfAlphabet = 97; 

 constructor() { } 

 ngOnInit() { 
 } 

 onClick(rows:number){ 

 let currentLetter = FloydComponent.startOfAlphabet; 
 for (let i = 0; i < rows; i++) { 
 for (let j = 0; j < i; j++) { 
 this.floydString += String.fromCharCode(currentLetter) + " "; 
 currentLetter++; 
 } 
 this.floydString += "\n\r"; 
 } 
 } 
}
```

请注意，组件类有一个后缀：`Component`。我将在下一章讨论原因。

这个名为`FloydComponent`的组件有两个私有成员：`floydString`和`startOfAlphabet`。`floydString`将包含表示第 n 个 Floyd 三角形的字符串，而`startOfAlphabet`则不断标记 ASCII 表中字母的位置。

`FloydComponent`还定义了一个构造函数，当用户请求我们组件管理的屏幕补丁时将被调用。目前，构造函数是空的。

最后，接受一个名为`rows`的数字参数的`onClick`方法将生成一个由`rows`行组成的 Floyd 三角形。总之，我们有一个管理展示 Floyd 三角形行为的视图的类。是的？嗯，视图部分有点缺失！我的用于客户端渲染的 HTML 在哪里？

在 Angular 中，我们的组件将控制的 HTML 部分被称为模板，我们可以使用元数据将模板链接到组件上：

```ts
import { Component } from '@angular/core'; 
@Component({ 
 selector: 'floyd', 
 template: 
 `<p> 
 <input #checkbox type="checkbox" value="even">Even?<br> 
 <input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 
 </p> 
 <pre> 

 {{floydString}} 
 </pre> 
 ` 
}) 
export class FloydComponent { 
```

那么，这一切到底是怎么回事？如果我们回顾一下`FloydComponent`的原始定义，没有任何地方指定`FloydComponent`是一个组件。我们没有像`FloydComponent`扩展/实现组件的任何东西，所以它只是一个普通的 typescript 类，什么都不是。更令人惊讶的是，根本没有 Angular 的引用；这个`FloydComponent`完全可以是 Angular 框架之外的一个 typescript 类。

元数据使用装饰器模式装饰`FloydComponent`类，因此 Angular 知道如何解释和处理`FloydComponent`类。

在任何面向对象的语言中，通过继承静态地扩展对象的责任是很容易的，但是在运行时动态地这样做是完全不同的。装饰器模式的目的是在对象上动态地添加额外的责任。

我们将在《第三章》《经典模式》中实现我们自己的装饰器。

注解本身是`@Component`，并使用一些参数使我们的类成为 Angular 组件。

注意`import { Component } from '@angular/core';`导入了`@angular/core`库中的`Component`模块。

第一个参数是一个`selector`，描述了我们的`FloydComponent`应该绑定到视图的哪个部分。在下面的 HTML 片段中，我们有`<floyd></floyd>`选择器标记，`FloydComponent`将绑定到它。第二个参数是模板字符串。模板字符串定义了在运行时将添加到 DOM 中的内容，位于`<floyd>`标记内部：

```ts
 <p> 
 <input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value)">CLICK</button> 
 </p> 
 <pre> 
 {{floydString}} 
 </pre>
```

反引号`允许我们在 JavaScript 中定义多行字符串。

首先，我们有`<input>`标记，看起来几乎像纯 HTML。唯一的特殊之处在于标记中的`#rows`属性。这个属性用于将标记引用为名为`rows`的变量。因此，我们可以在下面的标记中访问它的值：`<button (click)="onClick(rows.value)">CLICK</button>`。在这里，我们在模板和组件之间进行了事件绑定。当按钮被点击时，组件的`onClick`方法将被调用，并且输入的值将被传递给该方法。

在代码的下方，我们有`{{floydString}}`，这是从组件到模板的属性绑定。在这种情况下，我们将`floydString`组件属性绑定到模板上。换句话说，我们在 DOM 中显示`floydString`组件属性的内容。

我必须使用预先标记，以便`\n\r`在输出中得到保留。

总之，组件将其属性绑定到模板，而模板将其事件绑定到组件。运行此应用程序时可以期待以下截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/8f8cd7fc-91c8-4425-9003-c9d1123708e6.png)Angular 2 中的 Floyd 数组在你这边不起作用吗？想要在 GitHub 上 fork 这段代码吗？你现在可以在[`bit.ly/angular2-patterns-chap2`](http://bit.ly/angular2-patterns-chap2)看到整个应用程序。

# 服务

到目前为止，我们已经审查了 Angular 2 的四个构建块中的两个。剩下的两个是服务和指令。接下来我们将审查服务。服务是具有独特目的的类，它们应尽可能地具有内聚性，以便为应用程序的其他部分提供狭窄而明确定义的服务。从设计的角度来看，对于我们的 Floyd 三角形应用程序来说，将`FloydComponent.onClick`方法的内容放在一个服务中可能会更好。实际上，`floydString`字符串的计算不应该出现在管理视图的组件中。

组件应该只负责用户体验——将属性绑定到模板——其他所有事情都应该委托给服务。我们可以创建一个三角形服务，负责*鼓掌*创建像 Floyd 三角形这样的奇怪三角形。我们还可以让这个服务负责生成 Floyd 三角形，输出看起来像一棵树：

```ts
 a 
 b c 
 d e f 
 g h i j 

```

而不是：

```ts
 a 
 b c 
 d e f 
 g h i j 
```

这样的服务看起来会像下面这样：

```ts
import { Injectable } from '@angular/core'; 

@Injectable() 
export class TriangleService { 

 private static startOfAlphabet = 97; 

 constructor() {} 

 /** 
 * Computes a Floyd Triangle of letter.
 * Here's an example for rows = 5 
 * 
 * a 
 * b c 
 * d e f 
 * g h i j 
 * 
 * Adapted from http://www.programmingsimplified.com/c-program-print-floyd-triangle 
 * 
 * @param  {number} rows 
 * @return {string}
 */ 
 public floydTriangle(rows:number):string{ 

 let currentLetter = TriangleService.startOfAlphabet; 
 let resultString = ""; 

 for (let i = 0; i < rows; i++) { 
 for (let j = 0; j < i; j++) { 
 resultString += String.fromCharCode(currentLetter) + " "; 
 currentLetter++; 
 } 
 resultString += "\n\r"; 
 } 

 return resultString; 
 } 

 /** 
 * Computes a Even Floyd Triangle of letter. 
 * Here's an example for rows = 7 
 *       a 
 *      b c 
 *     d e f 
 *    g h i j 
 *   k l m n o 
 *  p q r s t u 
 * v w x y z { | 
 * 
 * @param  {number} rows 
 * @return {string} 
 */ 
 public evenFloydTriangle(rows:number):string{ 

 let currentLetter = TriangleService.startOfAlphabet; 
 let resultString = ""; 

 for (let i = 0; i < rows; i++) { 

 for (let j = 0; j <= (rows-i-2); j++) { 
 resultString += " "; 
 } 

 for (let j = 0; j <= i; j++) { 
 resultString += String.fromCharCode(currentLetter) + " "; 
 currentLetter++; 
 } 

 resultString+="\n\r"; 
 } 

 return resultString; 
 } 
 } 

```

`TriangleService`是一个简单的类，提供两种方法：`floydTriangle`和`evenFloydTriangle`。`evenFloydTriangle`有一个额外的 for 循环，用于在三角形的不同行添加前导空格。业务应用现在位于一个专用的服务上，我们可以在`FloydComponent`上使用它。在`FloydComponent`中使用我们的服务的正确方法是通过依赖注入。依赖注入是一个过程，通过该过程，请求类会动态地获得所请求类的一个完整形式的实例。将这个相当技术性的定义应用到我们的上下文中，`FloydComponent`在实例化时将获得`TriangleService`的一个实例。

要在 Angular 中使用依赖注入，我们需要为`TriangleService`定义一个提供者。我们可以在应用程序级别这样做：

```ts
import { TriangleService } from './app/triangle.service' 

bootstrap(FloydComponent, [TriangleService]); 
```

或者，我们可以在组件注解中定义提供者，以在组件级别进行此操作：

```ts
import { Component, OnInit, ViewEncapsulation } from '@angular/core'; 
import { TriangleService } from '../triangle.service' 

@Component({ 
 selector: 'floyd', 
 template:   `<p> 
 <input #checkbox type="checkbox" value="even">Even?<br> 
 <input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 
 </p> 
 <pre> 

 {{floydString}} 
 </pre> 
 `, 
 styleUrls: ['./floyd.component.css'], 
 providers: [TriangleService], 
 encapsulation: ViewEncapsulation.None 
}) 
export class FloydComponent implements OnInit { 
```

如果在应用程序级别创建提供者，那么`TriangleService`的相同实例将提供给任何请求它的人。然而，在组件级别，每次实例化该组件时都会创建一个新的`TriangleService`实例并提供给该组件。这两种情况都是有道理的。这取决于你的组件和你的服务在做什么。例如，我们将在第七章中实现的日志服务没有自己的状态，并且被应用程序的每个模块使用。因此，我们可以使用基于应用程序的提供者。反例是来自第五章的*Circuit breaker*模式，*稳定性模式*，它具有内部状态，因此是组件级别的。

最后一步是修改我们的`FloydComponent`构造函数，使其看起来像这样：

```ts
 constructor(private triangleService:TriangleService) { 
 }
```

在这里，我们为我们的`FloydComponent`定义了一个名为`triangleService`的私有成员，它将被用作注入的依赖项的占位符。

此外，我们在模板中添加一个复选框，用于确定我们是要一个偶数还是一个普通的 Floyd 数组：

```ts
<input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 
```

我们还可以修改`onClick`方法以使用我们的`TriangleService`。最终组件看起来像这样：

```ts

import { Component, OnInit, ViewEncapsulation } from '@angular/core'; 
import { TriangleService } from '../triangle.service' 

@Component({ 
 selector: 'floyd', 
 template:   `<p> 
 <input #checkbox type="checkbox" value="even">Even?<br> 
 <input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 
 </p> 
 <pre> 
 {{floydString}} 
 </pre> 
 `, 
 styleUrls: ['./floyd.component.css'], 
 providers: [TriangleService], 
 encapsulation: ViewEncapsulation.None 
}) 
export class FloydComponent implements OnInit { 

 private floydString:string = ""; 
 private static startOfAlphabet = 97; 

 constructor(private triangleService:TriangleService) { } 

 ngOnInit() { 
 } 

 onClick(rows:number, checked:boolean){ 

 if(checked){ 
 this.floydString = this.triangleService.evenFloydTriangle(rows); 
 }else{ 
 this.floydString = this.triangleService.floydTriangle(rows); 
 } 
 } 
} 

```

应用程序的当前状态可以在这里看到：[`bit.ly/angular2-patterns-chap2-part2`](http://bit.ly/angular2-patterns-chap2-part2)。

# 指令

结束我们快速的架构概述，我们将创建一个指令来增强我们相当单调的预标记。指令与模板以及它们的父组件进行属性和事件绑定交互。我们将创建一个指令，为我们的预标记添加样式。样式包括 1 像素边框，并将背景颜色更改为红色或黄色，分别用于偶数或奇数的 Floyd 数组。

首先，我们需要一种方法来询问用户希望使用哪种类型的数组。让我们在`FloydComponent`的模板中添加另一个输入，并修改`onClick`方法，使其接受第二个参数：

```ts
import { Component } from '@angular/core'; 
import { TriangleService } from '../triangle.service'; 
@Component({ 
 selector: 'floyd', 
 template: 
 `<p> 
 <input #checkbox type="checkbox" value="even">Even?<br> 
 <input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 
 </p> 
 <pre> 

 {{floydString}} 
 </pre> 
 `, 
 providers:   [TriangleService] 
}) 
export class FloydComponent { 

 private floydString:string = ""; 
 private color:"yellow" | "red"; 

 constructor(private triangleService:TriangleService) { 

 } 

 onClick(rows:number, even:boolean){ 

 if(even){ 
 this.floydString = this.triangleService.evenFloydTriangle(rows); 
 }else{ 
 this.floydString = this.triangleService.floydTriangle(rows); 
 } 

 } 

} 
```

然后，我们可以创建指令。它将如下所示：

```ts
import { Directive, Input, ElementRef, HostListener } from '@angular/core'; 

@Directive({ 
 selector: '[AngularPre]' 
}) 
export class AngularPre { 

 @Input() 
 highlightColor:string; 

 constructor(private el: ElementRef) { 
 el.nativeElement.style.border = "1px solid black"; 
 el.nativeElement.style.backgroundColor = this.highlightColor; 
 } 

 @HostListener('mouseenter') onMouseEnter() { 
 this.highlight(this.highlightColor); 
 } 

 @HostListener('mouseleave') onMouseLeave() { 
 this.highlight(null); 
 } 

 private highlight(color: string) { 
 this.el.nativeElement.style.backgroundColor = color; 
 } 

}
```

这里发生了很多事情。首先，我们有带有选择器的指令注释。选择器将用于表示给定的 HTML 标记取决于指令。在我们的例子中，我选择将指令命名为`AngularPre`，并为选择器使用相同的名称。它们可以不同；这取决于你。但是，选择器和类具有相同的名称是有意义的，这样你就知道当你的指令出现问题时应该打开哪个文件。

然后，我们有非常有趣的`@Input()`注释`highlightColor:string;`成员。在这里，我们指定`highlightColor`字符串的值实际上绑定到父组件的变量。换句话说，父组件将不得不指定它希望预标记突出显示的颜色。在构造函数中，指令通过注入接收了一个`ElementRef`对象。这个`ElementRef`代表了您的指令作用的 DOM。最后，我们在`mouseenter`和`mouseleave`上定义了两个`HostListener`，它们将分别开始和停止预标记的突出显示。

要使用这个指令，我们必须在`FloydComponent`模板的预标记中插入其选择器，如下所示：

```ts
<pre AngularPre [highlightColor]="color"> 
 {{floydString}} 
</pre> 
```

在这里，我们指定我们希望我们的预标记受到`AngularPre`选择器的影响，并将调用指令的`highlightColor`变量与`FloydComponent`的颜色变量绑定。这是带有颜色变量和`onClick`方法的`FloydComponent`，所以它改变颜色变量的值：

```ts
export class FloydComponent { 

 private floydString:string = ""; 
 private color:"yellow" | "red"; 

 constructor(private triangleService:TriangleService) { 

 } 

 onClick(rows:number, even:boolean){ 

 if(even){ 
 this.floydString = this.triangleService.evenFloydTriangle(rows); 
 this.color = "red"; 
 }else{ 
 this.floydString = this.triangleService.floydTriangle(rows); 
 this.color = "yellow"; 
 } 

 } 

} 
onClick modifies the color variable 
```

这是应用程序使用奇数数组的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/0cde42b3-4ba2-43e8-a027-5569c720fc65.png)奇数 Floyd 数组结果

这是偶数数组的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/ad758f35-adca-4c72-80ce-70c536f880c6.png)甚至弗洛伊德数组结果该应用程序可在此处下载：[`bit.ly/angular2-patterns-chap2-part3`](http://bit.ly/angular2-patterns-chap2-part3)。

# 管道

我想在这里解释的最后两个构建块是管道和路由。管道很棒。它们允许我们创建一个专门的类，将任何输入转换为所需的输出。在 Angular 中，管道遵循 Unix 管道编程范式，其中信息可以从一个进程传递到另一个进程。我们可以在基于弗洛伊德三角形的应用程序中创建一个管道，该管道将在每次遇到换行序列（如`\n\r`）时将任何给定的弗洛伊德字符串转换为包含段落`¶`（`244，&para;`）的 ASCII 字符：

```ts
import { Pipe, PipeTransform } from '@angular/core'; 

@Pipe({ 
 name: 'paragraph' 
}) 
export class ParagraphPipe implements PipeTransform { 

 transform(value: string): string { 

 return value.replace( 
 new RegExp("\n\r", 'g'), 
 "¶ \n\r" 
 ); 
 } 

} 
```

管道使用`@Pipe`注解进行装饰，非常类似于组件和指令。现在，与管道相比，与组件和指令相比的区别在于，除了装饰注解之外，我们还必须实现 Angular 框架提供的一个接口。这个接口被命名为`PipeTransform`，并定义了每个实现它的类必须具有的单个方法：

```ts
transform(value: any, args?:any): any 
```

该方法的实际签名由任何类型组成，因为管道可以用于一切，不仅仅是字符串。在我们的情况下，我们想要操作一个字符串输入并获得一个字符串输出。我们可以在不违反接口合同的情况下，细化`transform`方法的签名，如下所示：

```ts
transform(value: string): string 
```

在这里，我们只期望一个字符串参数并产生一个字符串输出。该方法的主体包含一个全局正则表达式，匹配所有的`\n\r`序列并添加`¶`。

要在`FloydComponent`中使用`ParagraphPipe`，我们必须修改模板如下：

```ts
 `<p> 

 <input #checkbox type="checkbox" value="even">Even?<br> 

 <input #rows type="text" name="rows"> 

 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 

 </p> 

 <pre AngularPre [highlightColor]="color"> 

 {{floydString | paragraph}} 

 </pre> 
```

`floydString`通过`|`运算符传递给`ParagraphPipe`。这是它的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-dsn-ptn/img/b4b0a918-007d-4c73-a98f-f0821f5042cc.png)将 floydString 管道化以获得段落标记

段落管道硬编码段落符号让我有点烦。如果我想要根据每次使用来更改它怎么办？嗯，Angular 正在处理许多额外的管道参数。我们可以修改`transform`方法如下：

```ts
 transform(value: string, paragrapheSymbol:string): string { 

 return value.replace( 

 new RegExp("\n\r", 'g'), 

 paragrapheSymbol + "\n\r" 

 ); 

 } 

```

此外，我们可以这样调用管道：

```ts
{{floydString | paragraph: "¶"}} 

```

在这里，`transform`方法的第一个参数将是`floydString`，而第二个参数将是段落符号。

如果我们考虑一下，我们目前正在为 Typescript 实现`replaceAll`函数，除了目标（`\n\r`是硬编码的）。让我们创建一个名为`replaceAll`的管道，它将目标替换和替换作为参数。唯一的问题是`PipeTransform`接口定义了一个带有两个参数的 transform 方法，第二个参数是可选的。在这里，我们需要三个参数：要转换的字符串，要在字符串中替换的目标，以及目标的替换。如果你尝试使用三个参数来定义一个 transform 方法，那么你将违反`PipeTransform`的约定，你的 Typescript 将不再编译。为了克服这个小问题，我们可以定义一个名为`replace`的内联类型，它将包含两个成员，`from`和`to`，它们都是字符串：

```ts
transform(value: string, replace: {from:string, to:string}): string 
To call it inside the FloydComponent we can do the following: 

{{floydString | replaceAll: {from:'\\n\\r', to:'¶ \\n\\r'} }}
```

在这里，我们使用`\\n\\r`作为字符串模式，因为我们还没有构建`RegExp`。因此，`\`需要转义`\n`和`\r`。

这是`replaceAll`管道的代码：

```ts
import { Pipe, PipeTransform } from '@angular/core'; 

@Pipe({ 
 name: 'replaceAll' 
}) 
export class ReplaceAllPipe implements PipeTransform { 

 transform(value: string, replace: {from:string, to:string}): string { 

 return value.replace( 
 new RegExp(replace.from, 'g'), 
 replace.to 
 ); 

 } 

} 
```

不错，对吧？我们已经填补了 JavaScript 的一个缺点，即`replaceAll`功能，以一种模块化和高效的方式。这个`replaceAll`管道将在你的应用程序中随处可用：

```ts
@Component({ 
 selector: 'floyd', 
 template:   `<p> 
 <input #checkbox type="checkbox" value="even">Even?<br> 
 <input #rows type="text" name="rows"> 
 <button (click)="onClick(rows.value, checkbox.checked)">CLICK</button> 
 </p> 
 <pre AngularPre [highlightColor]="color"> 
 {{floydString | replaceAll: {from:'\\n\\r', to:'¶ \\n\\r'} }} 
 </pre> 
 `, 
 styleUrls: ['./floyd.component.css'], 
 providers: [TriangleService], 
 encapsulation: ViewEncapsulation.None 
}) 
export class FloydComponent implements OnInit {
```

关于管道的最后一件事是，你可以像在 Unix 控制台中一样组合它们。例如，我们完全可以做以下事情，其中段落管道首先添加`¶`到所有行的末尾。然后，`replaceAll`管道介入并替换所有的`¶`为`¶`管道：

```ts
{{floydString | paragraph:'¶' | replaceAll: {from:'¶', to:'¶ piped'} }} 
```

应用程序的当前状态可以在这里下载：[`bit.ly/angular2-patterns-chap2-part5`](http://bit.ly/angular2-patterns-chap2-part5)。

# 路由

路由使得在 Angular 视图之间进行导航成为可能。在这个教程中，我们将了解它们，并在一个小应用程序的框架内看到它们的运作。

# Angular CLI

**Angular CLI**是一个非常简单但非常有用的 node 包，它采用命令行工具的形式。这个工具的目的是消除大部分与 Angular 2 开始的痛苦。基于框架的任何应用程序的问题是如何为你的代码引导事物，以便与框架的特性和库进行顺畅的通信。

这个工具是由 Angular 团队直接提供的，它为即将启动的应用程序提供了可用的蓝图。实际上，通过使用一个简单的命令，我们可以生成一个完整的 Angular 样板，可以进行转译、本地运行、测试，甚至部署到 GitHub 页面。

# 安装

安装 Angular CLI 非常简单，因为它是一个 `node` 包。无论您使用什么操作系统，以下命令都可以工作：

```ts
npm install -g angular-cli 
```

如果您使用的是基于 Unix 的系统，全局安装可能需要 `sudo`。

# 创建一个新的应用程序

一旦安装了 Angular CLI，我们就可以通过使用 `ng new` 命令来生成一个新的 Angular 应用程序。

```ts
ng new MyApp 
```

这个命令将为您的应用程序创建一个空的样板，并获取每个所需的节点模块。

请注意，根据您的互联网连接，这个命令可能需要一段时间才能完成。实际上，需要获取的节点包很多，这进一步证明了这样一个工具的必要性。

在新创建的文件夹的根目录，您可以找到以下文件和文件夹：

+   `Angular-cli-build.js`：用于构建应用程序的配置文件。

+   `config`：测试环境的配置文件夹。

+   `Node_modules`：所需的不同的节点模块。当我写下这些文字时，Angular CLI 的当前版本已经在 node-modules 目录中有 60,886 个文件和文件夹。

+   `Public`：包含应用程序公共部分。

+   `tslint.json`：您的 linter 的配置。我们将在下一章中对其进行配置。

+   `typings.json`：Typings 依赖。

+   `angular-cli.json`：应用程序的一些配置。

+   `e2e`：e2e 配置。

+   `package.json`：应用程序的依赖项。

+   `src`**:** 您的源代码。

+   `typings`：所需的 typings。

毫无疑问，我们将花费最多时间的文件夹是 `src` 文件夹，因为它包含了 TypeScript 源代码。创建后，它里面包含以下内容：

```ts
src 

├── app 

│   ├── environment.ts 

│   ├── index.ts 

│   ├── my-app.component.css 

│   ├── my-app.component.html 

│   ├── my-app.component.spec.ts 

│   ├── my-app.component.ts 

│   └── shared 

│       └── index.ts 

├── favicon.ico 

├── index.html 

├── main.ts 

├── system-config.ts 

```

```ts
├── tsconfig.json 

└── typings.d.ts 
```

正如您所看到的，这里有一个 `app` 文件夹，里面已经包含了一个名为 `my-app` 的组件，还有一个共享文件夹，可以用来在不同的应用程序之间共享资源。然后，我们有包含以下内容的 `index.html`：

```ts
<!doctype html> 
<html lang="en"> 
<head> 
 <meta charset="utf-8"> 
 <title>Chap2</title> 
 <base href="/"> 

 <meta name="viewport" content="width=device-width, initial-scale=1"> 
 <link rel="icon" type="image/x-icon" href="favicon.ico"> 
</head> 
<body> 
 <app-root></app-root> 
</body> 
</html> 

```

在这个 `index.html` 中，插入了 `<app-root></app-root>` 标记，并将所需的文件加载到脚本中。

另一个重要的地方是 `main.ts` 文件，它包含了应用程序的引导行：

```ts
import { enableProdMode } from '@angular/core'; 
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic'; 

import { AppModule } from './app/app.module'; 
import { environment } from './environments/environment'; 

if (environment.production) { 
 enableProdMode(); 
} 

platformBrowserDynamic().bootstrapModule(AppModule) 
 .catch(err => console.log(err)); 

```

在这里，`MyAppAppComponent` 组件被导入并用作我们应用程序的顶层或根组件。这是将首先实例化的组件。

# 生成

目前，我们的应用程序并不是特别令人兴奋；它只会在`h1`标记中显示`my-app works!`。

如果我们想要向这个样板添加组件、指令、服务和管道，我们必须使用`generate`命令。以下是一个生成名为`Floyd`的新组件的示例：

```ts
ng generate component Floyd 
```

作为回应，Angular CLI 创建了一个名为`Floyd`的新文件夹和我们组件所需的文件：

```ts
src/app 

├── environment.ts 

├── Floyd 

│   ├── floyd.component.css 

│   ├── floyd.component.html 

│   ├── floyd.component.spec.ts 

│   ├── floyd.component.ts 

│   └── index.ts 

├── index.ts 

├── my-app.component.css 

├── my-app.component.html 

├── my-app.component.spec.ts 

├── my-app.component.ts 

└── shared 

 └── index.ts 
```

我们可以使用指令、服务或管道来执行相同的操作，而不是组件。

Angular CLI 中的每个关键字都可以通过仅使用单词的第一个字母来缩写。因此，生成另一个名为`Pascal`的组件将会是`ng g c Pascal`。

# 服务

我们的应用程序中有许多组件、服务、指令和管道，我们已经准备好看到结果了。幸运的是，Angular CLI 可以构建您的应用程序，并使用命令`ng serve`启动 Web 服务器。

然后，您可以在`localhost:4200`上查看您的应用程序。

您的文件正在被 Angular CLI 监视。每当您对文件进行更改时，Angular CLI 将重新编译它并刷新您的浏览器。

# 部署

准备让您的应用程序上线了吗？`ng build`就是您要找的。这个命令将创建一个`dist`目录，您可以将其推送到任何能够提供 HTML 页面的服务器上。甚至可以放在 GitHub 页面上，这不会花费您一分钱。

# 总结

在本章中，我们已经完成了对 Angular 构建模块的概述，并看到它们是如何相互交互的。我们还创建了一个相对简单的应用程序来操作 Floyd 数组。最后，我们学会了如何使用 Angular CLI 来使用命令行创建新应用程序、组件、服务、指令和管道。

在下一章中，我们将专注于 Angular 的最佳实践。我们将以实际的方式了解谷歌工程师推荐的“做”和“不做”。


# 第三章：经典模式

TypeScript 是一种面向对象的编程语言，因此我们可以利用几十年关于面向对象架构的知识。在本章中，我们将探索一些最有用的面向对象设计模式，并学习如何在 Angular 中应用它们。

Angular 本身就是一个面向对象的框架，它强制你以某种方式进行大部分开发。例如，你需要有组件、服务、管道等。强制这些构建块对你有助于构建良好的架构，就像 Zend 框架对 PHP 或 Ruby on Rails 对 Ruby 所做的那样。当然，框架的存在是为了让你的生活更轻松，加快开发时间。

虽然 Angular 的设计方式远远超出了平均水平，但我们总是可以做得更好。我并不是说我在本章中提出的是最终设计，或者你将能够用它来解决从面包店网页到火星一号任务的仪表板的任何问题——不幸的是，这样的设计并不存在——但它肯定会丰富你的工具库。

在本章中，我们将看到以下经典模式：

+   组件

+   单例

+   观察者

# 组件

在这本书的前三章中，我们看到了大量的 Angular 组件。Angular `Component`是 Angular 应用程序的主要构建块之一，例如`services`，`pipes`等。作为提醒，TypeScript 类使用以下注解成为 Angular 组件：

```ts
import { Component } from '@angular/core'; 

@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  title = 'app'; 
} 
```

在这里，`AppComponent`类通过`selector`，`templateUrl`和`styleUrls` Angular 组件的行为得到了增强。

# 单例模式

用于前端应用程序的另一个方便的模式是单例模式。单例模式确保你的程序中只存在一个给定对象的实例。此外，它提供了对对象的全局访问点。

实际上看起来是这样的：

```ts
export class MySingleton{ 

    //The constructor is private so we  
    //can't do `let singleton:MySingleton = new MySingleton();` 
    private static instance:MySingleton = null; 

    private constructor(){ 

    } 

    public static getInstance():MySingleton{ 
        if(MySingleton.instance == null){ 
            MySingleton.instance = new MySingleton(); 
        }
```

```ts
        return MySingleton.instance; 
    } 
} 
 let singleton:MySingleton = MySingleton.getInstance();
```

我们有一个具有`private static instance:MySingleton`属性的类。然后，我们有一个私有构造函数，使以下操作失败：

```ts
let singleton:MySingleton = new MySingleton(); 
```

请注意，它失败是因为你的 TypeScript 转译器对可见性提出了抱怨。然而，如果你将`MySingleton`类转译为 JavaScript 并将其导入到另一个 TypeScript 项目中，你将能够使用*new*运算符，因为转译后的 TypeScript 没有任何可见性。

这种相当简单的单例模式实现的问题在于并发。确实，如果两个进程同时调用`getInstance():MySingleton`，那么程序中将会有两个`MySingleton`的实例。为了确保这种情况不会发生，我们可以使用一种称为早期实例化的技术：

```ts
export

 class MySingleton
 {
   private static instance : MySingleton = new MySingleton();

 private constructor()
  {

  }

 }

singleton: MySingleton = MySingleton.getInstance();
```

虽然你可以在 TypeScript 中实现你的单例，但你也可以利用 Angular 创建单例的方式：服务！确实，在 Angular 中，服务只被实例化一次，并且被注入到任何需要它的组件中。下面是一个通过本书之前看到的`NgModule`进行服务和注入的示例：

```ts

 import { Injectable } from '@angular/core'; 

@Injectable() 
export class ApiService { 

  private static increment:number = 0; 

  public constructor(){ 
    ApiService.increment++; 
  } 

  public toString() :string { 
    return "Current instance: " + ApiService.increment; 
  } 

} 

 // ./app.component.ts

 import { Component } from '@angular/core'; 
import { ApiService } from './api.service'; 

@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  title = 'app'; 

  public constructor(api:ApiService){ 
    console.log(api); 
  } 
} 

 // ./other/other.component.ts

 import { Component, OnInit } from '@angular/core'; 
import { ApiService } from './../api.service'; 

@Component({ 
  selector: 'app-other', 
  templateUrl: './other.component.html', 
  styleUrls: ['./other.component.css'] 
}) 
export class OtherComponent implements OnInit { 

  public constructor(api:ApiService){ 
    console.log(api); 
  } 

  ngOnInit() { 
  } 

} 

 //app.module.ts

 import { BrowserModule } from '@angular/platform-browser'; 
import { NgModule } from '@angular/core'; 
import { MySingleton } from './singleton'; 

import { AppComponent } from './app.component'; 
import { OtherComponent } from './other/other.component'; 

import { ApiService } from './api.service'; 

@NgModule({ 
  declarations: [ 
    AppComponent, 
    OtherComponent 
  ], 
  imports: [ 
    BrowserModule 
  ], 
  providers: [ApiService], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { 

} 
```

在上述代码中，我们有以下内容：

+   `APIService`显示了`@Injectable()`注解，使其可以被注入。此外，`APIService`有一个`increment:number`属性，每次创建新实例时都会递增。由于`increment:number`是静态的，它将准确告诉我们程序中有多少个实例。最后，`APIService`有一个`toString:string`方法，返回当前实例编号。

+   `AppComponent`是一个经典组件，它接收了`APIService`的注入。

+   `OtherComponent`是另一个经典组件，它接收了`APIService`的注入。

+   `/app.module.ts`包含了`NgModule`。在`NgModule`中，这里显示的大部分声明已经在本书中讨论过。新颖之处来自于`providers: [APIService]`部分。在这里，我们为`APIService`本身声明了一个提供者。由于`APIService`并没有做什么太疯狂的事情，它本身就足够了，并且可以通过引用类来提供。而更复杂的服务，例如它们自己需要注入的服务，需要定制的提供者。

现在，如果我们导航到这两个组件，结果将如下：

```ts
Current instance: 1
Current instance: 1
```

这证明只创建了一个实例，并且相同的实例已被注入到两个组件中。因此，我们有一个单例。然而，这个单例虽然方便，但并不是真正安全的。你为什么这样问？嗯，`APIService`也可以在组件级别提供，就像这样：

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

  public constructor(api:ApiService){ 
    console.log(api); 
  } 
} 
 // ./other.component.ts

 @Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
  providers: [APIService],
 })
 export class OtherComponent implements OnInit { 

  public constructor(api:ApiService){ 
    console.log(api); 
  } 

  ngOnInit() { 
  } 

} 
```

在这种情况下，将创建两个单独的实例，导致以下输出：

```ts
Current instance: 1
Current instance: 2
```

因此，使用 Angular 服务，你无法强制使用单例模式，与其普通的 TypeScript 对应相反。此外，普通的 TypeScript 比 Angular 服务快上一个数量级，因为我们完全跳过了注入过程。确切的数字严重依赖于你的机器的 CPU/RAM。

在单例的情况下，唯一剩下的问题是何时使用它或哪种实现效果最好。单例只强制在程序中给定类的一个实例。因此，它非常适合与后端的任何通信或任何硬件访问。例如，在与后端的通信的情况下，可能希望只有一个`APIService`处理 API 密钥、API 限制和整个板块的`csrf`令牌，而无需确保我们在所有组件、模型等中传递相同的服务实例。在硬件访问的情况下，您可能希望确保您只打开一个与用户的网络摄像头或麦克风的连接，以便在完成后可以正确释放它们。

在性能方面，以下是每种实现的结果，以毫秒为单位。我运行了每个版本 100 次，排除了异常值（最好和最差的 5%），并对剩下的 90 次调用进行了平均，如下表所示：

| **单例懒加载** | **单例早期加载** | **服务注入** |
| --- | --- | --- |
| 196 毫秒 | 183 毫秒 | 186 毫秒 |

我运行的代码如下：

```ts
import { Component } from '@angular/core';

 import {MySingleton} from './singleton';
 import { SingletonService } from './singleton.service';

 @Component({
   selector: 'app-root',
   templateUrl: './app.component.html',
   styleUrls: ['./app.component.css']
 })
 export class AppComponent {
   title = 'app works!';

   constructor(private singleton:SingletonService){
     singleton.doStuff();
   }
   //OR
   constructor(){
     MySingleton.getInstance().doStuff();
   }
 }
```

对于服务注入的实验，我不得不在`app.module.ts`中添加以下行：`providers: [SingletonService]`。

令我惊讶的是，两种方法的结果相差不大。早期实例化的单例实现仅比更实用的服务注入好 2%。懒加载的单例排名第三，用时 196 毫秒（比早期实例化的单例差 7%，比服务注入差 5%）。

# 工厂方法

假设我们有一个带有两个私有变量`lastName:string`和`firstName:string`的`User`类。此外，这个简单的类提供了`hello`方法，打印出`"Hi I am", this.firstName, this.lastName`：

```ts
class User{
     constructor(private lastName:string, private firstName:string){
     }
     hello(){
         console.log("Hi I am", this.firstName, this.lastName);
     }
 }
```

现在，考虑到我们通过 JSON API 接收用户。它很可能看起来像这样：

```ts
[{"lastName":"Nayrolles","firstName":"Mathieu"}...].  
```

通过以下代码片段，我们可以创建一个`User`：

```ts
let userFromJSONAPI: User = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')[0];
```

到目前为止，TypeScript 编译器没有抱怨，并且执行顺利。这是因为`parse`方法返回`any`（例如，Java 对象的 TypeScript 等价物）。当然，我们可以将`any`转换为`User`。然而，`userFromJSONAPI.hello();`将产生以下结果：

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

为什么？好吧，赋值的左侧被定义为`User`，但当我们将其转译为 JavaScript 时，它将被抹去。

在 TypeScript 中进行类型安全的方式如下：

```ts
let validUser = JSON.parse('[{"lastName":"Nayrolles","firstName":"Mathieu"}]')
 .map((json: any):User => {
     return new User(json.lastName, json.firstName);
 })[0];
```

有趣的是，函数的类型也不会帮助你。在这两种情况下，它都会显示`object`而不是`User`，因为 JavaScript 中并不存在用户的概念。

虽然直接的类型安全方法可以工作，但它并不是非常可扩展或可重用的。事实上，地图回调方法必须在接收 JSON 用户的任何地方重复。最方便的方法是通过`Factory`模式来做。工厂用于创建对象，而不会将实例化逻辑暴露给客户端。

如果我们要创建一个用户的工厂，它会是这样的：

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

在这里，我们有一个名为`buildUser`的`static`方法，它接收一个 JSON 对象，并从 JSON 对象中获取所有必需的值，以调用一个假设的`User`构造函数。这个方法是静态的，就像工厂的所有方法一样。事实上，在工厂中我们不需要保存任何状态或实例绑定的变量；我们只是将用户的创建封装起来。请注意，你的工厂可能会与你的 POTO 的其余部分共享。

# 观察者

允许一个名为主题的对象跟踪其他对象（称为观察者）对主题状态感兴趣的可观察模式。当主题状态改变时，它会通知观察者。这背后的机制非常简单。

让我们来看一下在纯 TypeScript 中（没有任何 Angular 2 或任何框架，只是 TypeScript）实现的观察者/主题实现。首先，我定义了一个`Observer`接口，任何具体的实现都必须实现：

```ts
export interface Observer{ 
    notify(); 
}
```

这个接口只定义了`notify()`方法。当被观察对象的状态改变时，主题（观察者观察的对象）将调用这个方法。然后，我有一个这个接口的实现，名为`HumanObserver`：

```ts
export class HumanObserver implements Observer{ 
    constructor(private name:string){}

    notify(){

        console.log(this.name, 'Notified');
    } 
} 
```

这个实现利用了 TypeScript 属性构造函数，其中你可以在构造函数内部定义类的属性。这种表示法与以下表示法完全等效，但更短：

```ts
private name:string; 
constructor(name:string){

        this.name = name;
}
```

在定义了`Observer`接口和`HumanObserver`之后，我们可以继续进行主题。我定义了一个管理观察者的主题类。这个类有三个方法：`attachObserver`，`detachObserver`和`notifyObservers`：

```ts
export class Subject{ 
private observers:Observer[] = [];

/**
* Adding an observer to the list of observers
*/
attachObserver(observer:Observer):void{

        this.observers.push(observer);
}

/**
* Detaching an observer
*/
detachObserver(observer:Observer):void{

    let index:number = this.observers.indexOf(observer);

    if(index > -1){

        this.observers.splice(index, 1);
    }else{

        throw "Unknown observer";
    }
}

/**
* Notify all the observers in this.observers
*/
protected notifyObservers(){

    for (var i = 0; i < this.observers.length; ++i) {

        this.observers[i].notify();
    }
} 
} 
```

`attachObserver`方法将新的观察者推入`observers`属性中，而`detachObserver`则将它们移除。

主题实现通常以 attach/detach，subscribe/unsubscribe 或 add/delete 前缀的形式出现。

最后一个方法是`notifyObservers`，它遍历观察者并调用它们的通知方法。允许我们展示可观察机制的最后一个类是 IMDB，它扩展了`subject`。它将在添加电影时通知观察者：

```ts
export class IMDB extends Subject{

    private movies:string[] = [];

     public addMovie(movie:string){

         this.movies.push(movie);
         this.notifyObservers();
     }
 }
```

为了使这些部分彼此通信，我们必须：创建一个`Subject`，创建一个`Observer`，将`Observer`附加到`Subject`，并通过`addMovie`方法改变主题的状态。

更具体地说，以下是先前列表的实现：

```ts
let imdb:IMDB = new IMDB();
 let mathieu:HumanObserver = new HumanObserver("Mathieu");
 imbd.attachObserver(mathieu);
 imbd.addMovie("Jaws");
```

为了加快我们的开发过程，我们将安装`ts-node`。这个 node 包将把 TypeScript 文件转译成 JavaScript，并解决这些文件之间的依赖关系。

输出是`Mathieu Notified`。我们可以尝试分离`mathieu`并添加另一部电影：

```ts
imdb.detachObserver(mathieu);
 imdb.addMovie("Die Hard");
```

输出仍然是`Mathieu Notified`，这发生在我们添加`Jaws`电影之后。第二部电影（`Die Hard`）的添加并不会触发控制台打印`Mathieu Notified`，因为它已经被分离。

# 带参数的 TypeScript 可观察对象

因此，这是观察者模式的一个基本实现。然而，它并不完全成熟，因为`HumanObserver`只知道它观察的主题中的某些东西发生了变化。因此，它必须遍历它观察的所有主题，并检查它们的先前状态与当前状态，以确定发生了什么变化以及在哪里发生了变化。更好的方法是修改`Observer`的`notify`，使其包含更多信息。例如，我们可以添加可选参数如下：

```ts
export interface Observer{

     notify(value?:any, subject?:Subject);
 }

 export class HumanObserver implements Observer{

     constructor(private name:string){}

     notify(value?:any, subject?:Subject){

         console.log(this.name, 'received', value, 'from', subject);
     }
 }
```

`notify()`方法现在接受一个可选的值参数，用于描述`subject`对象的新状态。我们还可以接收到`Subject`对象本身的引用。这在观察者观察多个主题时非常有用。在这种情况下，我们需要能够区分它们。因此，我们必须稍微更改 Subject 和 IMDB，以便它们使用新的通知：

```ts
export class Subject{

     private observers:Observer[] = [];

     attachObserver(oberver:Observer):void{

         this.obervers.push(oberver);
     }

     detachObserver(observer:Observer):void{
         let index:number = this.obervers.indexOf(observer);
         if(index > -1){
             this.observers.splice(index, 1);

         }else{

             throw "Unknown observer";
         }
     }

     protected notifyObservers(value?:any){

         for (var i = 0; i < this.obervers.length; ++i) {

             this.observers[i].notify(value, this);
         }
     }
 }

 export class IMDB extends Subject{

     private movies:string[] = [];

     public addMovie(movie:string){

         this.movies.push(movie);
         this.notifyObservers(movie);
     }
 }
```

最后，输出如下：

```ts
 Mathieu received Jaws from IMDB {

   observers: [ HumanObserver { name: 'Mathieu' } ],
   movies: [ 'Jaws' ] }
```

这比`Mathieu Notified`更具表现力。现在，当我们使用观察者模式进行异步编程时，我们真正的意思是要求某些东西，并且在其处理过程中不想等待做任何事情。相反，我们订阅响应事件以在响应到来时得到通知。在接下来的章节中，我们将使用相同的模式和机制与 Angular 一起使用。

# 观察 HTTP 响应

在本节中，我们将构建一个 JSON API，根据搜索参数返回电影。我们不仅仅是等待 HTTP 查询完成，而是利用观察者设计模式的力量，让用户知道我们正在等待，并且如果需要，执行其他进程。首先，我们需要一个数据源来构建我们的类似 IMDB 的应用程序。构建和部署一个能够解释 HTTP 查询并相应发送结果的服务器端应用程序现在相对简单。然而，这超出了本书的范围。相反，我们将获取托管在[`bit.ly/mastering-angular2-marvel`](http://bit.ly/mastering-angular2-marvel)的静态 JSON 文件。该文件包含漫威电影宇宙的一些最新电影。它包含一个描述 14 部电影的 JSON 数组作为 JSON 对象。这是第一部电影：

```ts
 {
 "movie_id" : 1,
 "title" : "The Incredible Hulk",
 "phase" : "Phase One: Avengers Assembled",
 "category_name" : "Action",
 "release_year" : 2005,
 "running_time" : 135,
 "rating_name" : "PG-13",
 "disc_format_name" : "Blu-ray",
 "number_discs" : 1,
 "viewing_format_name" : "Widescreen",
 "aspect_ratio_name" : " 2.35:1",
 "status" : 1,
 "release_date" : "June 8, 2008",
 "budget" : "150,000,000",
 "gross" : "263,400,000",
 "time_stamp" : "2018-06-08"
 },
```

您可以找到类似 IMDB 的应用程序提供的标准信息，例如发行年份，播放时间等。我们的目标是设计一个异步的 JSON API，使每个字段都可以搜索。

由于我们正在获取一个静态的 JSON 文件（我们不会插入、更新或删除任何元素），可接受的 API 调用如下：

```ts
IMDBAPI.fetchOneById(1);
 IMDBAPI.fetchByFields(MovieFields.release_date, 2015);
```

第一个调用只是获取`movie_id = 1`的电影；第二个调用是一个更通用的调用，可以在任何字段中工作。为了防止 API 使用者请求我们电影中不存在的字段，我们使用在`Movie`类内部定义的枚举器限制字段值。现在，这里的重要部分是这些调用的实际返回。实际上，它们将触发一个可观察机制，在这种机制中，调用者将附加到一个可观察的 HTTP 调用。然后，当 HTTP 调用完成并根据查询参数过滤结果时，被调用者将通知调用者有关响应。因此，调用者不必等待被调用者（`IMDBAPI`），因为他们将在请求完成时收到通知。

# 实施

让我们深入实现。首先，我们需要使用 Angular CLI 创建一个新的 Angular 项目：

```ts
mkdir angular-observable
 ng init
 ng serve
```

接下来，我们需要一个模型来表示电影概念。我们将使用`ng g class` models/Movie 命令行生成这个类。然后，我们可以添加一个构造函数，定义`Movie`模型的所有私有字段，这与我们为 getter 和 setter 所做的相同。

```ts
export class Movie {

     public constructor(
         private _movie_id:number,
         private _title: string,
         private _phase: string,
         private _category_name: string,
         private _release_year: number,
         private _running_time: number,
         private _rating_name: string,
         private _disc_format_name: string,
         private _number_discs: number,
         private _viewing_format_name: string,
         private _aspect_ratio_name: string,
         private _status: string,
         private _release_date: string,
         private _budget: number,
         private _gross: number,
         private _time_stamp:Date){
     }

     public toString = () : string => {

         return `Movie (movie_id: ${this._movie_id},
         title: ${this._title},
         phase: ${this._phase},
         category_name: ${this._category_name},
         release_year: ${this._release_year},
         running_time: ${this._running_time},
         rating_name: ${this._rating_name},
         disc_format_name: ${this._disc_format_name},
      number_discs: ${this._number_discs},
         viewing_format_name: ${this._viewing_format_name},
         aspect_ratio_name: ${this._aspect_ratio_name},
         status: ${this._status},
         release_date: ${this._release_date},
         budget: ${this._budget},
         gross: ${this._gross},
         time_stamp: ${this._time_stamp})`;

     }
    //GETTER
    //SETTER
 }

 export enum MovieFields{
     movie_id,
     title,
     phase,
     category_name,
     release_year,
     running_time,
     rating_name,
     disc_format_name,
     number_discs,
     viewing_format_name,
     aspect_ratio_name,
     status,
     release_date,
     budget,
     gross,
     time_stamp
 }
```

在这里，电影 JSON 定义的每个字段都使用构造函数属性声明映射到`Movie`类的私有成员

TypeScript。我们还覆盖了`toString`方法，以便打印每个字段。在`toString`方法中，我们利用反引号(` `)提供的多行字符串和`${}`语法，允许我们连接字符串和不同的变量。然后，我们有一个名为`MovieFields`的枚举器，它将允许我们限制可搜索的字段。

接下来，我们需要生成`IMDBAPI`类。由于`IMDBAPI`类可能会在程序的任何地方使用，我们将其定义为服务。其优势在于服务可以被注入到任何组件或指令中。此外，我们可以选择是否让 Angular 2 在每次注入时创建`IMDBAPI`的实例，或者始终注入相同的实例。如果为`IMDBAPI`创建的提供者是在应用程序级别的话，那么请求它的任何人都会得到同一个`IMDBAPI`的实例。然而，在组件级别，每次实例化该组件时都会创建新的`IMDBAPI`实例并提供给该组件。在我们的情况下，只有一个`IMDBAPI`实例更合理，因为它不会有任何特定于从一个组件到另一个组件可能会发生变化的状态。让我们生成`IMDBAPI`服务(`ng g s``services/IMDBAPI`)，并实现我们之前定义的两个方法：

```ts
IMDBAPI.fetchOneById(1);
 IMDBAPI.fetchByFields(MovieFields.release_date, 2015);
```

这是带有`fetchOneById`方法的 IMDAPI 服务：

```ts
import { Injectable } from '@angular/core';
 import { Http }  from '@angular/http';
 import { Movie, MovieFields } from '../models/movie';
 import { Observable } from 'rxjs/Rx';
 import 'rxjs/Rx';

 @Injectable()

 export class IMDBAPIService {

   private moviesUrl:string = "app/marvel-cinematic-universe.json";

   constructor(private http: Http) { }
   /**
    * Return an Observable to a Movie matching id
    * @param  {number}           id
    * @return {Observable<Movie>}  
    */
   public fetchOneById(id:number):Observable<Movie>{
     console.log('fetchOneById', id);

         return this.http.get(this.moviesUrl)
         /**
         * Transforms the result of the HTTP get, which is observable
         * into one observable by item.
         */
         .flatMap(res => res.json().movies)

         /**
         * Filters movies by their movie_id

         */
         .filter((movie:any)=>{

             console.log("filter", movie);
             return (movie.movie_id === id)
         })

         /**
         * Map the JSON movie item to the Movie Model
         */
         .map((movie:any) => {

             console.log("map", movie);

             return new Movie(

                 movie.movie_id,
                 movie.title,
                 movie.phase,
                 movie.category_name,
                 movie.release_year,
                 movie.running_time,
                 movie.rating_name,
                 movie.disc_format_name,
                 movie.number_discs,
                 movie.viewing_format_name,
                 movie.aspect_ratio_name,
                 movie.status,
                 movie.release_date,
                 movie.budget,
                 movie.gross,
                 movie.time_stamp
             );
         });
   }
 }
```

# 理解实现

让我们一步步来分解。首先，服务的声明非常标准：

```ts
import { Injectable } from '@angular/core'; 
import { Http } from '@angular/http'; 

import { Movie, MovieFields } from '../models/movie'; 
import { Observable } from 'rxjs/Rx'; 
import 'rxjs/Rx';

@Injectable()
 export class IMDBAPIService {
  private moviesUrl:string = "app/marvel-cinematic-universe.json";
  constructor(private http: Http) { }
```

服务是可注入的。因此，我们需要导入并添加`@Injectable`注解。我们还导入`Http`，`Movie`，`MovieFields`，`Observable`以及`Rxjs`的操作符。**RxJS**代表**JavaScript 的响应式扩展**。它是用于执行观察者、迭代器和函数式编程的 API。当涉及到 Angular 2 中的异步操作时，大部分情况下会依赖于 RxJS。

值得注意的是，我们使用的是 RxJS 5.0，它是一次完整的重写，基于相同概念的 RxJS 4.0。

`IMDBAPIService`还有一个对我们的 JSON 文件路径的引用，以及一个接收 HTTP 服务注入的构造函数。在`fetchOneById`方法的实现中，我们可以看到四个不同的操作链接在一起：`get`， `flatMap`，`filter`和`map`。 `Get`返回 HTTP 请求的主体上的 observable。 `flatMap`通过应用您指定的每个发射项目的 observable 函数来转换`get observable`，其中该函数返回发出项目的`observable`。然后，`flatMap`合并这些结果的发射，将这些合并的结果作为其序列发射。在我们的情况下，这意味着我们将对从 HTTP 获取的所有项目应用接下来的两个操作（filter 和 map）。筛选器检查当前电影的 ID 是否是我们要查找的 ID，Map 将电影的 JSON 表示转换为电影的 TypeScript 表示（例如`Movie`类）。

最后一个操作虽然反直觉，但却是必须的。事实上，人们可能会认为 JSON 表示和 TypeScript 表示是相同的，因为它们拥有相同的字段。然而，TypeScript 表示以及其属性定义了`toString`，getter 和 setter 等函数。移除`map`将返回一个包含`Movie`所有字段的`Object`实例，而不是`Movie`。此外，类型转换也无济于事。事实上，TypeScript 转换器将允许您将`Object`转换为`Movie`，但它仍然不会包含`Movie`类中定义的方法，因为当 TypeScript 转换为 JavaScript 时，静态类型概念消失。以下情况将无法在执行时转换：

```ts
movie.movie_id(25) TypeError: movie.movie_id is not a function at Object.<anonymous>
movie: Movie = JSON.parse(`{
                             "movie_id" : 1,
                              "title" : "Iron Man",
                              "phase" : "Phase One: Avengers Assembled",
                             "category_name" : "Action",
                             "release_year" : 2015,
                              "running_time" : 126,
                              "rating_name" : "PG-13",
                              "disc_format_name" : "Blu-ray",
                              "number_discs" : 1,
                              "viewing_format_name" : "Widescreen",
                              "aspect_ratio_name" : " 2.35:1",
                              "status" : 1,
                              "release_date" : "May 2, 2008",
                              "budget" : "140,000,000",
                              "gross" : "318,298,180",
                              "time_stamp" : "2015-05-03"
        }`);
 Console.log(movie.movie_id(25));
```

现在，如果我们想要使用我们的`IMDB`服务，则需要进一步修改由 Angular CLI 生成的代码。首先，我们需要修改`main.ts`，使其看起来像这样：

```ts
import{ bootstrap } from '@angular/platform-browser-dynamic';
 import{ enableProdMode } from '@angular/core';
 import{ AngularObservableAppComponent, environment } from './app/';
 import{ IMDBAPIService } from './app/services/imdbapi.service';
 import { HTTP_PROVIDERS } from '@angular/http';
 if(environment.production)  {
     enableProdMode();
}

```

```ts
 bootstrap(AngularObservableAppComponent, 
    [IMDBAPIService , HTTP_PROVIDERS]
);
```

粗体的行表示新增内容。我们导入我们的`IMDBService`和`HTTP_PROVIDERS`。这两个提供者在应用程序级别声明，这意味着将被注入到控制器或指令中的实例始终是相同的。

然后，我们修改了生成的`angular-observable.component.ts`文件，并添加了以下内容：

```ts
import { Component } from '@angular/core';
import { IMDBAPIService } from './services/imdbapi.service';
import { Movie } from './models/movie';

@Component({
  moduleId: module.id, 
  selector: 'angular-observable-app', 
  templateUrl: 'angular-observable.component.html', 
  styleUrls: ['angular-observable.component.css']
 })
 export class AngularObservableAppComponent {
   title = 'angular-observable works!'; 
   private movies:Movie[] = [];
   private error:boolean = false; 
   private finished:boolean = false;

 constructor(private IMDBAPI:IMDBAPIService){
    this.IMDBAPI.fetchOneById(1).subscribe(
       value => {this.movies.push(value); console.log("Component",value)},
       error => this.error = true, 
       () => this.finished =true 
      )
   }
 }
```

我们将几个属性添加到`AngularObservableAppComponent`：`movies`，`error`和`finished`。第一个属性是存储我们查询结果的`Movie`数组，而第二个和第三个属性是`error`和`termination`的标志。在构造函数中，我们注入了`IMDBAPIService`，并订阅了`fetchOneById`方法的结果。`subscribe`方法期望三个回调函数：

+   **观察者**：接收被观察方法产生的值。这是本章前面看到的通知方法的 RxJS 等效物。

+   **错误**（**可选**）：在观察到对象产生错误的情况下触发。

+   **Complete**（**可选**）：完成时触发。

最后，我们可以修改`angular-ob``servable.component.html`文件来映射`AngularObservableAppComponent`数组的`movie`属性：

```ts
<h1>
  {{title}}
</h1>

<ul>
   <li *ngFor = "let movie of movies">{{movie}}</li> 
</ul>
```

我们可以看到，第一个电影条目已经被正确插入到我们的`ul`/`li` HTML 结构中。关于这段代码真正有趣的地方在于事物执行的顺序。分析日志有助于我们掌握 Angular 与 RxJS 中异步性的真正力量。我们的代码执行后，控制台如下所示：

```ts
javascript fetchOneById 1 :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:34 map Object :4200/app/angular-observable.component.js:21 Component Movie_aspect_ratio_name: " 2.35:1"_budget: "140,000,000"_category_name: "Action"_disc_format_name: "Blu-ray"_gross: "318,298,180"_movie_id: 1_number_discs: 1_phase: "Phase One: Avengers Assembled"_rating_name: "PG-13"_release_date: "May 2, 2008"_release_year: 2015_running_time: 126_status: 1_time_stamp: "2015-05-03"_title: "Iron Man"_viewing_format_name: "Widescreen"aspect_ratio_name: (...)budget: (...)category_name: (...)disc_format_name: (...)gross: (...)movie_id: (...)number_discs: (...)phase: (...)rating_name: (...)release_date: (...)release_year: (...)running_time: (...)status: (...)time_stamp: (...)title: (...)toString: ()viewing_format_name: (...)__proto__: Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object :4200/app/services/imdbapi.service.js:30 filter Object
```

如你所见，`AngularObservableAppComponent`在过滤函数分析所有项之前就收到了匹配查询的电影的通知。提醒一下，在按 ID 获取时，`fetchOneById`方法的操作顺序是：`get`、`flatMap`、`filter`和`map`，而且`filter`和`map`方法也有日志记录语句。因此，这里的`filter`操作分析了第一项，恰好是我们寻找的那一项（`movie_id===1`），并将其转发给将其转化为`Movie`的`map`操作。这个`Movie`被立刻发送给了`AngularObservableAppComponent`。我们清楚地看到，在`AngularObservableAppComponent`组件中收到的对象是`Movie`类型，因为控制台给出了我们对`toString`方法的覆盖。然后，`filter`操作继续处理剩下的项。它们中没有一个匹配。因此，我们不会再收到任何通知了。让我们更进一步地用第二种方法`IMDBAPI.fetchByField`进行测试：

```ts

 public fetchByField(field:MovieFields, value:any){
 console.log('fetchByField', field, value); 
 return this.http.get (this.moviesUrl)
      .flatMap(res => res.json().movies)
 /**
 * Filters movies by their field
 */
 .filter((movie:any) =>{

     console.log("filter" , movie);
     return (movie[MovieFields[field]] === value)
  })

 /**
 * Map the JSON movie item to the Movie Model
 */
 .map(( movie: any) => {
     console.log ("map", movie);  
     return new Movie( 
         movie.movie_id, 
         movie.title,  
         movie.phase, 
         movie.category_name, 
         movie.release_year,  
         movie.running_time,  
         movie.rating_name,  
         movie.disc_format_name,  
         movie.number_discs, 
         movie.viewing_format_name,
         movie.aspect_ratio_name,  
         movie.status,
         movie.release_date,
         movie.budget,
         movie.gross,  
         movie.time_stamp
      );
   });
}
```

对于`fetchByField`方法，我们使用与`fetchById`相同的机制。毫不奇怪，操作仍然是一样的：`get`、`flatMap`、`filter`和`map`。唯一的变化在于过滤操作，这里我们现在必须根据作为参数接收的字段进行过滤：

```ts
return (movie[MovieFields[field]] === value).
```

对于 TypeScript 或 JavaScript 初学者来说，这个声明可能有点令人困惑。首先，`MovieFields[field]`部分的解释是`enum`将被转译为以下 JavaScript 函数：

```ts
(function(MovieFields) {
   MovieFields[MovieFields["movie_id"] = 0] = "movie_id";
   MovieFields[MovieFields["title"] = 1] = "title";
   MovieFields[MovieFields["phase"] = 2] = "phase"; 
   MovieFields[MovieFields["category_name"] = 3] = "category_name";
   MovieFields[MovieFields["release_year"] = 4] = "release_year";
   MovieFields[MovieFields["running_time"] = 5] = "running_time"; 
   MovieFields[MovieFields["rating_name"] = 6] = "rating_name";
   MovieFields[MovieFields["disc_format_name"] = 7] ="disc_format_name";
   MovieFields[MovieFields["number_discs"] = 8] = "number_discs";
   MovieFields[MovieFields["viewing_format_name"] = 9] = "viewing_format_name";
 MovieFields[MovieFields["aspect_ratio_name"] = 10] =  "aspect_ratio_name";
 MovieFields[MovieFields["status"] = 11] = "status"; 
 MovieFields[MovieFields["release_date"] = 12] = "release_date";
 MovieFields[MovieFields["budget"] = 13] = "budget";
 MovieFields[MovieFields["gross"] = 14] = "gross";
 MovieFields[MovieFields["time_stamp"] = 15] = "time_stamp";
 })(exports.MovieFields || (exports.MovieFields =  {}));
 var MovieFields = exports.MovieFields;
```

结果，`MovieFields.release_year`的值实际上是 4，而`MovieFields`是一个静态数组。因此，请求`MovieFields`数组的第四个索引会使我得到字符串`release_year is`。因此，在我们当前的示例中，`movie[MovieFields[field]]`被解释为`movie["release_year is"]`。

现在我们有了五个匹配项而不是一个。分析控制台，我们可以看到通知仍然在找到合适的对象时立即出现，而不是在所有被过滤完后出现：

```ts
fetchByField 4 2015
 imdbapi.service.js:43  filter Object  {movie_id: 1,  title: "Iron Man", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:47 map Object {movie_id: 1, title: "Iron Man", phase: "Phase One: Avengers Assembled", category_name: "Action",  release_year: 2015...}
 angular-observable.component.js:22 Component Movie {_movie_id: 1, _title: "Iron Man", _phase: "Phase One: Avengers Assembled", _category_name: "Action", _release_year: 2015...}
 imdbapi.service.js:43 filter Object {movie_id: 2, title: "The Incredible Hulk", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2008...}
 imdbapi.service.js:43 filter Object {movie_id: 3, title: "Iron Man 2", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:47map Object {movie_id: 3 =, title: "Iron Man 2", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 angular-observable.component.js:22 Component Movie{_movie_id: 3, _title: "Iron Man 2", _phase: "Phase One: Avengers Assembled", _category_name: "Action", _release_year:2015...}
 imdbapi.service.js:43 filter Object {movie_id: 4, title: "Thor", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year:2011...}
 imdbapi.service.js:43filter Object {movie_id: 5, title: "Captain America", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2011...}
 imdbapi.service.js:43 filter Object {movie_id: 6, title: "Avengers, The", phase: "Phase One: Avengers Assembled", category_name: "Science Fiction", release_year: 2012...}
 imdbapi.service.js:43 filter Object {movie_id: 7, title: "Iron Man 3", phase: "Phase Two", category_name: "Action", release_year : 2015...}
 imdbapi.service.js:47 map Object {movie_id: 7, title: "Iron Man 3", phase: "Phase Two", category_name: "Action", release_year:2015...}
 angular-observable.component.js: 22 Component Movie {_movie_id: 7, _title: "Iron Man 3", _phase: "Phase Two", _category_name:"Action", _release_year: 2015...}
 imdbapi.service.js:43 filter Object {movie_id: 8, title: "Thor: The Dark World", phase: "Phase Two", category_name: "Science Fiction", release_year: 2013...}
 imdbapi.service.js:43 filter Object {movie_id: 9, title: "Captain America: The Winter Soldier", phase: "Phase Two", category_name: "Action", release_year: 2014...}
 imdbapi.service.js:43 filter Object {movie_id: 10, title: "Guardians of the Galaxy", phase: "Phase Two", category_name: "Science Fiction", release_year: 2014...}
 imdbapi.service.js:43 filter Object {movie_id: 11, title: "Avengers: Age of Ultron", phase: "Phase Two", category_name: "Science Fiction", release_year: 2015...}
 imdbapi.service.js:47 map Object {movie_id: 11, title: "Avengers: Age of Ultron", phase:  "Phase Two", category_name: "Science Fiction", release_year: 2015...}
 angular-observable.component.js:22 Component Movie {_movie_id: 11, _title: "Avengers: Age of Ultron", _phase: "Phase Two", _category_name: "Science Fiction", _release_year:2015...}
 imdbapi.service.js:43 filter Object {movie_id: 12, title: "Ant-Man", phase: "Phase Two", category_name: "Science Fiction", release_year: 2015...}
 imdbapi.service.js:47 map Object {movie_id: 12, title: "Ant-Man", phase: "Phase Two", category_name: "Science Fiction", release_year: 2015...}
 angular-observable.component.js:22 Component Movie {_movie_id: 12, _title: "Ant-Man", _phase: "Phase Two", _category_name: "Science Fiction", _release_year: 2015...}
 imdbapi.service.js:43 filter Object {movie_id: 13, title: "Captain America: Civil War",phase: "Phase Three", category_name: "Science Fiction", release_year: 2016...}
imdbapi.service.js:43 filter Object {movie_id: 14, title: "Doctor Strange", phase: "Phase Two", category_name: "Science Fiction", release_year: 2016...}
```

现在，这种设计模式的另一个优势是能够自行取消订阅。要这样做，你只需获取对订阅的引用并调用`unsubscribe()`方法，如下所示：

```ts
constructor(private IMDBAPI:IMDBAPIService{ 
 let imdbSubscription = this.IMDBAPI.fetchByField(MovieFields.release_year, 2015).subscribe(
       value=> {
            this.movies.push(value);
            console.log("Component", value)
            if(this.movies.length > 2){
                    imdbSubscription.unsubscribe();
             }
      },
     error => this.error = true,
     () => this.finished = true
    );
 }
```

在这里，我们在第三个通知后取消订阅。除此之外，可观察对象甚至会检测到没有人再观察它，然后停止它正在做的任何事情。事实上，上一个带有`unsubscribe`的代码产生了：

```ts
fetchByField 4 2015
 imdbapi.service.js:43 filter Object {movie_id: 1, title: "Iron Man", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:49 map Object {movie_id: 1, title: "Iron Man", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 angular-observable.component.js:24 Component Movie {_movie_id: 1, _title: "Iron Man", _phase: "Phase One: Avengers Assembled", _category_name: "Action", _release_year: 2015...}
 imdbapi.service.js:43 filter Object {movie_id: 2, title: "The Incredible Hulk", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2008...}
 imdbapi.service.js:43 filter Object { movie_id: 3, title: "Iron Man 2", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:49 map Object {movie_id: 3, title: "Iron Man 2", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 angular-observable.component.js:24 Component Movie {_movie_id: 3, _title: "Iron Man 2", _phase:  "Phase One: Avengers Assembled", _category_name: "Action",_release_year: 2015...}
 imdbapi.service.js:43 filter Object {movie_id: 4, title: "Thor", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2011...}
 imdbapi.service.js:43 filter Object {movie_id: 5, title: "Captain America", phase: "Phase One: Avengers Assembled", category_name: "Action",release_year: 2011...}
 imdbapi.service.js:43 filter Object {movie_id: 6, title: "Avengers, The", phase: "Phase One: Avengers Assembled", category_name: "Science Fiction", release_year: 2012...}
 imdbapi.service.js:43 filter Object {movie_id: 7, title: "Iron Man 3", phase: "Phase Two", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:49 map Object {movie_id: 7, title: "Iron Man 3", phase: "Phase Two", category_name: "Action", release_year: 2015...}
 angular-observable.component.js:24 Component Movie {_movie_id: 7, _title: "Iron Man 3", _phase: "Phase Two", _category_name: "Action", _release_year: 2015...}
```

所有事情在第三次通知后停止了。

# Promises

Promise 是 Angular 2 提供的另一个有用的异步概念。它承诺提供与`Observer`相同的功能：处理某些事情，并且异步地通知调用者答案已经准备好了。那么，为什么要同时存在两个做相同事情的概念呢？嗯，`Observer`的冗长使得`Promise`无法实现的一件事情是：取消订阅。因此，如果你永远不打算使用观察者模式的取消订阅功能，那么最好使用`Promises`，在我看来，它们在书写和理解上更直观。为了强调观察者和 Promise 之间的差异，我们将采用与之前相同的例子——从 JSON API 获取电影。`AngularObservableAppComponent`将向`IMDBAPIService`发出异步调用，并在答案到来时更新 HTML 视图。

这是使用`Promise`而不是`Observable`的`fetchOneById`方法：

```ts

 /**
 * Return a Promise to a Movie matching id
 *@param  {number}  id
 *@return {Promise<Movie>}
 */
 public fetchOneById(id:number) : Promise <Movie>{
 console.log('fecthOneById', id);

      return this.http.get(this.moviesUrl)
     /**
     * Transforms the result of the HTTP get, which is observable
     * into one observable by item.
     */
     .flatMap(res => res.json().movies)
     /**
     * Filters movies by their movie_id
     */
    .filter((movie:any) =>{
        console.log("filter", movie);
       return (movie.movie_id === id)
   })
   .toPromise()
   /**
 * Map the JSON movie item to the Movie Model
 */
    .then((movie:any) => {

       console.log("map", movie);
       return new Movie(
              movie.movie_id,
              movie.title,
              movie.phase,
              movie.category_name,
              movie.release_year,
              movie.running_time,
              movie.rating_name,
              movie.disc_format_name,
              movie.number_discs,
              movie.viewing_format_name,
              movie.aspect_ratio_name,
              movie.status,
              movie.release_date,
              movie.budget,
              movie.gross,
              movie.time_stamp
      )
});
 }
```

如此代码所示，我们从`flatMap`，`filter`，`map`变为了`flatMap`，`filter`，`Promise`，`then`。新的操作`toPromise`和`then`将创建一个包含`filter`操作结果的`Promise`对象，在`filter`操作完成时，`then`操作将被执行。`then`操作可以被视为一个 map；它做的事情是一样的。为了使用这段代码，我们还需要修改在`AngularObservableAppComponent`中调用`IMDBAPIService`的方式如下：

```ts

 this.IMDBAPI.fetchOneById(1).then(
        value => {
              this.movies.push(value);

              console.log("Component", value)
       },
       error => this.error = true
 );
```

一次又一次，我们可以看到一个`then`操作，该操作将在`IMDBAPIService.FetchOneById`的 promise 完成时执行。`then`操作接受两个回调函数：`onCompletion`和`onError`。第二个回调函数`onError`是可选的。现在，`onCompletion`回调函数仅在 Promise 完成时执行一次，如控制台所示：

```ts
imdbapi.service.js:30 filter Object {movie_id: 2, title: "The Incredible Hulk", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2008...}
 imdbapi.service.js:30 filter Object {movie_id: 3, title: "Iron Man 2", phase : "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:30 filter Object {movie_id: 4, title: "Thor", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2011...}
 imdbapi.service.js:30 filter Object {movie_id: 5, title: "Captain America", phase:  "Phase One: Avengers Assembled", category_name: "Action", release_year: 2011...}
 imdbapi.service.js:30 filter Object {movie_id: 6, title: "Avengers, The", phase: "Phase One: Avengers Assembled", category_name:"Science Fiction", release_year: 2012...}
 imdbapi.service.js:30 filter Object {movie_id: 7, title: "Iron Man 3", phase: "Phase Two", category_name: "Action", release_year: 2015...}
 imdbapi.service.js:30 filter Object {movie_id: 8, title: "Thor: The Dark World", phase: "Phase Two", category_name: "Science Fiction", release_year: 2013...}
 imdbapi.service.js:30 filter Object {movie_id: 9, title: "Captain America: The Winter Soldier", phase: "Phase Two", category_name: "Action",release_year: 2014...}
 imdbapi.service.js:30 filter Object {movie_id: 10, title: "Guardians of the Galaxy", phase: "Phase Two", category_name: "Science Fiction", release_year: 2014...}
 imdbapi.service.js:30 filter Object { movie_id: 11, title: "Avengers: Age of Ultron", phase: "Phase Two", category_name: "Science Fiction", release_year: 2015...}
 imdbapi.service.js:30 filter Object {movie_id: 12, title: "Ant-Man", phase: "Phase Two", category_name: "Science Fiction", release_year: 2015...}
 imdbapi.service.js:30 filter Object {movie_id: 13, title: "Captain America: Civil War", phase: "Phase Three", category_name: "Science Fiction", release_year: 2016...}
 imdbapi.service.js:30 filter Object {movie_id: 14, title: "Doctor Strange", phase: "Phase Two", category_name: "Science Fiction", release_year: 2016...}
 imdbapi.service.js:35 map Object {movie_id: 1, title: "Iron Man", phase: "Phase One: Avengers Assembled", category_name: "Action", release_year: 2015...}
 angular-observable.component.js:23 Component Movie {_movie_id: 1, _title: "Iron Man", _phase: "Phase One: Avengers Assembled", _category_name: "Action",  _release_year: 2015...}
```

虽然对于`fetchOneById`方法，对`IMDBAPIService`的修改很小，但我们需要更显著地修改`fetchByField`。实际上，`onComplete`回调函数只会执行一次，所以我们需要返回一个`Movie`数组而不仅仅是一个`Movie`。以下是`fetchByField`方法的实现：

```ts
public fetchByField(field: MovieFields, value: any) :Promise<Movie[]>{
       console.log('fetchByField', field, value);
       return this.http.get(this.moviesUrl)
          .map(res => res.json().movies.filter(
              (movie)=>{
                  return (movie[MovieFields[field]] === value)
              })
         )
         .toPromise()
         /**
          * Map the JSON movie items to the Movie Model
         */
        .then((jsonMovies:any[]) => {
           console.log("map",jsonMovies);
           let movies:Movie[] = [];
           for (var i = 0; i < jsonMovies.length; i++) {
               movies.push(
                  new Movie(
                      jsonMovies[i].movie_id,
                      jsonMovies[i].title,
                      jsonMovies[i].phase,
                      jsonMovies[i].category_name,
                      jsonMovies[i].release_year,
                      jsonMovies[i].running_time,
                      jsonMovies[i].rating_name,
                      jsonMovies[i].disc_format_name,
                      jsonMovies[i].number_discs, 
                      jsonMovies[i].viewing_format_name, 
                      jsonMovies[i].aspect_ratio_name, 
                      jsonMovies[i].status,
                      jsonMovies[i].release_date, 
                      jsonMovies[i].budget, 
                      jsonMovies[i].gross,
                      jsonMovies[i].time_stamp
                  )
                )
              }
              return movies;  
           });
 }
```

为了实现这一点，我将`flatMap`替换为了一个经典的 map 作为第一个操作。在 map 中，我直接获取 JSON `movie`数组的引用并应用字段过滤。结果被转换为 promise 并在`then`中处理。`then`操作接收到一个 JSON `movies`数组并将其转换为一个`Movie`数组。这产生了一个被承诺的结果返回给调用者的`Movie`数组。在`AngularObservableAppComponent`中的调用也有些不同，因为我们现在期望一个数组：

```ts

 this.IMDBAPI.fetchByField(MovieFields.release_year, 2015).then(
     value => {
        this.movies = value;
        console.log("Component", value)
     },
     error => this.error = true
 )
```

使用 `Promise` 的另一种方式是通过 fork/join 范式。实际上，可以启动许多进程(fork)，并等待所有 promise 完成后再将聚合结果发送给调用者(join)。因此，相对来说很容易增强 `fetchByField` 方法,因为它可以使用逻辑 or 在多个字段中运行。以下是我们需要实现这个逻辑 or 的三个非常简短的方法:

```ts

 /**
 * Private member storing pending promises
 */
 private promises:Promise<Movie[]>[] = [];
 /**
  * Register one promise for field/value. Returns this
  * for chaining i.e.
  *
  * byField(Y, X)
  * .or(...)
  * .fetch()
  *
  * @param {MovieFields} field
  * @param {any}         value
  * @return {IMDBAPIService}
  */
public byField(field:MovieFields, value:any):IMDBAPIService{

   this.promises.push(this.fetchByField(field, value));
   return this; 
 }
 /**
 * Convenient method to make the calls more readable, i.e.
 *
 * byField(Y, X)
 * .or(...)
 * .fetch()
 *
 * instead of
 *
 * byField(Y, X)
 * .byField(...)
 * .fetch()
 *
 * @param {MovieFields} field
 * @param {any}         value
 * @return {IMDBAPIService}
 */
public or(field:MovieFields, value:any):IMDBAPIService{
 return this.byField(field, value);

}

 /** 
  * Join all the promises and return the aggregated result. 
  * 
  *@return {Promise<Movie[]>} 
  */
public fetch():Promise<Movie[]>{
 return Promise.all(this.promises).then((results:any) => {
         //result is an array of movie arrays. One array per
         //promise. We need to flatten it.
         return [].concat.apply([], results);
 }); 
}
```

这里我提供了两种便捷的方法 `field` 和 `or`，它们以 `MovieField` 和一个值作为参数，创建一个新的 promise。它们都返回 `this` 以支持链式调用。`fetch` 方法将所有 promise 连接在一起，并合并它们各自的结果。在 `AngularObservableAppComponent` 中，我们现在有以下内容:

```ts

 this.IMDBAPI.byField(MovieFields.release_year, 2015) 
             .or(MovieFields.release_year, 2014)
             .or(MovieFields.phase, "Phase Two") 
             .fetch()
             .then (
                value => {
                    this.movies = value;
                    console.log("Component", value)
                },
            error => this.error = true
        );
```

这很容易阅读和理解，同时保持了 Angular 2 的所有异步能力。

# 总结

在本章中，我们学习了如何使用一些最有用的经典模式：组件、单例和观察者。我们学会了如何在纯 TypeScript 中以及使用 Angular 2 构建块来实现。本章的代码可以在这里找到：[`github.com/MathieuNls/Angular-Design-Patterns-and-Best-Practices/tree/master/chap4`](https://github.com/MathieuNls/Angular-Design-Patterns-and-Best-Practices/tree/master/chap4)。

在下一章中，我们将专注于模式，旨在简化和组织我们的 Angular 2 应用程序中的导航。
