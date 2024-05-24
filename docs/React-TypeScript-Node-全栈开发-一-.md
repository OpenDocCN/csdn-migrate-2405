# React TypeScript Node 全栈开发（一）

> 原文：[`zh.annas-archive.org/md5/F7C7A095AD12AA62E0C9F5A1E1F6F281`](https://zh.annas-archive.org/md5/F7C7A095AD12AA62E0C9F5A1E1F6F281)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

根据 GitHub，这是全球最大的开源软件仓库，JavaScript 仍然是世界上最流行的编程语言。比任何其他语言都有更多的项目是用 JavaScript 编写的。甚至通常不与 Web 相关的项目，如机器学习和加密货币，也经常使用 JavaScript。

JavaScript 编程语言非常强大和有能力，但除了语言本身，还有一些框架，包括 React 和 Node，可以增强语言的功能，使其变得更好。此外，TypeScript 现在已成为进行大型 JavaScript 项目的标准。它提供了使 JavaScript 编码更加高效和更适合大型应用程序的语言特性。

现代 Web 开发在多年来取得了巨大进步。过去，客户端代码通常意味着静态的 HTML 和 CSS，可能还有少量的 JavaScript。而后端通常是用完全不同的语言编写的，比如 PHP 或 CGI 脚本。然而，现在通常使用 JavaScript 及其相关框架来编写从客户端到服务器的整个应用程序。只使用一种语言来编写我们的应用程序在开发过程中提供了巨大的好处。此外，可用的强大和成熟的框架使得 JavaScript 全栈编程与任何其他平台竞争力。

在这本书中，我们将学习如何利用 JavaScript 的力量来构建完整的全栈 Web 应用程序。我们将使用 TypeScript 来增强这种力量，TypeScript 是另一种功能强大的前十语言。然后，我们将使用诸如 React、Redux、Node、Express 和 GraphQL 等框架来构建一个现实的、完全功能的最佳实践 Web 应用程序，这将为您提供构建现代全栈 Web 应用程序所需的所有知识。一旦我们的应用程序完成，我们将部署到 AWS 云服务，这是全球最受欢迎和功能丰富的云服务提供商。

# 这本书适合谁

这本书是为那些想要超越前端 Web 开发，进入全栈 Web 开发世界的 Web 开发人员而写的，通过学习现代 Web 技术以及它们如何结合在一起。在开始阅读本 Web 开发书之前，需要对 JavaScript 编程有很好的理解。

# 本书涵盖内容

[*第一章*]《理解 TypeScript》解释了 TypeScript 是什么，以及它为何在大型应用程序开发中是理想的选择。

[*第二章*]《探索 TypeScript》深入探讨了 TypeScript。我们将探索其特性，包括静态类型，以及为什么这些特性比 JavaScript 更好。我们还将研究面向对象编程的应用程序设计以及 TypeScript 特性如何实现这一重要的编程范式。

[*第三章*]《使用 ES6+功能构建更好的应用程序》回顾了每个开发人员都需要了解的 JavaScript 的重要功能。我们将重点关注 ES6 及更高版本中新增的最新功能。

[*第四章*]《学习单页应用程序概念以及 React 如何实现它们》解释了网站是如何构建的，并专注于单页应用程序风格的应用程序。然后我们将介绍 React 以及 React 如何用于创建单页应用程序。

[*第五章*]《使用 Hooks 进行 React 开发》深入探讨了 React。我们将了解旧的类式编写 React 应用程序的局限性，以及学习 Hooks 和函数组件以及它们如何改进旧的类式。

*第六章*，*使用 create-react-app 设置我们的项目并使用 Jest 进行测试*，描述了用于开发 React 应用程序的现代方法。这包括创建 React 项目的标准`create-react-app`，以及使用 Jest 和 testing-library 进行客户端测试。

*第七章*，*学习 Redux 和 React Router*，涵盖了 Redux 和 React Router，帮助我们构建 React 应用程序。自 React 诞生以来，这两个框架一直是管理状态和路由的首选框架。

*第八章*，*学习使用 Node.js 和 Express 进行服务器端开发*，涵盖了 Node 和 Express。Node 是使 JavaScript 服务器应用程序成为可能的基础运行时。Express 是围绕 Node 的框架，使使用 Node 构建强大的服务器端应用程序变得容易。

*第九章*，*GraphQL 是什么？*，回顾了 GraphQL 是什么，以及它如何使用数据模式来帮助构建 Web API。

*第十章*，*使用 TypeScript 和 GraphQL 依赖项设置 Express 项目*，解释了如何使用 TypeScript、Express、GraphQL 和 Jest 创建一个生产质量的服务器端项目进行测试。

*第十一章*，*我们将学到什么-在线论坛应用*，讨论了我们将要构建的应用程序。我们将回顾其特性，以及构建这样一个应用程序将如何帮助我们更详细地了解 Web 开发。

*第十二章*，*构建我们在线论坛应用的 React 客户端*，解释了如何使用 React 开始编写我们应用程序的客户端。我们将使用函数组件、Hooks 和 Redux 来开始构建我们的屏幕。

*第十三章*，*使用 Express 和 Redis 设置会话状态*，探讨了会话状态是什么，以及如何使用 Redis 创建服务器的会话，Redis 是世界上最强大的内存数据存储。我们还开始使用 Express 编写我们的服务器。

*第十四章*，*使用 TypeORM 设置 Postgres 和存储库层*，解释了如何在 Postgres 中为我们的应用程序创建数据库，以及如何使用称为存储库层的强大设计技术访问它。

*第十五章*，*添加 GraphQL 模式-第一部分*，开始将 GraphQL 集成到我们的应用程序中。我们将构建我们的模式并添加我们的查询和变异。我们还将开始向我们的 React 前端添加 GraphQL Hooks。

*第十六章*，*添加 GraphQL 模式-第二部分*，通过完成将 GraphQL 集成到我们的客户端和服务器中的工作来完成我们的应用程序。

*第十七章*，*将应用程序部署到 AWS*，将我们完成的应用程序部署到 AWS 云服务。我们将使用 Ubuntu Linux 和 NGINX 来托管我们的服务器和客户端代码。

# 为了充分利用本书

你应该至少有一年或更多的编程经验，至少掌握一种现代语言，并且具有一些构建应用程序的基础知识，尽管这不一定是为网络而做的。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Preface_1.jpg)

本书将提供逐步使用或安装这些依赖项的说明。然而，这个列表确实给出了一些所需的想法。应用程序源代码将是最终完成版本的应用程序。本书将包括任何中间代码。

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

理想情况下，您应该始终努力自己输入代码，因为这将帮助您记住代码，并让您在出现问题时有所经验。

# 下载示例代码文件

您可以从 GitHub 上的[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)下载本书的示例代码文件。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这里有一个例子：“在`src`文件夹中创建一个名为`Home.tsx`的新文件，并添加以下代码。”

代码块设置如下：

```ts
let a = 5;
let b = '6';
console.log(a + b);
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```ts
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下方式编写：

```ts
 npm install typescript
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这里有一个例子：“从**管理**面板中选择**系统信息**。”

提示或重要说明

会以这种方式出现。


# 第一部分：了解 TypeScript 及其如何改进您的 JavaScript

本节将为您概述 TypeScript 的优势及其最重要的语言特性。我们还将介绍 ES6 最重要的特性，以及如何提高代码质量和可读性。

本节包括以下章节：

+   *第一章*，*了解 TypeScript*

+   *第二章*，*探索 TypeScript*

+   *第三章*，*使用 ES6+特性构建更好的应用程序*


# 第一章：理解 TypeScript

JavaScript 是一种非常流行和强大的语言。根据 GitHub 的数据，它是世界上最流行的语言（是的，甚至比 Python 更多），ES6+中的新功能继续增加有用的功能。然而，对于大型应用程序开发来说，其功能集被认为是不完整的。这就是为什么 TypeScript 被创建的原因。

在本章中，我们将了解 TypeScript 语言，它是如何创建的，以及它为 JavaScript 开发人员提供了什么价值。我们将了解 Microsoft 在创建 TypeScript 时使用的设计哲学，以及为什么这些设计决策为大型应用程序开发提供了重要的支持。

我们还将看到 TypeScript 如何增强和改进 JavaScript。我们将比较 JavaScript 编写代码的方式与 TypeScript 的区别。TypeScript 具有丰富的前沿功能，有利于开发人员。其中最重要的是静态类型和**面向对象编程**（**OOP**）能力。这些功能可以使代码质量更高，更易于维护。

通过本章结束时，您将了解 JavaScript 的一些限制，这些限制使其在大型项目中难以使用。您还将了解 TypeScript 如何填补其中的一些空白，并使编写大型、复杂的应用程序更容易，更不容易出错。

在本章中，我们将涵盖以下主要主题：

+   什么是 TypeScript？

+   为什么需要 TypeScript？

# 技术要求

为了充分利用本章，您应该对 JavaScript 版本 ES5 或更高版本有基本了解，并具有使用 JavaScript 框架构建 Web 应用程序的经验。您还需要安装 Node 和 JavaScript 代码编辑器，如**Visual Studio Code**（**VSCode**）。

您可以在[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)找到本章的 GitHub 存储库。使用`Chap1`文件夹中的代码。

# 什么是 TypeScript？

TypeScript 实际上是两种不同但相关的技术 - 一种语言和一种编译器：

+   该语言是一种功能丰富的静态类型编程语言，为 JavaScript 添加了真正的面向对象的能力。

+   编译器将 TypeScript 代码转换为本机 JavaScript，但也为程序员在编写代码时提供了帮助，减少了错误。

TypeScript 使开发人员能够设计更高质量的软件。语言和编译器的结合增强了开发人员的能力。通过使用 TypeScript，开发人员可以编写更易于理解和重构、包含更少错误的代码。此外，它通过在开发过程中强制修复错误，为开发工作流程增加了纪律性。

TypeScript 是一种开发时技术。它没有运行时组件，也没有任何 TypeScript 代码在任何机器上运行。相反，TypeScript 编译器将 TypeScript 转换为 JavaScript，然后部署和运行该代码在浏览器或服务器上。微软可能考虑开发 TypeScript 的运行时。然而，与操作系统市场不同，微软并不控制 ECMAScript 标准组织（决定 JavaScript 每个版本中将包含什么内容的组织）。因此，获得该组织的支持将是困难且耗时的。因此，微软决定创建一个工具，增强 JavaScript 开发人员的生产力和代码质量。

那么，如果 TypeScript 没有运行时，开发人员如何获得运行代码呢？TypeScript 使用一种称为**转译**的过程。**转译**是一种将一种语言的代码“编译”或转换为另一种语言的方法。这意味着所有 TypeScript 代码最终都会在最终部署和运行之前转换为 JavaScript 代码。

在本节中，我们已经学习了 TypeScript 是什么以及它是如何工作的。在下一节中，我们将学习为什么这些特性对于构建大型复杂应用程序是必要的。

# 为什么需要 TypeScript？

JavaScript 编程语言是由 Brendan Eich 创建的，并于 1995 年添加到 Netscape 浏览器中。从那时起，JavaScript 取得了巨大的成功，现在被用于构建服务器和桌面应用程序。然而，这种流行和普及也成为了一个问题和一个好处。随着越来越大的应用程序被创建，开发人员开始注意到这种语言的局限性。

大型应用程序开发需要比 JavaScript 最初创建的浏览器开发更多的需求。在高层次上，几乎所有大型应用程序开发语言，比如 Java、C++、C#等，都提供静态类型和面向对象编程能力。在本节中，我们将讨论静态类型相对于 JavaScript 动态类型的优势。我们还将了解面向对象编程，以及为什么 JavaScript 的面向对象编程方法对于大型应用程序来说太有限。

但首先，我们需要安装一些包和程序来允许我们的示例。要做到这一点，请按照以下说明操作：

1.  首先让我们安装 Node。你可以从这里下载 Node：[`nodejs.org/`](https://nodejs.org/)。Node 给我们提供了`npm`，这是一个 JavaScript 依赖管理器，它将允许我们安装 TypeScript。我们将在*第八章*中深入学习 Node，*使用 Node.js 和 Express 学习服务器端开发*。

1.  安装 VSCode。它是一个免费的代码编辑器，其高质量和丰富的功能使其迅速成为了在任何平台上编写 JavaScript 代码的标准开发应用程序。你可以使用任何你喜欢的代码编辑器，但我会在本书中广泛使用 VSCode。

1.  在你的个人目录中创建一个名为`HandsOnTypeScript`的文件夹。我们将把所有项目代码保存在这个文件夹中。

重要提示

如果你不想自己输入代码，你可以按照*技术要求*部分提到的方式下载完整的源代码。

1.  在`HandsOnTypeScript`中，创建另一个名为`Chap1`的文件夹。

1.  打开 VSCode，转到**文件** | **打开**，然后打开你刚创建的**Chap1**文件夹。然后，选择**视图** | **终端**，在你的 VSCode 窗口内启用终端窗口。

1.  在终端中输入以下命令。这个命令将初始化你的项目，以便它可以接受`npm`包依赖。你需要这个因为 TypeScript 是作为`npm`包下载的：

```ts
npm init
```

你应该看到一个像这样的屏幕：

![图 1.1 – npm 初始化屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure1.1_B15508.jpg)

图 1.1 – npm 初始化屏幕

你可以接受所有提示的默认值，因为我们现在只安装 TypeScript。

1.  使用以下命令安装 TypeScript：

```ts
npm install typescript
```

在所有项目都安装完成后，你的 VSCode 屏幕应该看起来像这样：

![图 1.2 – 安装完成后的 VSCode](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure1.2_B15508.jpg)

图 1.2 – 安装完成后的 VSCode

我们已经完成了安装和设置环境。现在，我们可以看一些示例，这些示例将帮助我们更好地理解 TypeScript 的好处。

## 动态与静态类型

每种编程语言都有并且使用类型。类型只是描述对象并且可以被重用的一组规则。JavaScript 是一种动态类型语言。在 JavaScript 中，新变量不需要声明它们的类型，即使在设置后，它们也可以被重置为不同的类型。这个特性为语言增加了灵活性，但也是许多 bug 的根源。

TypeScript 使用了一个更好的替代方案叫做**静态类型**。静态类型强制开发人员在创建变量时提前指定变量的类型。这消除了歧义，并消除了许多类型之间的转换错误。在接下来的步骤中，我们将看一些动态类型的缺陷示例，以及 TypeScript 的静态类型如何消除它们：

1.  在`Chap1`文件夹的根目录下，让我们创建一个名为`string-vs-number.ts`的文件。`.ts`文件扩展名是 TypeScript 特有的扩展名，允许 TypeScript 编译器识别该文件并将其转译为 JavaScript。接下来，将以下代码输入到文件中并保存：

```ts
let a = 5;
let b = '6';
console.log(a + b);
```

1.  现在，在终端中，输入以下内容：

```ts
tsc is the command to execute the TypeScript compiler, and the filename is telling the compiler to check and transpile the file into JavaScript. 
```

1.  一旦你运行了`tsc`命令，你应该会在同一个文件夹中看到一个新文件`string-vs-number.js`。让我们运行这个文件：

```ts
node command acts as a runtime environment for the JavaScript file to run. The reason why this works is that Node uses Google's Chrome browser engine, V8, to run JavaScript code. So, once you have run this script, you should see this:

```

将一个数字变量转换为字符串，并将其附加到变量 b。这种情况在现实世界的代码中似乎不太可能发生，但如果不加以检查，它可能会发生，因为在 Web 开发中，大多数来自 HTML 的输入都以字符串形式输入，即使用户输入的是一个数字。

```ts

```

1.  现在，让我们将 TypeScript 的静态类型引入到这段代码中，看看会发生什么。首先，让我们删除`.js`文件，因为 TypeScript 编译器可能会认为`a`和`b`变量有两个副本。看看这段代码：

```ts
let a: number = 5;
let b: number = '6';
console.log(a + b);
```

1.  如果你在这段代码上运行`tsc`编译器，你会得到错误`Type "'6'" is not assignable to the type 'number'`。这正是我们想要的。编译器告诉我们代码中有一个错误，并阻止了成功编译。由于我们指示这两个变量应该是数字，编译器会检查并在发现不符合时进行投诉。因此，如果我们修复这段代码并将`b`设置为一个数字，让我们看看会发生什么：

```ts
let a: number = 5;
let b: number = 6;
console.log(a + b);
```

1.  现在，如果你运行编译器，它将成功完成，并且运行 JavaScript 将得到值`11`：

![图 1.3 - 有效数字相加](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure1.3_B15508.jpg)

图 1.3 - 有效数字相加

很好，当我们错误地设置`b`时，TypeScript 捕获了我们的错误，并阻止了它在运行时被使用。

让我们看另一个更复杂的例子，因为它就像你可能在更大的应用代码中看到的那样：

1.  让我们创建一个名为`test-age.ts`的新`.ts`文件，并将以下代码添加到其中：

```ts
function canDrive(usr) {    
    console.log("user is", usr.name);     

    if(usr.age >= 16) {
        console.log("allow to drive");
    } else {
        console.log("do not allow to drive");
    }
} 

const tom = { 
    name: "tom"
} 
canDrive (tom); 
```

如你所见，代码中有一个函数，用于检查用户的年龄，并根据年龄确定他们是否被允许驾驶。在函数定义之后，我们看到创建了一个用户，但没有年龄属性。假设开发人员希望稍后根据用户输入填写该属性。现在，在用户创建下面，调用了`canDrive`函数，并声称用户不被允许驾驶。如果事实证明用户`tom`已经超过 16 岁，并且该函数触发了基于用户年龄采取其他行动，显然这可能会导致一系列问题。

在 JavaScript 中有方法来解决这个问题，或者至少部分解决。我们可以使用`for`循环来迭代用户对象的所有属性键名，并检查是否有`age`名称。然后，我们可以抛出异常或使用其他错误处理程序来处理此问题。但是，如果我们必须在每个函数中都这样做，那么效率会很低，负担也会很重。此外，我们将在代码运行时进行这些检查。显然，对于这些错误，我们更希望在它们传递给用户之前捕获它们。TypeScript 为这个问题提供了一个简单的解决方案，并在代码甚至进入生产之前捕获错误。看看下面更新的代码：

```ts
interface User {
    name: string;
    age: number;
}

function canDrive(usr: User) {     
    console.log("user is", usr.name);     

    if(usr.age >= 16) {
        console.log("allow to drive");
    } else {
        console.log("do not allow to drive");
    }
} 

const tom = { 
    name: "tom"
} 
canDrive (tom); 
```

让我们来看一下这个更新后的代码。在顶部，我们看到一个叫做接口的东西，它被命名为`User`。在 TypeScript 中，接口是一种可能的类型。我将在后面的章节中详细介绍接口和其他类型，但现在，让我们看一下这个例子。`User`接口有我们需要的两个字段：`name`和`age`。现在，在下面，我们看到我们的`canDrive`函数的`usr`参数有一个冒号和`User`类型。这被称为类型注解，它意味着我们告诉编译器只允许将`User`类型的参数传递给`canDrive`。因此，当我尝试使用 TypeScript 编译这段代码时，编译器抱怨说在调用`canDrive`时，传入的参数缺少`age`，因为我们的`tom`对象没有这个属性：

![图 1.4 – canDrive 错误](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure1.4_B15508.jpg)

图 1.4 – canDrive 错误

1.  因此，编译器再次捕捉到了我们的错误。让我们通过给`tom`一个类型来解决这个问题：

```ts
const tom: User = { 
    name: "tom"
} 
```

1.  如果我们给`tom`一个`User`类型，但没有添加必需的`age`属性，我们会得到以下错误：

```ts
age property, the error goes away and our canDrive function works as it should. Here's the final working code:

```

用户接口 {

name: string;

age: number;

}

function canDrive(usr: User) {

console.log("user is", usr.name);

if(usr.age >= 16) {

console.log("allow to drive");

} else {

console.log("do not allow to drive");

}

}

// 假设过了一段时间，其他人使用了 canDrive 函数

const tom: User = {

name: "tom",

age: 25

}

canDrive(tom);

```ts

This code provides the required `age` property in the `tom` variable so that when `canDrive` is executed, the check for `usr.age` is done correctly and the appropriate code is then run.
```

一旦进行了这个修复并且重新运行代码，这个输出的截图如下：

![图 1.5 – canDrive 成功结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure1.5_B15508.jpg)

图 1.5 – canDrive 成功结果

在本节中，我们了解了动态类型的一些缺陷，以及静态类型如何帮助消除和防止这些问题。静态类型消除了代码中的歧义，对编译器和其他开发人员都有帮助。这种清晰度可以减少错误，并产生更高质量的代码。

## 面向对象编程

JavaScript 被称为面向对象的语言。它确实具有一些其他面向对象语言的能力，比如继承。然而，JavaScript 的实现在可用语言特性和设计方面都是有限的。在本节中，我们将看一下 JavaScript 是如何进行面向对象编程的，以及 TypeScript 如何改进 JavaScript 的能力。

首先，让我们定义一下面向对象编程是什么。面向对象编程有四个主要原则：

+   封装

+   抽象

+   继承

+   多态

让我们来复习一下每一个。 

### 封装

封装的另一种说法是信息隐藏。在每个程序中，你都会有数据和函数，允许你对这些数据进行操作。当我们使用封装时，我们将这些数据放入一种容器中。在大多数编程语言中，这个容器被称为类，基本上，它保护数据，使得容器外部无法修改或查看它。相反，如果你想使用数据，必须通过容器对象控制的函数来完成。这种处理对象数据的方法允许严格控制代码中发生的数据变化，而不是分散在大型应用程序中的许多位置，这可能会使维护变得困难。

有些对封装的解释主要集中在将成员分组在一个共同的容器内。然而，在封装的严格意义上，信息隐藏，JavaScript 没有内置这种能力。对于大多数面向对象编程语言，封装需要通过语言设施明确隐藏成员的能力。例如，在 TypeScript 中，您可以使用`private`关键字，以便属性在其类外部无法看到或修改。现在，虽然可以通过各种变通方法模拟成员的私有性，但这并不是原生代码的一部分，并增加了额外的复杂性。TypeScript 通过`private`等访问修饰符原生支持封装。

重要提示

ECMAScript 2020 将支持类字段的私有性。然而，由于这是一个较新的功能，在撰写本文时，并不是所有浏览器都支持。

### 抽象

抽象与封装有关。在使用抽象时，您隐藏了数据管理的内部实现，并为外部代码提供了更简化的接口。主要是为了实现“松耦合”。这意味着希望负责一组数据的代码独立于其他代码并分开。这样，就可以在应用程序的一个部分更改代码，而不会对另一个部分的代码造成不利影响。

大多数面向对象编程语言的抽象需要使用机制来提供对对象的简化访问，而不会揭示该对象的内部工作方式。对于大多数语言，这要么是一个接口，要么是一个抽象类。我们将在后面的章节中更深入地介绍接口，但现在，接口就像没有实际工作代码的类。您可以将它们视为仅显示对象成员的名称和类型，但隐藏它们的工作方式。这种能力在产生先前提到的“松耦合”并允许更轻松地修改和维护代码方面非常重要。JavaScript 不支持接口或抽象类，而 TypeScript 支持这两个特性。

### 继承

继承是关于代码重用的。例如，如果您需要为几种类型的车辆（汽车、卡车和船）创建对象，为每种车辆类型编写不同的代码是低效的。最好创建一个具有所有车辆的核心属性的基本类型，然后在每种特定的车辆类型中重用该代码。这样，我们只需编写一次所需的代码，并在每种车辆类型中共享它。

JavaScript 和 TypeScript 都支持类和继承。如果您不熟悉类，类是一种存储一组相关字段的类型，还可以具有可以操作这些字段的函数。JavaScript 通过使用原型继承系统来支持继承。基本上，这意味着在 JavaScript 中，特定类型的每个对象实例共享单个核心对象的相同实例。这个核心对象是原型，原型上创建的任何字段或函数都可以在各个对象实例之间访问。这是一种节省资源（如内存）的好方法，但它没有 TypeScript 中继承模型的灵活性或复杂性。

在 TypeScript 中，类可以继承自其他类，但也可以继承自接口和抽象类。由于 JavaScript 没有这些特性，相比之下，它的原型继承是有限的。此外，JavaScript 没有直接从多个类继承的能力，这是另一种称为多重继承的代码重用方法。但是 TypeScript 允许使用混入进行多重继承。我们将在以后深入研究所有这些特性，但基本上，关键是 TypeScript 具有更强大的继承模型，允许更多种类的继承，因此有更多的代码重用方式。

### 多态性

多态性与继承有关。在多态性中，可以创建一个对象，该对象可以设置为任何可能从相同基本谱系继承的多种类型之一。这种能力对于需要的类型不是立即可知的情况很有用，但可以在运行时根据适当的情况进行设置。

这个特性在面向对象编程代码中的使用频率比一些其他特性要低，但仍然可以很有用。在 JavaScript 的情况下，没有直接支持多态的语言特性，但由于它的动态类型，可以相当好地模拟（一些 JavaScript 爱好者会强烈反对这种说法，但请听我说）。

让我们来看一个例子。可以使用 JavaScript 类继承来创建一个基类，并有多个类从这个父基类继承。然后，通过使用标准的 JavaScript 变量声明，不指示类型，我们可以在运行时将类型实例设置为适当的继承类。我发现的问题是，没有办法强制变量成为特定的基本类型，因为在 JavaScript 中没有办法声明类型，因此在开发过程中没有办法强制只有从一个基本类型继承的类。因此，再次，你必须诉诸于解决方法，比如在运行时使用`instanceof`关键字来测试特定类型，以尝试强制类型安全。

在 TypeScript 的情况下，静态类型默认开启，并在变量首次创建时强制类型声明。此外，TypeScript 支持接口，可以由类实现。因此，声明一个变量为特定接口类型会强制所有实例化为该变量的类都是相同接口的继承者。同样，这都是在代码部署之前的开发时间完成的。这个系统比 JavaScript 中的系统更加明确、可强制执行和可靠。

在本节中，我们已经了解了面向对象编程及其在大型应用程序开发中的重要性。我们也了解了为什么 TypeScript 的面向对象编程能力比 JavaScript 更加强大和功能丰富。

# 总结

在本章中，我们介绍了 TypeScript，并了解了它为什么被创建。我们了解了为什么类型安全和面向对象编程能力对于构建大型应用程序如此重要。然后，我们看了一些比较动态类型和静态类型的例子，并了解了为什么静态类型可能是编写代码的更好方式。最后，我们比较了两种语言之间的面向对象编程风格，并了解了为什么 TypeScript 拥有更好、更有能力的系统。本章的信息使我们对 TypeScript 的好处有了一个良好的高层次概念理解。

在下一章中，我们将深入研究 TypeScript 语言。我们将更多地了解类型，并调查 TypeScript 的一些最重要的特性，比如类、接口和泛型。这一章应该为您在 JavaScript 生态系统中使用各种框架和库奠定坚实的基础。


# 第二章：探索 TypeScript

在本章中，我们将深入了解 TypeScript 语言。我们将学习 TypeScript 的显式类型声明语法，以及 TypeScript 中许多内置类型及其用途。

我们还将学习如何创建自己的类型，并构建遵循面向对象原则的应用程序。最后，我们将回顾语言中添加的一些最新功能，例如可选链和 nullish 合并。

通过本章结束时，您将对 TypeScript 语言有很好的理解，这将使您能够轻松阅读和理解现有的 TypeScript 代码。您还将了解足够多关于该语言，以便编写实现应用程序目标并且可靠的高质量代码。

在本章中，我们将涵盖以下主要主题：

+   什么是类型？

+   探索 TypeScript 类型

+   理解类和接口

+   理解继承

+   学习泛型

+   学习最新功能和配置编译器

# 技术要求

本章的要求与*第一章*中的*理解 TypeScript*相同。您应该对 JavaScript 和 Web 技术有基本的了解。您将再次使用 Node 和**Visual Studio Code**（**VSCode**）。

GitHub 存储库再次位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap2`文件夹中的代码。

在继续之前，让我们为本章做好准备：

1.  转到您的`HandsOnTypeScript`文件夹并创建一个名为`Chap2`的新文件夹。

1.  打开 VSCode 并转到您刚创建的`Chap2`文件夹。然后，选择**视图** | **终端**并在 VSCode 窗口内启用终端窗口。

1.  输入`npm init`命令，就像*第一章*中的*理解 TypeScript*一样，来初始化`npm`项目，并接受所有默认设置。

1.  输入`npm install typescript`命令，就像*第一章*中的*理解 TypeScript*一样，来安装 TypeScript。

现在我们准备好开始了。

# 什么是类型？

**类型**是一组可重复使用的规则。类型可以包括属性和函数（能力）。它也可以被共享和重复使用。当您重用一个类型时，您正在创建它的**实例**。这意味着您正在创建您的类型的一个示例，该示例具有属性的特定值。在 TypeScript 中，正如其名称所示，类型非常重要。这是语言首次创建的主要原因。让我们看看 TypeScript 中类型是如何工作的。

## 类型如何工作？

如前所述，JavaScript 确实具有类型。数字、字符串、布尔值、数组等在 JavaScript 中都是类型。然而，在声明时这些类型并没有被明确设置；它们只是在运行时被推断出来。在 TypeScript 中，类型通常在声明时设置。也可以允许编译器推断您的类型。然而，编译器选择的类型可能不是您想要的，因为它并不总是明显的。除了 JavaScript 支持的类型外，TypeScript 还具有其自己独特的类型，并且还允许您创建自己的类型。

关于 TypeScript 中类型的第一件事是，它们是由它们的形状而不是它们的类型名称处理的。这意味着类型的名称对于 TypeScript 编译器并不重要，但它具有的属性及其类型是重要的。

让我们看一个例子：

1.  创建一个名为`shape.ts`的文件，并添加以下代码：

```ts
class Person {
    name: string;
}	
const jill: { name: string } = {
    name: "jill"
};
const person: Person = jill;
console.log(person);
```

您应该注意到的第一件事是，我们有一个名为`Person`的类，其中有一个名为`name`的属性。在下面，您会看到我们有一个名为`jill`的变量，它是`{ name: string }`类型。这有点奇怪，因为您可以看到，这种类型声明不是实际的类型名称；它更像是类型定义。但是编译器没有任何问题，也没有抱怨。在 TypeScript 中，可以同时定义和声明类型。此外，在下面，您可以看到我们有另一个名为`person`的变量，它是`Person`类型，我们将其设置为`jill`。同样，编译器没有抱怨，一切似乎都很好。

1.  让我们编译此代码并运行它，看看会发生什么。在终端中输入以下行：

```ts
tsc shape
node shape
```

运行命令后，您应该会看到以下内容：

![图 2.1 - shape.ts 输出](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.01_B15508.jpg)

图 2.1 - shape.ts 输出

如您所见，代码编译和运行都没有问题。这表明在 TypeScript 中，编译器查看类型的形状，并不关心其名称。在后面的章节中，当我们更深入地挖掘 TypeScript 类型时，您将看到了解这种行为为何如此重要。

# 探索 TypeScript 类型

在本节中，我们将看一些 TypeScript 中可用的核心类型。使用这些类型将为您提供错误检查和编译器警告，可以帮助改进您的代码。它们还将向其他可能在您团队上的开发人员提供有关您意图的信息。因此，让我们继续看看这些类型是如何工作的。

## 任何类型

“任何”类型是一种动态类型，可以设置为任何其他类型。如果将变量声明为“任何”类型，这意味着可以将其设置为任何内容，并且稍后也可以将其重置为任何其他内容。实际上，它没有类型，因为编译器不会代表您检查它。这是关于“任何”的关键事实 - 编译器不会在开发时干预并警告您的问题。因此，如果可能的话，应避免使用“任何”类型。可能会觉得奇怪，一个旨在静态类型的语言会有这样的特性，但在某些情况下这是必要的。

在大型应用程序中，开发人员并不总是能够控制进入其代码的类型。例如，如果开发人员依赖于 Web 服务 API 调用来获取数据，那么数据的类型可能由其他团队或甚至完全不同的公司控制。在互操作期间，当代码依赖于来自不同编程语言的数据时，这也是真实的情况 - 例如，当公司在另一种语言中维护遗留系统的同时，又在不同的语言中构建其新系统。这些情况需要类型的灵活性和对类型系统的逃生舱。

重要的是不要滥用“任何”类型。您应该小心，只有在知道没有其他选择时才使用它 - 例如，当类型信息不清晰或可能会更改时。但是，有一些替代方案可以使用“任何”类型。根据情况，您可能可以使用接口、泛型、联合类型或“未知”类型。我们将在后面涵盖其余这些可能性，但现在让我们接下来讨论“未知”类型。

## 未知类型

“未知”类型是在 TypeScript 版本 3 中发布的一种类型。它类似于`any`，因为一旦声明了这种类型的变量，就可以将任何类型的值设置给它。随后可以将该值更改为任何其他类型。因此，我可以首先将我的变量设置为字符串类型，然后稍后将其设置为数字。但是，您不能调用其任何成员或将变量设置为另一个变量的值，而不首先检查其真正的类型。我将如下所示地展示一个示例。您可以在不首先检查其类型的情况下将“未知”设置为其他内容的唯一时间是将“未知”类型设置为另一个“未知”或“任何”类型时。

让我们看一个`any`的例子，然后我们将看到为什么`unknown`类型比使用`any`类型更可取（事实上，TypeScript 团队建议使用`unknown`）：

1.  首先，让我们看一下使用`any`存在的问题的一个例子。转到 VSCode，创建一个名为`any.ts`的文件，然后输入以下代码：

```ts
let val: any = 22;
val = "string value";
val = new Array();
val.push(33);
console.log(val);
```

如果您使用以下命令运行此代码，您将看到以下结果：

![图 2.2 – any 运行结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.02_B15508.jpg)

图 2.2 – any 运行结果

1.  由于`val`是`any`类型，我们可以将其设置为任何我们喜欢的值，然后调用`push`进入它，因为`push`是`Array`的一个方法。然而，这只是因为我们作为开发人员知道`Array`中有一个叫做`push`的方法。如果我们意外地调用了`Array`上不存在的东西会怎么样？用以下代码替换上一个代码：

```ts
let val: any = 22;
val = "string value";
val = new Array();
val.doesnotexist(33);
console.log(val);
```

1.  现在，再次运行 TypeScript 编译器：

```ts
any type causes the compiler to no longer check the type. Additionally, we also lost IntelliSense, the VSCode development time code highlighter and error checker. Only when we try and run the code do we get any indication that there is a problem, which is never what we want. If we now try and run the code, as shown next, it fails immediately:
```

![图 2.3 – any 失败](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.03_B15508.jpg)

图 2.3 – any 失败

对于这个简单的例子，这种错误不太可能发生，但在一个大型应用程序中，即使错误只是简单地拼错了一些东西，也很容易发生。

让我们看一个类似的使用`unknown`的例子：

1.  首先，注释掉`any.ts`中的代码，并删除`any.js`文件（因为我们将使用相同的变量名，如果不这样做，将会导致冲突错误）。

重要提示

稍后我们将学习一些称为命名空间的东西，它可以消除这些冲突，但现在介绍它们还为时过早。

1.  现在，创建一个名为`unknown.ts`的新文件，并将以下代码添加到其中：

```ts
let val: unknown = 22;
val = "string value";
val = new Array();
val.push(33);
console.log(val);
```

您会注意到 VSCode 给出了一个错误，立即抱怨`push`函数。这很奇怪，因为显然`Array`中有一个叫做`push`的方法。这种行为展示了`unknown`类型的工作原理。您可以将`unknown`类型视为一种标签，而不是一种类型，在该标签下是实际类型。然而，编译器无法自行确定类型，因此我们需要自己向编译器明确证明类型。

1.  我们使用类型守卫来证明`val`是某种类型：

```ts
let val: unknown = 22;
val = "string value";
val = new Array();
if (val instanceof Array) {
    val.push(33);
}
console.log(val);
```

如您所见，我们用一个测试来包装我们的`push`调用，以查看`val`是否是`Array`的一个实例。

1.  一旦我们证明这是真的，对`push`的调用就可以继续进行，如下所示：

![图 2.4 – 未知](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.04_B15508.jpg)

图 2.4 – 未知

这种机制有点繁琐，因为我们总是需要在调用成员之前测试类型。然而，与使用`any`类型相比，它仍然更可取，因为它由编译器检查，更安全。

## 交集和联合类型

还记得我们在本节开始时说过 TypeScript 编译器关注类型形状而不是名称吗？这种机制允许 TypeScript 支持所谓的`obj`，它与两种类型相关联。您会记得在 TypeScript 中，我们不仅可以将命名类型声明为变量的类型，还可以同时动态定义和声明类型。在以下代码中，每种类型都是不同的类型，但`&`关键字用于将两种类型合并为单一类型：

```ts
let obj: { name: string } & { age: number } = {
    name: 'tom',
    age: 25
}
```

让我们尝试运行这段代码，并在控制台上显示结果。创建一个名为`intersection.ts`的新文件，并将以下代码添加到其中：

```ts
let obj: { name: string } & { age: number } = {
    name: 'tom',
    age: 25
}
console.log(obj);
```

如果您编译并运行此代码，您将看到一个包含名称和年龄属性的对象：

![图 2.5 – 交集结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.05_B15508.jpg)

图 2.5 – 交集结果

如您所见，IntelliSense 和编译器都接受了该代码，最终对象具有两个属性。这是一个交集类型。

另一种类型类似，称为`union`类型。在联合的情况下，我们不是合并类型，而是以“或”的方式使用它们，即一个类型或另一个类型。让我们看一个例子。创建一个名为`union.ts`的新文件，并将以下代码添加到其中：

```ts
let unionObj: null | { name: string } = null;
unionObj = { name: 'jon'};
console.log(unionObj);
```

`unionObj`变量被声明为 null 类型或`{ name: string }`，通过使用`|`字符。如果编译并运行这段代码，你会看到它接受两种类型的值。这意味着类型值可以是 null，也可以是`{ name: string }`类型的对象。

## 文字类型

**文字**类型类似于联合类型，但它们使用一组硬编码的字符串或数字值。这是一个相当简单的字符串文字示例，相当容易理解。正如你所看到的，我们有一堆硬编码的字符串作为类型。这意味着只有与这些字符串中的任何一个相同的值才会被接受为文字变量：

```ts
let literal: "tom" | "linda" | "jeff" | "sue" = "linda";
literal = "sue";
console.log(literal);
```

正如你所看到的，编译器很高兴接收列表中的任何值，甚至重置它们。然而，它不会允许设置不在列表中的值。这将导致编译错误。让我们看一个例子。按照将文字变量重置为`john`的方式更新代码：

```ts
let literal: "tom" | "linda" | "jeff" | "sue" = "linda";
literal = "sue";
literal = "john";
console.log(literal);
```

在这里，我们将文字变量设置为`john`，编译会出现以下错误：

![图 2.6 – 一个文字错误](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.06_B15508.jpg)

图 2.6 – 一个文字错误

数字文字也可以以相同的方式进行，但值是由数字而不是字符串组成的。

## 类型别名

在 TypeScript 中，类型别名被非常频繁地使用。这只是一种为类型提供不同名称的方法，大多数情况下用于为某些复杂类型提供更短的简单名称。例如，这里是一个可能的用法：

```ts
type Points = 20 | 30 | 40 | 50;
let score: Points = 20;
console.log(score);
```

在这段代码中，我们将一个长数字文字类型赋予一个更短的名字`Points`。然后，我们声明`score`为`Points`类型，并给它一个值`20`，这是`Points`的可能值之一。当然，如果我们试图将分数设置为，比如，`99`，编译将失败。

另一个别名的例子是对象文字类型声明：

```ts
type ComplexPerson = {
    name: string,
    age: number,
    birthday: Date,
    married: boolean,
    address: string
}
```

由于类型声明非常长并且没有名称，例如类会有的，我们使用别名。在 TypeScript 中，类型别名可以用于包括函数和泛型在内的几乎任何类型，我们将在本章后面进一步探讨。

## 函数返回类型

为了完整起见，我想展示一个函数返回声明的例子。它与典型的变量声明非常相似。创建一个名为`functionReturn.ts`的新文件，并将其添加到其中：

```ts
function runMore(distance: number): number {
    return distance + 10;
}
```

`runMore`函数接受`number`类型的参数并返回一个数字。参数声明就像任何变量声明一样，但是函数返回在括号之后，并指示函数返回的类型。如果函数不返回任何内容，那么可以不声明返回的类型，或者可以声明`void`以更明确。

让我们看一个返回`void`的例子。注释掉`runMore`函数和控制台日志，然后编译并运行这段代码：

```ts
function eat(calories: number) {
    console.log("I ate " + calories + " calories");
}
function sleepIn(hours: number): void {
    console.log("I slept " + hours + " hours");
}
let ate = eat(100);
console.log(ate);
let slept = sleepIn(10);
console.log(slept);
```

这两个函数什么都不返回，只是将它们的参数写入控制台，如下所示：

![图 2.7 – 函数 void 结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.07_B15508.jpg)

图 2.7 – 函数 void 结果

正如你所看到的，它们的内部`console.log`语句确实运行。然而，尝试获取返回值会导致`undefined`，因为没有返回任何内容。

因此，函数返回类型声明与变量声明非常相似。现在，让我们看看如何将函数用作类型。

## 函数作为类型

在 TypeScript 中，类型也可以是整个函数签名。也就是说，在前面的部分中，我们看到函数可以接受基于类型的参数，并返回一个类型。嗯，这个定义也被称为函数签名。在 TypeScript 中，这个签名也可以作为对象属性的类型。

让我们看一个例子。创建一个名为`functionSignature.ts`的新文件，并将以下代码添加到其中：

```ts
type Run = (miles: number) => boolean;
let runner: Run = function (miles: number): boolean {
    if(miles > 10){
        return true;
    }
    return false;
}
console.log(runner(9));
```

第一行显示了我们将在此代码中使用的函数类型。`Run`类型别名只是为了使重用长函数签名更容易。实际的函数类型是`(miles: number) => boolean`。这看起来很奇怪，但它只是一个简化的函数签名。所以，唯一需要的是用括号表示参数，`=>`符号表示这是一个函数，然后是返回类型。

在函数定义行之后的代码中，您可以看到`runner`变量声明为`Run`类型，这又是一个函数。这个函数简单地检查人是否跑了超过 10 英里，并在他们跑了超过 10 英里时返回`true`，否则返回`false`。然后，在代码底部，`console.log`语句输出函数调用的结果。编译和运行后，您应该能看到这个结果：

![图 2.8 – 函数类型结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.08_B15508.jpg)

图 2.8 – 函数类型结果

正如您所见，使用参数`9`调用`runner`会使函数返回`false`，这是正确的。在静态类型中，能够对我们返回数据的所有方式进行类型标注是很重要的，这意味着不仅是变量，还有函数。

## 永远类型

这种类型一开始会听起来很奇怪。`never`类型用于指示一个永远不会返回（完成）的函数，或者一个没有设置为任何值的变量，甚至不是`null`。乍一看，这听起来像`void`类型。然而，它们根本不一样。在`void`中，函数确实返回，完全意义上的返回，它只是不返回任何值（返回`undefined`，这是没有值）。在`never`的情况下，函数根本不会完成。现在，这似乎完全没有用，但实际上它对于指示意图是非常有用的。

再次，让我们看一个例子。创建一个名为`never.ts`的文件，并添加以下代码：

```ts
function oldEnough(age: number): never | boolean {
    if(age > 59) {
        throw Error("Too old!");
    }
    if(age <=18){
        return false;
    }
    return true;
}
```

正如您所见，这个函数返回一个`union`类型，要么是`never`，要么是布尔值。现在，我们只能指示布尔值，代码仍然可以工作。然而，在这个函数中，如果人的年龄超过一定年龄，我们会抛出一个错误，表明这是一个意外的`age`值。因此，由于封装是编写高质量代码的高级原则，明确指示函数可能失败而无需开发人员了解函数工作原理的内部细节是有益的。`never`提供了这种沟通。

在这一部分，我们学习了 TypeScript 中许多内置类型。我们能够看到为什么使用这些类型可以提高我们的代码质量，并帮助我们在编码周期的早期发现错误。在下一部分，我们将学习如何使用 TypeScript 来创建我们自己的类型，并遵循面向对象编程原则。

# 理解类和接口

我们已经在之前的部分简要地看过类和接口。让我们在这一部分深入了解一下，并看看为什么这些类型可以帮助我们编写更好的代码。一旦我们完成了这一部分，我们将更好地准备好编写更易读、可重用的代码，bug 更少。

## 类

基本上，TypeScript 中的类看起来就像 JavaScript 中的类。它们是一个相关字段和方法的容器，可以被实例化和重用。然而，TypeScript 中的类支持 JavaScript 不支持的封装的额外特性。让我们看一个例子。

创建一个名为`classes.ts`的新文件，并输入以下代码：

```ts
class Person {
    constructor() {}
    msg: string;
    speak() {
        console.log(this.msg);
    }
}
const tom = new Person();
tom.msg = "hello";
tom.speak();
```

如您所见，这个例子展示了一个简单的类，除了静态类型之外，它与 JavaScript 中看到的类似。首先，您为类命名，以便可以重用。接下来，您有一个构造函数，用于初始化类可能具有的任何字段，并为类实例进行任何其他设置（再次，实例只是我们的类的特定示例，具有自己字段的唯一值）。然后，您声明了一个名为`msg`的变量和一个名为`speak`的函数，该函数将`msg`的值写入控制台。然后，我们创建了我们类的一个实例。最后，我们将`msg`字段设置为`hello`的值，并调用`speak`方法。现在，让我们看一看 TypeScript 和 JavaScript 之间类的区别。

### 访问修饰符

我们之前提到面向对象开发的一个主要原则是封装，或者信息隐藏。好吧，如果我们再次清楚地看一下代码，我们并没有隐藏`msg`变量，因为它在类外是可见和可编辑的。所以，让我们看看 TypeScript 允许我们对此做些什么。让我们像这样更新代码：

```ts
class Person {
    constructor(private msg: string) {}

    speak() {
        console.log(this.msg);
    }
}
const tom = new Person("hello");
// tom.msg = "hello";
tom.speak();
```

如您所见，我们使用关键字`private`更新了构造函数。通过声明构造函数参数并添加访问修饰符，一行代码实际上做了几件事。首先，它告诉编译器类具有一个名为`msg`的`string`类型字段，应该是`private`的。通常，这种声明是在构造函数上方或下方的一行中分开完成的，这样做是完全有效的，但是 TypeScript 允许我们通过将其添加到构造函数参数中来使用快捷方式。此外，通过将其添加到构造函数中，您可以看到它允许我们在实例化时使用`new Person("hello")`调用来设置我们的`msg`字段。

现在，将某些东西设置为`private`实际上是做了什么？通过将字段设置为`private`，我们使其无法从类外部访问。其结果是`tom.msg = "hello"`不再起作用并引发错误。尝试删除注释并重新编译。您应该会看到此消息：

![图 2.9 - 类错误](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.09_B15508.jpg)

图 2.9 - 类错误

如您所见，它抱怨私有成员`msg`无法从类外部访问。现在，我们只将修饰符应用于字段，但请注意，访问修饰符可以应用于任何成员字段或函数。

重要提示

如前所述，ECMAScript 2020 将通过`#`符号支持私有字段。但是，目前浏览器对其支持有限，因为它只支持字段，并且这是一个全新的标准。

现在，让我们学习`readonly`修饰符。这个相对简单；它使字段在构造函数中设置一次后变为只读。因此，更新代码如下，并在`msg`字段的声明中添加`readonly`：

```ts
class Person {
    constructor(private readonly msg: string) {}

    speak () {
        this.msg = "speak " + this.msg;
        console.log(this.msg);
    }
}
const tom = new Person("hello");
// tom.msg = "hello";
tom.speak();
```

如果这样做，IntelliSense 会抱怨，因为在`speak`函数中，尽管`msg`已经通过构造函数设置了一次，我们仍然试图改变`msg`的值。

`private`和`readonly`访问修饰符并不是 TypeScript 中唯一的修饰符。还有几种其他类型的访问修饰符。但是，如果我们稍后在继承的上下文中解释它们，它们会更有意义。

### Getter 和 setter

类的另一个特性实际上在 TypeScript 和 JavaScript 中都可用：**getter**和**setter**：

+   **Getter**：允许在返回相关字段之前修改或验证值的属性

+   **Setter**：允许在设置到相关字段之前修改或计算值的属性

在其他一些语言中，这些类型的属性被称为计算属性。让我们看一个例子。创建一个名为`getSet.ts`的文件，并添加以下代码：

```ts
class Speaker {
    private message: string;
    constructor(private name: string) {}

    get Message() {
        if(!this.message.includes(this.name)){
            throw Error("message is missing speaker's name");
        }
        return this.message;
    }
    set Message(val: string) {
        let tmpMessage = val;
        if(!val.includes(this.name)){
            tmpMessage = this.name + " " + val;
        }
        this.message = tmpMessage;
    }
}
const speaker = new Speaker("john");
speaker.Message = "hello";
console.log(speaker.Message);
```

这里发生了很多事情，所以在编译和运行之前让我们来看一下。首先，你可以看到我们的`message`字段不在构造函数中可用，而是一个`private`字段，因此不能直接从我们的类外部访问。构造函数接受的唯一初始化器是我们的`name`字段。之后，你可以看到`Message`属性是一个 getter，因为它的名称前缀带有`get`关键字。在 getter 中，我们测试看看我们的`message`字段值是否包含说话者的名字，如果不包含，我们抛出一个异常来指示一个不需要的情况。setter，也称为`Message`，由`set`关键字指示，这个属性接收一个字符串，并通过检查`message`字段是否缺少说话者的名字来添加它。请注意，尽管`getter`和`setter`看起来像函数，但它们并不是。当它们在后面的代码中被调用时，它们被调用就像一个字段被调用一样，不带括号。因此，在代码的最后，speaker 对象被实例化为一个名为`john`的新 speaker，并且它的`Message`属性被设置为`hello`。此后，消息被写入控制台。

现在，我们想要编译这段代码，以便我们可以运行它，但这次我们需要做一些不同的事情。TypeScript 编译器有一些选项，它可以接受以定制其行为。在这个例子中，getter 和 setter 以及`includes`函数只在 ES5 和 ES6 中才可用。如果你对此不熟悉，`includes`函数检查一个字符串是否是另一个较大字符串的子字符串。因此，让我们告诉 TypeScript 编译器，它需要编译到比默认的 ES3 更新的 JavaScript 目标。

这是你需要的新编译命令（我们稍后会更深入地讨论`tsc`编译器选项，包括使用配置文件）：

```ts
tsc --target "ES6" getSet
```

现在，你可以运行命令。再一次，它如下所示：

```ts
node getSet
```

所以，你现在得到了以下输出：

![图 2.10 – getSet 输出](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.10_B15508.jpg)

图 2.10 – getSet 输出

为了进一步强调这一点，让我们尝试将`speaker.Message = "hello"`这一行切换为`speaker.message = "hello"`。如果你编译，你应该会看到这个错误：

![图 2.11 – Message 字段错误](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.11_B15508.jpg)

图 2.11 – Message 字段错误

你能猜到为什么会失败吗？是的，这是因为`message`是一个`private`字段，不能从我们的类外部访问。

也许你会想为什么我在这里提到`getter`和`setter`，当它们在常规 JavaScript 中也是可用的。如果你看一下例子，你会发现`message`字段是`private`的，而`getter`和`setter`属性是`public`的（注意，当你没有显式声明访问修饰符时，默认为`public`）。因此，为了允许良好的封装，最好的做法是隐藏我们的字段，并且只在需要时通过 getter 和/或 setter 或一些允许修改字段的函数来暴露它。还要记住，在决定成员的访问级别时，你希望从最严格的能力开始，然后根据需要变得不那么严格。此外，通过允许通过访问器访问字段，我们可以做各种检查和修改，就像我们在例子中所做的那样，这样我们就可以对进出我们的类的内容有最终的控制。

### 静态属性和方法

最后，让我们讨论**静态**属性和方法。当你在类内部将某些东西标记为静态时，你是在说这个成员是类类型的成员，而不是类实例的成员。因此，它可以在不需要创建类的实例的情况下访问，而是通过在类名前加上前缀来访问。

让我们看一个例子。创建一个名为`staticMember.ts`的新文件，并添加以下代码：

```ts
class ClassA {
    static typeName: string;
    constructor(){}

    static getFullName() {
        return "ClassA " + ClassA.typeName;
    }
}
const a = new ClassA();
console.log(a.typeName);
```

如果你尝试编译这段代码，它将失败，并声明`typeName`是`ClassA`类型的静态成员。再次强调，静态成员必须使用类名调用。以下是修复后的代码版本：

```ts
class ClassA {
    static typeName: string;
    constructor(){}

    static getFullName() {
        return "ClassA " + ClassA.typeName;
    }
}
const a = new ClassA();
console.log(ClassA.typeName);
```

正如你所看到的，我们用类名引用了`typeName`。那么，为什么我要使用静态成员而不是实例成员呢？在某些情况下，跨类实例共享数据可能是有用的。例如，我可能想要做这样的事情：

```ts
class Runner {    
    static lastRunTypeName: string;
    constructor(private typeName: string) {}

    run() {        
        Runner.lastRunTypeName = this.typeName;
    }
}
const a = new Runner("a");
const b = new Runner("b");
b.run();
a.run();
console.log(Runner.lastRunTypeName);
```

在这个例子中，我试图确定在任何给定时间内最后调用`run`函数的类实例。通过使用静态成员，这可以很简单。还要注意的一点是，在类内部，静态成员可以被静态成员和实例成员调用。但是，静态成员不能调用实例成员。

现在我们已经在本节中学习了类及其特性。这将有助于我们为封装设计代码，从而提高其质量。接下来，我们将学习接口和基于合同的编码。

## 接口

在面向对象编程设计中，另一个重要的原则是抽象。抽象的目标是通过不暴露内部实现来减少代码的复杂性和紧密耦合（我们已经在《第一章》《理解 TypeScript》中涵盖了抽象）。这样做的一种方式是使用接口来仅显示类型的签名，而不是其内部工作方式。接口有时也被称为合同，因为对参数和返回类型进行特定类型的约束会强制执行接口的用户和创建者之间的某些期望。因此，对接口的另一种思考方式是对类型实例的输出和输入施加严格的规则。

现在，接口只是一组规则。为了使代码正常工作，我们需要对这些规则进行实现。因此，让我们展示一个带有实现的接口的示例以开始。创建一个名为`interfaces.ts`的新文件，并添加以下接口定义：

```ts
interface Employee {
    name: string;
    id: number;
    isManager: boolean;
    getUniqueId: () => string;
}
```

这个接口定义了我们稍后将创建实例的`Employee`类型。正如你所看到的，`getUniqueId`函数没有实现，只有其签名。实现将在我们定义它时进行。

现在，将实现添加到`interfaces.ts`文件中。插入以下代码，创建`Employee`接口的两个实例：

```ts
const linda: Employee = {
    name: "linda",
    id: 2,
    isManager: false,
    getUniqueId: (): string => {
        let uniqueId = linda.id + "-" + linda.name;
        if(!linda.isManager) {
            return "emp-" + uniqueId;
        }
        return uniqueId;
    }
}
console.log(linda.getUniqueId());
const pam: Employee = {
    name: "pam",
    id: 1,
    isManager: true,
    getUniqueId: (): string => {
        let uniqueId = pam.id + "-" + pam.name;
        if(pam.isManager) {
            return "mgr-" + uniqueId;
        }
        return uniqueId;
    }
}
console.log(pam.getUniqueId());
```

因此，我们通过实例化一个名为`linda`的对象文字来创建一个实例，设置两个字段名 - `name`和`id`，然后实现`getUniqueId`函数。稍后，我们在控制台记录`linda.getUniqueId`调用。之后，我们创建另一个对象，名为`pam`，基于相同的接口。然而，它不仅具有不同的字段值，而且其`getUniqueId`的实现也与`linda`对象不同。这是接口的主要用途：允许对象之间有一个统一的结构，但可以实现不同的实现。通过这种方式，我们对类型结构施加严格的规则，但也允许函数在执行其工作时具有一定的灵活性。以下是我们代码的输出：

![图 2.12 - 员工接口结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.12_B15508.jpg)

图 2.12 - 员工接口结果

接口的另一个可能用途是在使用第三方 API 时。有时，类型信息没有很好地记录，你得到的只是无类型的 JSON 或者对象类型非常庞大，有许多你永远不会使用的字段。在这种情况下，很容易只是使用`any`作为类型并完成它。然而，如果可能的话，你应该更倾向于提供类型声明。

在这种情况下，您可以创建一个只包含您知道并关心的字段的接口。然后，您可以声明您的数据类型为此类型。在开发时，TypeScript 将无法检查类型，因为 API 网络调用的数据将在运行时传入。但是，由于 TypeScript 只关心任何给定类型的形状，它将忽略未在类型声明中提到的字段，只要数据以您在接口中定义的字段传入，运行时就不会抱怨，您将保持开发时的类型安全。但是，请务必小心处理`null`或`undefined`字段，允许它们使用联合或测试这些类型。

在本节中，我们学习了接口和接口与类之间的区别。我们将能够使用接口来抽象类的实现细节，从而在我们的代码之间产生松耦合，从而提高代码质量。在下一节中，我们将学习类和接口如何允许我们执行继承，从而实现代码重用。

# 理解继承

在本节中，我们将学习**继承**。面向对象编程中的继承是一种代码重用的方法。这将缩小我们的应用程序代码大小，并使其更易读。此外，一般来说，较短的代码往往会有更少的错误。因此，一旦开始构建，所有这些因素都将提高我们应用程序的质量。

如前所述，继承主要是允许代码重用。继承在概念上也被设计成像现实生活中的继承，以便继承关系的逻辑流可以直观且更易于理解。现在让我们看一个例子。创建一个名为`classInheritance.ts`的文件，并添加以下代码：

```ts
class Vehicle {
    constructor(private wheelCount: number) {}
    showNumberOfWheels() {
        console.log(`moved ${this.wheelCount} miles`);
    }
}
class Motorcycle extends Vehicle {
    constructor() {
        super(2);
    }
}
class Automobile extends Vehicle {
    constructor() {
        super(4);
    }
}
const motorCycle = new Motorcycle();
motorCycle.showNumberOfWheels();
const autoMobile = new Automobile();
autoMobile.showNumberOfWheels();
```

重要提示

如果您以前从未见过反引号``和`${}`，这是一个快速和简单的方法，称为字符串插值，通过嵌入对象在字符串中插入字符串值。

如您所见，有一个基类，也称为父类，名为`Vehicle`。这个类充当了源代码的主要容器，稍后将被从中继承的任何类重用，也称为子类。子类使用`extends`关键字从`Vehicle`继承。一个重要的事情要注意的是，在每个子类的构造函数中，您会看到第一行代码是对`super`的调用。`super`是子类继承的父类的实例的名称。因此，在这种情况下，那将是`Vehicle`类。现在，您可以看到，每个子类通过父类的构造函数向父类的`wheelCount`变量传递了不同数量的轮子。然后，在代码的末尾，创建了每个子类的实例`Motorcycle`和`Automobile`，并调用了`showNumberOfWheels`函数。如果我们编译并运行此代码，我们会得到以下结果：

![图 2.13 - classInheritance 结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.13_B15508.jpg)

图 2.13 - classInheritance 结果

因此，每个子类向父类的`wheelCount`变量提供了不同数量的轮子，尽管它们无法直接访问该变量。现在，假设子类希望直接访问父类的`wheelCount`变量有一个原因。例如，假设发生了爆胎，需要更新轮胎数量。我们该怎么办？好吧，让我们尝试为每个子类创建一个独特的函数，试图更新`wheelCount`。让我们看看会发生什么。通过向`Motorcycle`类添加一个新函数`updateWheelCount`来更新代码：

```ts
class Vehicle {
    constructor(private wheelCount: number) {}
    showNumberOfWheels() {
        console.log(`moved ${this.wheelCount} miles`);
    }
}
class Motorcycle extends Vehicle {
    constructor() {
        super(2);
    }
    updateWheelCount(newWheelCount: number){
        this.wheelCount = newWheelCount;
    }
}
class Automobile extends Vehicle {
    constructor() {
        super(4);
    }
}
const motorCycle = new Motorcycle();
motorCycle.showNumberOfWheels();
const autoMobile = new Automobile();
autoMobile.showNumberOfWheels();
```

作为一个测试，如果我们只更新`Motorcycle`类并添加一个`updateWheelCount`函数，如下所示，我们会得到一个错误。你能猜到为什么吗？这是因为我们试图访问父类的私有成员。因此，即使子类从父类继承其成员，它们仍然无法访问父类的`private`成员。这是正确的行为，再次促进封装。那么，我们该怎么办呢？好吧，让我们再次尝试编辑代码来允许这样做：

```ts
class Vehicle {
    constructor(protected wheelCount: number) {}
    showNumberOfWheels() {
        console.log(`moved ${this.wheelCount} miles`);
    }
}
class Motorcycle extends Vehicle {
    constructor() {
        super(2);
    }
    updateWheelCount(newWheelCount: number){
        this.wheelCount = newWheelCount;
    }
}
class Automobile extends Vehicle {
    constructor() {
        super(4);
    }
}
const motorCycle = new Motorcycle();
motorCycle.showNumberOfWheels();
const autoMobile = new Automobile();
autoMobile.showNumberOfWheels();
```

您看到我们做的小改变了吗？没错，我们将`Vehicle`父类构造函数中的`wheelCount`参数更改为`protected`访问器类型。`protected`允许类和任何继承类访问成员。

在我们继续下一个主题之前，让我们介绍`namespaces.ts`的概念，并添加以下代码：

```ts
namespace A {
    class FirstClass {}
}
namespace B {
    class SecondClass {}
    const test = new FirstClass();
}
```

从这段代码中可以看出，即使在编译之前，VSCode IntelliSense 已经抱怨找不到`FirstClass`。这是因为它被隐藏在`namespace B`中，因为它只在`namespace A`中定义。这就是命名空间的目的，将一个范围内的信息隐藏在其他范围之外。

在这一部分，我们学习了从类中继承。类继承是重用代码的一个非常重要的工具。在下一节中，我们将学习使用抽象类，这是一种更灵活的继承方式。

## 抽象类

如前所述，接口可以用于定义合同，但它们本身没有工作代码的实现。类有工作实现，但有时只需要一个签名。对于这种类型的情况，您将使用`abstractClass.ts`，并将我们的`classInheritance.ts`文件中的代码复制粘贴到其中。如果这样做，您可能会遇到一些错误，因为这两个文件都有相同的类和变量名。

因此，在我们的新的`abstractClass.ts`文件中，我们将使用命名空间更新它，并将`Vehicle`类修改为抽象类。添加命名空间并像这样更新`Vehicle`类：

```ts
namespace AbstractNamespace {
    abstract class Vehicle {
        constructor(protected wheelCount: number) {}
        abstract updateWheelCount(newWheelCount: number): void;
        showNumberOfWheels() {
            console.log(`moved ${this.wheelCount} miles`);
        }
    }
```

因此，首先，我们显然将所有代码包装在一个名为`namespace AbstractNamespace`的括号中（请注意，命名空间可以有任何名称；它的名称不需要在名称中包含`namespace`）。同样，这只是一个容器，允许我们控制作用域，以便我们的`abstractClass.ts`文件的成员不会泄漏到全局作用域，并影响其他文件。

如果您查看新的`Vehicle`代码，我们在类名`abstract`之前有一个`new`关键字。这表明该类将是一个抽象类。您还可以看到我们有一个名为`updateWheelCount`的新函数。这个函数在`Vehicle`类前面有一个`abstract`关键字，这表明它在`Vehicle`类中没有实现，需要由继承类实现。

现在，在`Vehicle abstract`类之后，我们想要继承它的子类。因此，在`Vehicle`类下面添加`Motorcycle`和`Automobile`类：

```ts
    class Motorcycle extends Vehicle {
        constructor() {
            super(2);
        }
        updateWheelCount(newWheelCount: number){
            this.wheelCount = newWheelCount;
            console.log(`Motorcycle has ${this.wheelCount}`);
        }
    }
    class Automobile extends Vehicle {
        constructor() {
            super(4);
        }
        updateWheelCount(newWheelCount: number){
            this.wheelCount = newWheelCount;
            console.log(`Automobile has ${this.wheelCount}`);
        }
        showNumberOfWheels() {
            console.log(`moved ${this.wheelCount} miles`);
        }
    }
```

添加类之后，我们实例化它们并调用它们各自的`updateWheelCount`方法，如下所示：

```ts
    const motorCycle = new Motorcycle();
    motorCycle.updateWheelCount(1);
    const autoMobile = new Automobile();
    autoMobile.updateWheelCount(3);
}
```

正如您所看到的，`abstract`成员`updateWheelCount`的实现在子类中。这是抽象类提供的功能。抽象类既可以作为常规类，提供成员实现，也可以作为接口，只提供子类实现的规则。请注意，由于抽象类可以有抽象成员，您不能实例化抽象类。

此外，如果您查看`Automobile`类，您会发现它有自己的`showNumberOfWheels`的实现，即使这个函数不是抽象的。这展示了一种称为**覆盖**的东西，即子类成员能够创建父类成员的独特实现的能力。

在本节中，我们学习了不同类型的基于类的继承。学习继承将使我们能够重用更多的代码，减少代码大小和潜在的错误。在下一节中，我们将学习如何使用接口进行继承，以及它与基于类的继承有何不同。

## 接口

正如前面所解释的，**接口**是一种为类型设置约定规则的方式。它们将允许我们将实现与定义分离，从而提供抽象，这又是一个强大的面向对象编程原则，将为我们提供更高质量的代码。让我们学习如何使用接口来明确继承并以一种良好结构的方式使用。

TypeScript 接口为接口的成员提供一组类型签名，但它们本身没有实现。现在，我们确实展示了一些使用独立接口的例子，但这次，让我们看看如何可以使用接口作为继承和代码重用的手段。创建一个名为`interfaceInheritance.ts`的新文件，并添加以下代码：

```ts
namespace InterfaceNamespace {
    interface Thing {
        name: string;
        getFullName: () => string;
    }
    interface Vehicle extends Thing {
        wheelCount: number;
        updateWheelCount: (newWheelCount: number) => void;
        showNumberOfWheels: () => void;
    }
```

在命名空间之后，您可以看到有一个名为`Thing`的接口，之后是定义了`Vehicle`接口，并使用`extends`关键字从`Thing`继承。我将这放入示例中以表明接口也可以从其他接口继承。`Thing`接口有两个成员 - `name`和`getFullName` - 正如您所看到的，尽管`Vehicle`扩展了`Thing`，但在`Vehicle`的任何地方都没有提到这些成员。这是因为`Vehicle`是一个接口，因此不能有任何实现。然而，如果您查看以下代码，在`Motorcycle`类中，您会发现，由于这个类扩展了`Vehicle`，实现是存在的：

```ts
    class Motorcycle implements Vehicle {
        name: string;
        wheelCount: number;
        constructor(name: string) {
            // no super for interfaces
            this.name = name;
        }
        updateWheelCount(newWheelCount: number){
            this.wheelCount = newWheelCount;
            console.log(`Automobile has ${this.wheelCount}`);
        }
        showNumberOfWheels() {
            console.log(`moved Automobile ${this.wheelCount}            miles`);
        }
        getFullName() {
            return "MC-" + this.name;
        }
    }
    const moto = new Motorcycle("beginner-cycle");
    console.log(moto.getFullName());
}
```

因此，如果我们编译并运行此代码，我们会得到以下结果：

![图 2.14 – 接口继承结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.14_B15508.jpg)

图 2.14 – 接口继承结果

接口本身并不直接提供代码重用的手段，因为它们没有实现。然而，它仍然有利于代码重用，因为接口的结构提供了对代码将接收和返回什么的明确期望。将实现隐藏在接口后面也有利于进行封装和抽象，这也是面向对象编程的重要原则。

重要提示

在使用 TypeScript 时，充分利用面向对象编程中可用的继承模型。使用接口来抽象实现细节。使用`private`和`protected`来帮助封装数据。请记住，当编译并将您的代码转换为 JavaScript 时，TypeScript 编译器将为您执行任何翻译工作，以将事物重新转换为原型样式。但在开发模式下，您应该充分利用 TypeScript 提供的所有功能，以增强您的开发体验。

在本节中，我们学习了继承以及如何将其用于代码重用。我们了解了如何使用三种主要的容器类型：类、抽象类和接口进行继承。一旦我们开始编写应用程序，您将会看到为什么能够进行代码重用是大型应用程序开发中如此关键的因素。在下一节中，我们将介绍泛型，它将使用我们在本节中学到的类型。

# 学习泛型

**泛型**允许类型定义包括一个关联类型，可以由泛型类型的用户选择，而不是由类型创建者指定。这样，有一些结构和规则，但仍然有一定的灵活性。泛型在我们后面使用 React 编码时肯定会发挥作用，所以让我们在这里学习一下。

泛型可以用于函数、类和接口。让我们看一个使用函数泛型的例子。创建一个名为`functionGeneric.ts`的文件，并添加以下代码：

```ts
function getLength<T>(arg: T): number {
    if(arg.hasOwnProperty("length")) {
        return arg["length"];
    }
    return 0;
}
console.log(getLength<number>(22));
console.log(getLength("Hello world."));
```

如果我们从顶部开始，我们会看到一个名为`getLength<T>`的函数。这个函数使用了一个泛型，告诉编译器无论它在哪里看到`T`符号，它都可以期望任何可能的类型。现在，在内部，我们的函数实现检查`arg`参数是否有一个名为`length`的字段，然后尝试获取它。如果没有，它就返回`0`。最后，在底部，您可以看到`getLength`函数被调用了两次：一次是为了一个数字，另一次是为了一个字符串。此外，您可以看到对于`number`，它明确地有`<number>`类型指示符，而对于`string`，它没有。这只是为了表明您可以明确指定类型，但编译器通常可以根据使用情况推断出您的意图。

这个例子的问题在于为了检查`length`字段而需要额外的代码。这使得代码变得繁忙，比实际需要的代码更长。让我们更新这段代码，以防止调用这个函数如果参数没有`length`属性。首先，注释掉我们刚刚写的代码，然后在其下面添加以下新代码：

```ts
interface HasLength {
    length: number;
}
function getLength<T extends HasLength>(arg: T): number {
    return arg.length;
}
console.log(getLength<number>(22));
console.log(getLength("Hello world."));
```

这段代码非常相似，只是我们使用了一个`HasLength`接口来限制允许的类型。通过使用`extends`关键字来约束泛型类型。通过编写`T extends HasLength`，我们告诉编译器无论`T`是什么，它必须继承自`HasLength`类型，这有效地意味着它必须具有`length`属性。因此，当进行前两个调用时，对于`number`类型会失败，因为它们没有`length`属性，但对于`string`则有效。

现在，让我们看一个使用接口和类的例子。让我们创建一个名为`classGeneric.ts`的文件，并向其中添加以下代码：

```ts
namespace GenericNamespace {
    interface Wheels {
        count: number;
        diameter: number;
    }
    interface Vehicle<T> {
        getName(): string;
        getWheelCount: () => T;
    }
```

因此，我们可以看到我们有一个名为`Wheels`的接口，它提供了轮子信息。我们还可以看到`Vehicle`接口采用了类型`T`的泛型，表示任何特定类型。

随后，我们看到`Automobile`类实现了具有泛型作为`Wheel`类型的`Vehicle`接口，将`Wheel`关联到`Automobile`。然后，最后，我们看到`Chevy`类扩展了`Automobile`，提供了一些默认值：

```ts
    class Automobile implements Vehicle<Wheels> {
        constructor(private name: string, private wheels:          Wheels){}
        getName(): string {
            return this.name;
        }
        getWheelCount(): Wheels {
            return this.wheels;
        }
    }
    class Chevy extends Automobile {
        constructor() {
            super("Chevy", { count: 4, diameter: 18 });
        }
    }
```

在定义了所有这些类型之后，我们创建了`Chevy`类的一个实例，并从中记录了一些输出：

```ts
    const chevy = new Chevy();
    console.log("car name ", chevy.getName());
    console.log("wheels ", chevy.getWheelCount());
}
```

这段代码编译并成功运行，并给出以下结果：

![图 2.15 – classGeneric.ts 的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_2.15_B15508.jpg)

图 2.15 – classGeneric.ts 的结果

您可以看到我们的继承层次结构有几个级别，但我们的代码能够成功返回有效的结果。虽然现实世界代码中的具体细节可能不同，但是在这里显示的多级类型层次结构在面向对象编程设计中是经常发生的事情。

在本节中，我们学习了如何在函数和类类型上使用泛型。泛型通常在 React 开发中使用，以及一些 Node 包中也会用到。因此，一旦我们在后面的章节开始编码，它们将会很有用。在下一节中，我们将看一些其他杂项内容来完成本章。

# 学习最新功能并配置编译器

在本节中，我们将学习 TypeScript 中一些较新的特性，以及如何配置 TypeScript 编译器。通过了解这些较新的特性，我们将能够编写更清晰、更易读的代码，这当然对团队中使用应用程序是有益的。通过使用 TypeScript 的配置选项，我们可以让编译器以我们认为最适合我们项目的方式工作。

## Optional chaining

让我们来看看`null`对象。让我们创建一个名为`optionalChaining.ts`的文件，并将以下代码添加到其中：

```ts
namespace OptionalChainingNS {
    interface Wheels {
        count?: number;
    }
    interface Vehicle {
        wheels?: Wheels;
    }
    class Automobile implements Vehicle {
        constructor(public wheels?: Wheels) {}
    }
    const car: Automobile | null = new Automobile({
        count: undefined
    });
    console.log("car ", car);
    console.log("wheels ", car?.wheels);
    console.log("count ", car?.wheels?.count);
}
```

如果我们看这段代码，我们可以看到有几种类型被一起使用。`car`有一个`wheels`属性，而`wheels`有一个`count`属性。因此，稍后当我们记录时，你可以看到调用被链接在一起。例如，最后的`console.log`行引用了`car?.wheels?.count`。这被称为可选链。问号表示对象可能是`null`或`undefined`。如果它是`null`或`undefined`，那么代码将在该对象结束，返回对象或属性的任何值，并且不继续到其余的属性，但不会导致错误。

因此，如果我们以旧的方式编写底部的控制台代码，我们将不得不进行大量的代码测试，以确保我们不会通过调用可能是`undefined`的东西而导致错误。我们将使用三元操作符，它可能看起来像这样：

```ts
const count = !car ? 0 
    : !car.wheels ? 0 
    : !car.wheels.count ? 0
    : car.wheels.count;
```

显然，这既难写又难读。因此，通过使用可选链，我们允许编译器在发现`null`或`undefined`时立即停止并返回。这使我们免于编写大量冗长、可能容易出错的代码。

## Nullish coalescing

Nullish coalescing 是三元运算符的简化形式。因此，它非常直接，看起来像这样：

```ts
const val1 = undefined;
const val2 = 10;
const result = val1 ?? val2;
console.log(result);
```

双问号从左到右工作。该语句的意思是，如果`val1`不是`null`或`undefined`并且有实际值，则返回该值。然而，如果`val1`没有值，则返回`val2`。因此，在这种情况下，编译和运行将导致`10`被写入控制台。

你可能想知道这是否与`||`运算符相同。它有些相似但更受限制。逻辑或运算符在这种情况下，检查“真值”。在 JavaScript 中，这是一个概念，其中大量可能的值可以被认为是“真值”或“假值”。例如，`0`，`true`或`false`，`undefined`和`""`在 JavaScript 中都有真或假的等价性。然而，在 nullish coalescing 的情况下，只有`null`或`undefined`被明确检查。

## TypeScript 配置

TypeScript 配置可以通过命令行传递，或者更常见的是通过一个名为`tsconfig.json`的文件。如果你使用命令行，那么调用编译器就像这样：

```ts
tsc tsfile.ts –lib 'es5, dom'
```

这告诉 TypeScript 忽略任何`tsconfig.json`文件，只使用命令行选项 - 在这种情况下，`-lib`选项，它声明在开发过程中使用的 JavaScript 版本，并且只编译这一个文件。如果你只在命令行上输入`tsc`，TypeScript 将寻找一个`tsconfig.json`文件并使用该配置，并编译它找到的所有`ts`文件。

有许多选项，所以我们在这里不会涵盖所有。然而，让我们回顾一些最重要的选项（当我们开始编码时，我会提供一个示例`tsconfig.json`文件供使用）：

+   `--lib`：这用于指示在开发过程中将使用哪个 JavaScript 版本。

+   `--target`：这表示你想要发射到`.js`文件中的 JavaScript 版本。

+   `--noImplicitAny`：不允许`any`类型，除非显式声明它。

+   `--outDir`：这是 JavaScript 文件将保存到的目录。

+   `--outFile`：这是最终的 JavaScript 文件名。

+   `--rootDirs`：这是一个存储`.ts`文件源代码的数组。

+   `--exclude`：这是一个要从编译中排除的文件夹和文件的数组。

+   `--include`：这是一个要包含在编译中的文件夹和文件的数组。

本节仅提供了 TypeScript 一些新特性的简要概述，以及一些与配置相关的信息。然而，这些新特性和配置 TypeScript 的能力非常重要，在我们开始编写代码的后续章节中将会被广泛使用。

# 总结

在本章中，我们学习了 TypeScript 语言。我们了解了语言中存在的许多不同类型，以及如何创建我们自己的类型。我们还学习了如何使用 TypeScript 来创建面向对象的代码。这是一个庞大而复杂的章节，但对于我们开始构建应用程序时将是绝对必要的知识。

在下一章中，我们将回顾一些传统 JavaScript 中最重要的特性。我们还将了解一些最新版本语言中的新特性。由于 TypeScript 是 JavaScript 的真正超集，因此了解 JavaScript 的最新情况对于充分利用 TypeScript 非常重要。


# 第三章：使用 ES6+功能构建更好的应用程序

在本章中，我们将回顾 JavaScript 在其最新的 ES6+形式中的一些重要特性（我添加了加号表示 ES6 及更高版本）。重要的是要理解，尽管本书使用 TypeScript，但这两种语言是互补的。换句话说，TypeScript 并不取代 JavaScript。它增强和增强了 JavaScript，添加了使其更好的功能。因此，我们将回顾 JavaScript 语言中一些最重要的特性。我们将回顾变量作用域和新的`const`和`let`关键字。此外，我们将深入研究`this`关键字以及在需要时如何切换它。我们还将学习 JavaScript 中许多新功能，例如新的数组函数和`async await`。这些知识将为我们提供一个坚实的基础，使我们能够在 TypeScript 中编码。

在本章中，我们将涵盖以下主要主题：

+   学习 ES6 变量类型和 JavaScript 作用域

+   学习箭头函数

+   更改`this`上下文

+   学习有关传播、解构和剩余

+   学习新的数组函数

+   学习新的集合类型

+   学习`async await`

# 技术要求

本章的要求与*第二章** TypeScript 探索*相同。您应该对 JavaScript 和 Web 技术有基本的了解。您将再次使用 Node 和**Visual Studio Code**（**VSCode**）。

GitHub 存储库位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap3`文件夹中的代码。

让我们设置本章的代码文件夹：

1.  转到您的`HandsOnTypescript`文件夹并创建一个名为`Chap3`的新文件夹。

1.  打开 VSCode 并转到您刚创建的`Chap3`文件夹。然后，选择**View** | **Terminal**并在 VSCode 窗口内启用终端窗口。

1.  键入`npm init`命令，就像上一章那样，初始化`npm`项目，并接受所有默认值（您也可以使用`npm init -y`自动接受所有默认值）。

1.  键入`npm install typescript`命令，就像上一章那样，安装 TypeScript。

现在我们准备开始了。

# 学习 ES6 变量类型和 JavaScript 作用域

在本节中，我们将学习 JavaScript 的作用域规则和一些新的变量类型，这有助于澄清和改进有关这些作用域规则的一些问题。这些信息很有价值，因为作为软件开发人员，您将不断地创建变量，并且了解变量可以在什么范围内访问以及在什么情况下可能会更改是很重要的。

在大多数其他语言中，变量作用域发生在任意一组括号或*begin end*作用域语句内。然而，在 JavaScript 中，作用域由函数体处理，这意味着当使用`var`关键字在函数体内声明变量时，该变量只能在该体内访问。让我们看一个例子。创建一个名为`functionBody.ts`的新文件，并将以下代码添加到其中：

```ts
if (true) {
    var val1 = 1;
}
function go() {
    var val2 = 2;
}
console.log(val1);
console.log(val2);
```

在 VSCode 中，您应该看到对`console.log(val2)`的调用的错误指示，而对`console.log(val1)`的调用却可以正常工作。您可能会认为，由于`val1`是在`if`语句的括号内声明的，所以稍后将无法访问它。然而，显然它是可以的。但另一方面，由`go`函数作用域的`val2`在外部是不可访问的。这表明就变量声明而言，使用`var`的函数充当作用域容器。

这个功能实际上是 JavaScript 中很多混淆的根源。因此，在 ES6 中，创建了一组新的变量声明前缀：`const`和`let`。让我们在这里回顾一下。

`const`变量支持一种称为块级作用域的东西。块级作用域是在任何花括号之间的作用域。例如，在我们之前的例子中，那将是`if`语句。此外，顾名思义，`const`创建一个常量变量值，一旦设置，就不能重新设置为其他值。然而，这意味着的内容与其他一些语言有点不同。在 JavaScript 中，这意味着变量的赋值不能被更改。但是，变量本身可以被编辑。这很难想象，所以让我们看一些例子。创建一个名为`const.ts`的新文件，并添加以下代码：

```ts
namespace constants {
    const val1 = 1;
    val1 = 2;
    const val2 = [];
    val2.push('hello');
}
```

在 VSCode 中，这段代码将对`val1 = 2`显示错误，但对于`val2.push('hello')`则没有问题。原因是在`val1`的情况下，变量实际上被重置为一个全新的值，这是不允许的。然而，对于`val2`，数组值保持不变，并且新元素被添加到其中。因此，这是允许的。

现在，让我们看一下`let`关键字。`let`变量与`const`变量一样，也是块级作用域的。然而，它们可以随意设置和重置（当然，在 TypeScript 中，类型需要保持不变）。让我们展示一个`let`的例子。创建一个名为`let.ts`的文件，并添加以下代码：

```ts
namespace lets {
    let val1 = 1;
    val1 = 2;
    if(true) {
        let val2 = 3;
        val2 = 3;
    }
    console.log(val1);
    console.log(val2);
}
```

因此，在这里，我们有两组`let`变量。`val1`没有在块中作用域，但`val2`在`if`块中作用域。正如你所看到的，只有对`console.log(val2)`的调用失败了，因为`val2`只存在于`if`块内部。

那么，你会使用哪种变量声明方法？社区中目前的最佳实践是优先使用`const`，因为不可变性是一个有益的属性，而且使用常量还会带来微小的性能优势。然而，如果你知道需要能够稍后重置变量，那么请使用`let`。最后，避免使用`var`。

我们已经了解了作用域和 ES6 中新的`const`和`let`变量类型。理解作用域并知道何时使用`const`和何时使用`let`是进行现代 JavaScript 开发的重要技能。在较新的 JavaScript 代码中，你会经常看到这些关键字。接下来，我们将回顾`this`上下文和箭头函数。

# 学习箭头函数

箭头函数是 ES6 的一个新添加。基本上，它们有两个主要目的：

+   它们缩短了编写函数的语法。

+   它们还会自动使立即作用域父级成为`this`对象，箭头函数的父级。

在继续之前，让我更详细地解释一下`this`，因为这对 JavaScript 开发人员来说是至关重要的知识。

在 JavaScript 中，`this`对象，即成员属性和方法所属的所有者对象实例，可以根据调用的上下文而改变。因此，当直接调用函数时，例如`MyFunction()`，父`this`将是函数的调用者；也就是说，当前作用域的`this`对象。对于浏览器来说，通常是`window`对象。然而，在 JavaScript 中，函数也可以用作对象构造函数，例如`new MyFunction()`。在这种情况下，函数内部的`this`对象将是从`new MyFunction`构造函数创建的对象实例。

让我们看一个例子来澄清一下，因为这是 JavaScript 的一个非常重要的特性。创建一个名为`testThis.ts`的新文件，并添加以下代码：

```ts
function MyFunction () {
    console.log(this);
}

MyFunction();
let test = new MyFunction();
```

如果你编译然后运行这段代码，你会看到以下结果：

![图 3.1 - testThis 结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.01_B15508.jpg)

图 3.1 - testThis 结果

因此，当直接调用`MyFunction`时，立即作用域父级将是 Node 的全局对象，因为我们不是在浏览器中运行。接下来，如果我们使用`new MyFunction()`从`MyFunction`创建一个新对象，`this`对象将成为它自己的对象实例，因为该函数被用来创建一个对象，而不是直接运行。

既然我们已经了解了这一点，让我们看看箭头函数是什么样子的。创建`arrowFunction.ts`文件，并添加以下代码：

```ts
const myFunc = (message: string): void => {
    console.log(message);
}

myFunc('hello');
```

如果编译并运行此代码，您将看到打印出`hello`。语法与函数类型非常相似；但它们并不相同。如果我们看一下代码，您会看到参数括号后面有一个冒号，然后是参数括号后面的 void 类型。这是函数的返回类型。在函数类型的情况下，返回类型在`=>`符号之后表示。

关于箭头函数还有一些额外的事情需要注意。JavaScript 中的所有非箭头函数都可以访问一个称为`arguments`的集合。这是给定给函数的所有参数的集合。箭头函数没有自己的`arguments`集合。但是，它们可以访问立即函数父级的`arguments`集合。

箭头函数有几种主体样式。以下是三种样式的示例：

```ts
const func = () => console.log('func');
const func1 = () => ({ name: 'dave' });
const func2 = () => {
    const val = 20;
    return val;
}
console.log(func());
console.log(func1());
console.log(func2());
```

让我们看看这三种样式：

+   第一个函数`func`显示了函数体中只使用了一行代码，没有返回任何内容，您可以看到函数体没有闭合括号或括号。

+   第二个函数`func1`显示了只有一行，但返回了一些内容的情况。在这种情况下，不需要`return`关键字，只有在返回对象时才需要括号。

+   最后一个案例是`func2`。在这种情况下，需要花括号，因为这是一个多行语句（无论是否返回）。

我们在本节中介绍了箭头函数。箭头函数在现代 JavaScript 和 TypeScript 代码中被广泛使用，因此深入了解这个特性是有益的。

# 更改 this 上下文

我们已经在前一节讨论了`this`上下文对象。如前所述，在 JavaScript 中，函数可以访问一个称为`this`的内部对象，该对象表示函数的调用者。现在，使用`this`的令人困惑的部分是，`this`的值可能会根据函数的调用方式而改变。因此，JavaScript 提供了一些帮助器，允许您将函数的`this`对象重置为您想要的对象，而不是给定的对象。有几种方法，包括`apply`和`call`，但我们要学习的最重要的是`bind`关键字。这对我们很重要，因为在 React 基于类的组件中经常使用`bind`。现在展示一个完整的 React 示例还为时过早。所以，让我们从一些更简单的东西开始。创建一个名为`bind.ts`的新文件，并将以下代码添加到其中：

```ts
class A {
    name: string = 'A';
    go() {
        console.log(this.name);
    }
}
class B {
    name: string = 'B';
    go() {
        console.log(this.name);
    }
}
const a = new A();
a.go();
const b = new B();
b.go = b.go.bind(a);
b.go();
```

从这段代码中可以看出，有两个不同的类：`A`和`B`。这两个类都有一个`go`函数，将特定的类名写入日志。现在，当我们将`b`对象的`go`函数的`this`对象的`bind`重置为`a`对象时，它会将`console.log(this.name)`语句切换为使用`a`作为`this`对象。因此，如果我们编译并运行，我们会得到这个：

![图 3.2 - bind](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.02_B15508.jpg)

图 3.2 - bind

正如您所看到的，`a.go()`写入了`A`，但`b.go()`也写入了`A`，而不是`B`，因为我们将`this`切换为`a`而不是`b`。请注意，除了接受`this`参数外，`bind`还可以在此后接受任意数量的参数。

您可能想知道使用`bind`、`call`和`apply`之间的区别是什么。`bind`用于更改`this`上下文，稍后在调用函数时，它将具有更改后的`this`对象。但是，`call`和`apply`是在调用函数时立即替换调用时的`this`上下文。`call`和`apply`之间的区别在于，`call`接受不确定数量的参数，而`apply`接受参数数组。让我们看一些示例。创建一个名为`call.js`的文件，并将以下代码添加到其中：

```ts
const callerObj = {
    name: 'jon'
}
function checkMyThis(age) {    
    console.log(`What is this ${this}`)
    console.log(`Do I have a name? ${this.name}`)
    this.age = age;
    console.log(`What is my age ${this.age}`);
}
checkMyThis();
checkMyThis.call(callerObj, 25);
```

首先，我们创建一个名为`callerObj`的新对象，它有一个名为`name`的字段，即`jon`。之后，我们声明一个`checkMyThis`函数，测试当前的`this`是什么，以及它是否有一个名字。最后，我们运行两个调用。请注意，第二个调用看起来很奇怪，但`checkMyThis.call`实际上是对`checkMyThis`函数的执行。如果我们运行这段代码，我们会看到一些有趣的东西。运行以下命令：

```ts
node call
```

您将看到以下结果：

![图 3.3 – node call](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.03_B15508.jpg)

图 3.3 – node call

`checkMyThis`函数的第一次执行默认使用全局对象，因为它没有被覆盖。对于 Node 来说，是 Node 的全局对象，但对于浏览器来说，是`window`对象。我们还看到`name`和`age`字段是未定义的，因为 Node 的全局对象没有`name`字段，而 age 没有作为参数传递给`checkMyThis`。然而，在函数的第二次执行中，使用`call`，我们看到对象已经改变为标准对象类型，它有一个名为`jon`的`name`字段，这是`callerObj`的`name`字段，以及一个等于`25`的`age`字段，这是我们传递给`call`的参数。您应该注意`call`的参数列表的顺序遵循被调用函数的参数列表的顺序。`apply`的用法是相同的；但是，它将参数作为数组。

在本节中，我们了解了处理`this`上下文的困难以及如何使用`bind`来处理这个问题。一旦我们开始创建 React 组件，我们将广泛使用`bind`。但即使超出了特定的用例，您会发现您的代码有时需要能够更改`this`上下文，可能还需要一些函数的参数。因此，这种能力是一个非常有用的功能。

# 学习 spread、解构和 rest

在 ES6+中，有新的方法来处理对象的复制和显示变量和参数。这些功能在使 JavaScript 代码更短、更易读方面发挥了重要作用。这些特性已经成为现代 JavaScript 的标准实践，因此我们需要了解它们并正确使用它们。

## Spread、Object.assign 和 Array.concat

`Object.assign`和`Array.concat` JavaScript 功能非常相似。基本上，您将多个对象或数组追加到一个对象或数组中。但严格来说，有一些区别。

在对象的情况下，有两种合并或连接对象的方法：

+   Spread—例如，`{ … obja, …objb }`: 您正在创建这两个对象的非修改副本，然后创建一个全新的对象。请注意，spread 可以处理不止两个对象。

+   `Object.assign`—`(obja, objb)`: 将`objb`的属性添加到`obja`中并返回`obja`。因此，`obja`被修改。以下是一个示例。创建一个名为`spreadObj.ts`的新文件，并添加以下代码：

```ts
namespace NamespaceA {
    class A {
        aname: string = 'A';
    }
    class B {
        bname: string = 'B';
    }
    const a = new A();
    const b = new B();
    c, which is set using the spread operator, …. After that, we create d from the Object.assign call. Let's try running this code. You'll need to target ES6 since Object.assign is only available on that version of JavaScript. Let's compile and then run with the following commands:

```

tsc spreadObj –target 'es6'

node spreadObj

```ts

Once these commands run, you will see the following:
```

![图 3.4 – spreadObj](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.04_B15508.jpg)

图 3.4 – spreadObj

如您所见，`c`既有`aname`和`bname`属性，但它是一个独特的对象。然而，`d`实际上是对象`a`具有对象`b`的属性，这由`a.aname = 'a1'`设置后`aname`变量等于`a1`来证明。

现在，对于合并或连接数组，您还有两种方法：

+   展开运算符：与对象的展开类似，它合并数组并返回一个新的单一数组。原始数组不会被修改。

+   `Array.concat`：通过将两个源数组合并成一个新数组来创建一个新数组。原始数组不会被修改。

让我们看一个使用这两种方法的示例。创建一个名为`spreadArray.ts`的文件，并添加以下代码：

```ts
namespace SpreadArray {
    const a = [1,2,3];
    const b = [4,5,6];
    const c = [...a, ...b];
    const d = a.concat(b);
    console.log('c before', c);
    console.log('d before', d);
    a.push(10);
    console.log('a', a);
    console.log('c after', c);
    console.log('d after', d);
}
```

正如您所看到的，数组`c`是使用 spread 从两个数组`a`和`b`创建的。然后，数组`d`是使用`a.concat(b)`创建的。在这种情况下，两个结果数组都是唯一的，不引用任何原始数组。让我们像之前一样编译和运行这段代码，看看我们得到了什么：

![图 3.5 – spreadArray](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.05_B15508.jpg)

图 3.5 – spreadArray

您会发现`a.push(10)`对`console.log('d after', d)`语句没有影响，即使数组`d`是从数组`a`创建的。这表明数组的 spread 和`concat`都会创建新的数组。

解构

**解构**是显示和直接使用对象内部属性的能力，而不仅仅依赖于对象名称。我稍后会用一个例子来解释这一点，但请注意，这是现代 JavaScript 开发中非常常用的功能，特别是在 React hooks 中，所以我们需要熟悉它。

让我们来看一个对象解构的例子。对于这个例子，让我们只使用一个 JavaScript 文件，这样例子会更清晰。创建一个名为`destructuring.js`的新文件，并将以下代码添加到其中：

```ts
function getEmployee(id) {
    return {
        name: 'John',
        age: 35,
        address: '123 St',
        country: 'United States'
    }
}
const { name: fullName, age } = getEmployee(22);
console.log('employee', fullName, age);
```

假设一下`getEmployee`函数去服务器并通过`id`检索员工的信息。现在，正如您所看到的，`employee`对象有很多字段，也许并不是每个调用该函数的人都需要每个字段。因此，我们使用对象解构来选择我们关心的字段。此外，请注意，我们还使用冒号给字段名称取了一个别名`fullName`。

数组也可以进行解构。让我们将以下代码添加到这个文件中：

```ts
function getEmployeeWorkInfo(id) {
    return [
        id,
        'Office St',
        'France'
    ]
}
const [id, officeAddress] = getEmployeeWorkInfo(33);
console.log('employee', id, officeAddress);
```

在这个例子中，`getEmployeeWorkInfo`函数返回一个关于员工工作位置的事实数组；但它以数组的形式返回。因此，我们也可以对数组进行解构，但请注意，在解构时元素的顺序是很重要的。让我们看看这两个函数的结果。请注意，由于这是一个 JavaScript 文件，我们只需要调用 Node。运行以下命令：

```ts
node destructuring.js 
```

您将看到这两个函数的以下结果：

![图 3.6 – 解构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.06_B15508.jpg)

图 3.6 – 解构

正如您所看到的，这两个函数都返回了正确的相关数据。

## 休息

`…`关键字。任何 rest 参数都是数组，因此可以访问所有数组函数。rest 关键字指的是"其余的项目"，而不是"暂停"或"停止"。这个关键字在创建函数签名时提供了更多的灵活性，因为它允许调用者确定他们想要传递多少参数。请注意，只有最后一个参数可以是 rest 参数。以下是使用 rest 的一个例子。创建一个名为`rest.js`的文件，并添加以下代码：

```ts
function doSomething(a, ...others) {
    console.log(a, others, others[others.length - 1]);
}
doSomething(1,2,3,4,5,6,7);
```

正如您所看到的，`…others`指的是`a`之后的其余参数。这表明 rest 参数不必是函数的唯一参数。因此，如果您运行此代码，您会得到以下结果：

![图 3.7 – Rest](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.07_B15508.jpg)

图 3.7 – Rest

`doSomething`函数接收两个参数：`a`变量和`a`参数，rest 参数（再次是参数数组），以及 rest 参数的最后一个元素。Rest 并不像 spread 和解构那样经常使用。尽管如此，您会看到它，所以您应该意识到它。

在本节中，我们学习了使代码更简洁和易读的 JavaScript 特性。这些特性在现代 JavaScript 编程中非常常见，因此学会使用这些功能将使您受益匪浅。在下一节中，我们将学习一些非常重要的数组操作技术，这些技术可以简化处理数组，并且也非常常用。

# 学习新的数组函数

在本节中，我们将回顾 ES6 中用于操作数组的许多方法。这是一个非常重要的部分，因为你将经常在 JavaScript 编程中处理数组，并且使用这些性能优化的方法比创建自己的方法更可取。使用这些标准方法还可以使代码更一致和易读，其他开发人员在你的团队上也会更容易理解。我们将在 React 和 Node 开发中广泛利用这些方法。让我们开始吧。

## find

`find`关键字允许你从数组中抓取与搜索条件匹配的第一个元素。让我们看一个简单的例子。创建`find.ts`并添加以下代码：

```ts
const items = [
    { name: 'jon', age: 20 },
    { name: 'linda', age: 22 },
    { name: 'jon', age: 40}
]
const jon = items.find((item) => {
    return item.name === 'jon'
});
console.log(jon);
```

如果你看一下`find`的代码，你会发现它接受一个函数作为参数，这个函数是在寻找名为`jon`的项目。该函数进行真值检查，以判断项目的名称是否等于`jon`。如果项目的真值检查为真，`find`将返回该项目。然而，你也可以看到数组中有两个`jon`项目。让我们编译并运行这段代码，看看哪一个会返回。运行以下命令：

```ts
tsc find –target 'es6'
node find
```

编译并运行上述命令后，你应该会看到以下结果：

![Figure 3.8 – find](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.08_B15508.jpg)

Figure 3.8 – find

你可以在输出中看到第一个找到的`jon`项目被返回。这就是`find`的工作方式；它总是只返回一个项目——数组中找到的第一个项目。

## filter

`filter`与`find`类似，只是它返回所有匹配搜索条件的项目。让我们创建一个名为`filter.ts`的新文件，并添加以下代码：

```ts
const filterItems = [
    { name: 'jon', age: 20 },
    { name: 'linda', age: 22 },
    { name: 'jon', age: 40}
]
const results = filterItems.filter((item, index) => {
    return item.name === 'jon'
});
console.log(results);
```

正如你所看到的，`filter`函数也可以接受数组中项目的索引号作为可选的第二个参数。但是，内部实现上，它看起来与`find`的工作方式相同，都是通过真值检查来判断是否找到了某个匹配项。然而，对于`filter`来说，所有匹配项都会被返回，如下所示：

![Figure 3.9 – filter](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.09_B15508.jpg)

Figure 3.9 – filter

正如你所看到的，对于`filter`来说，所有满足过滤条件的项目都会被返回，这在这个示例中是两个`jon`项目。

## map

`map`函数是 ES6 风格编码中需要了解的更重要的数组函数之一。它经常出现在 React 组件创建中，以便从数据数组中创建一组组件元素。请注意，`map`函数与`Map`集合不同，我们将在本章后面介绍。创建一个名为`map.ts`的新文件，并添加以下代码：

```ts
const employees = [
    { name: 'tim', id: 1 },
    { name: 'cindy', id: 2 },
    { name: 'rob', id: 3 },
]
const elements = employees.map((item, index) => {
    return `<div>${item.id} - ${item.name}</div>`;
});
console.log(elements);
```

正如你所看到的，`map`函数有两个参数，`item`和`index`（你可以随意命名，但顺序很重要），它将自定义的返回值映射到每个数组元素。要清楚，`return`意味着将每个项目返回到一个新数组中。它并不意味着返回并停止运行迭代。如果我们运行代码，结果将是以下 DOM 字符串：

![Figure 3.10 – map](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.10_B15508.jpg)

Figure 3.10 – map

这个函数实际上可能是最常见的 ES6 数组函数，所以你非常重要要理解它是如何工作的。尝试修改代码并练习使用它与不同的数组项目类型。

## reduce

`reduce`函数是一个聚合器，它接受数组中的每个元素，并根据自定义逻辑创建一个最终值。让我们看一个例子。创建一个`reduce.js`文件——同样，我们将使用 JavaScript 文件来减少 TypeScript 编译器的一些噪音，并专注于代码——并添加以下代码：

```ts
const allTrucks = [
    2,5,7,10
]
const initialCapacity = 0;
const allTonnage = allTrucks.reduce((totalCapacity,  currentCapacity) => {
    totalCapacity = totalCapacity + currentCapacity;

    return totalCapacity;
}, initialCapacity);
console.log(allTonnage);
```

在这个例子中，让我们想象一下我们需要计算一家卡车公司所有卡车的总吨位容量。然后，`allTrucks`列出了它所有卡车的吨位。然后，我们使用`allTrucks.reduce`来获得所有卡车的总容量。`initialCapacity`变量仅用于有一个起始点，目前设置为`0`。然后，当我们记录最终值时，我们会看到以下结果：

![图 3.11 - reduce](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.11_B15508.jpg)

图 3.11 - reduce

所有卡车的总容量是`24`，因为每辆卡车的容量之和为 24。请注意，reducer 的逻辑可以是任何内容；它不一定要是求和。它可以是减法或者您可能需要的任何其他逻辑。核心点在于最终，您将只有一个单一的值或对象结果。这就是为什么它被称为`reduce`。

## some 和 every

这些函数旨在测试特定的条件。因此，它们只返回`true`或`false`。`some`用于检查数组中是否有*任何*元素满足特定条件，而`every`用于检查*所有*元素是否满足特定条件。让我们来看看两者。创建一个名为`someEvery.js`的文件，并添加以下代码：

```ts
const widgets = [
    { id: 1, color: 'blue' },
    { id: 2, color: 'yellow' },
    { id: 3, color: 'orange' },
    { id: 4, color: 'blue' },
]
console.log('some are blue', widgets.some(item => {
    return item.color === 'blue';
}));
console.log('every one is blue', widgets.every(item => {
    return item.color === 'blue';
}));
```

代码非常简单，`some`和`every`的两个条件都被测试了。如果你运行这段代码，你会看到以下结果：

![图 3.12 - someEvery](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.12_B15508.jpg)

图 3.12 - someEvery

如您所见，结果对每个测试都是有效的。

在本节中，我们学习了 ES6 中添加的许多新函数，这些函数可以帮助我们更有效地处理和使用 JavaScript 中的数组。在构建应用程序时，您肯定会在自己的代码中使用许多这些函数。接下来，我们将学习一些可以用来替代数组的新集合类型。

# 学习新的集合类型

ES6 有两种新的集合类型，`Set`和`Map`，它们对于特定的场景可能会很有用。在本节中，我们将学习这两种类型以及如何为它们编写代码，以便在我们开始构建应用程序时稍后使用它们。

## Set

`Set`是一组唯一值或对象。当您只想查看一个项目是否包含在一个大型复杂列表中时，这是一个很好的函数。让我们看一个例子。创建一个名为`set.js`的新文件，并添加以下代码：

```ts
const userIds = [
    1,2,1,3
]
const uniqueIds = new Set(userIds);
console.log(uniqueIds);
uniqueIds.add(10);
console.log('add 10', uniqueIds);
console.log('has', uniqueIds.has(3));
console.log('size', uniqueIds.size);
for (let item of uniqueIds) {
    console.log('iterate', item);
}
```

`Set`对象有许多成员，但这些是它最重要的一些特性。正如您所看到的，`Set`有一个构造函数，可以接受一个数组，使该数组成为一个唯一集合。

重要提示

关于集合，`size`用于检查数量而不是长度。

在底部，请注意迭代`Set`与正常使用数组索引的方式不同。运行此文件将产生以下结果：

![图 3.13 - Set](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.13_B15508.jpg)

图 3.13 - Set

从概念上讲，它仍然与数组非常相似，但是针对唯一集合进行了优化。

## Map

`Map`是键值对的集合。换句话说，它是一个字典。`Map`的每个成员都有一个唯一的键。让我们创建一个示例`Map`对象。创建一个名为`mapCollection.js`的新文件，并添加以下代码：

```ts
const mappedEmp = new Map();
mappedEmp.set('linda', { fullName: 'Linda Johnson', id: 1 });
mappedEmp.set('jim', { fullName: 'Jim Thomson', id: 2 });
mappedEmp.set('pam', { fullName: 'Pam Dryer', id: 4 });
console.log(mappedEmp);
console.log('get', mappedEmp.get('jim'));
console.log('size', mappedEmp.size);
for(let [key, val] of mappedEmp) {
    console.log('iterate', key, val);
}
```

正如您所看到的，一些调用与`Set`非常相似。然而，一个不同之处在于底部的迭代循环，它使用数组来指示键和值。运行此文件将产生以下输出：

![图 3.14 - mapCollection](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.14_B15508.jpg)

图 3.14 - mapCollection

这很简单。首先，记录了所有`Map`对象的列表。然后，我们使用`get`通过其键值获取了`jim`项。接下来是`size`，最后是对所有元素的迭代。

本节展示了 ES6 中的两种新集合类型。这些类型并不经常使用，但如果您有这些集合所需的需求，它们可能会派上用场。在下一节中，我们将讨论`async await`，这是一个 ES7 功能。`async await`已经被 JavaScript 开发者社区广泛采用，因为它使难以阅读的异步代码变得更加可读，并使其看起来像是同步的。

# 学习关于`async await`

在解释`async`和`await`之前，让我们解释一下什么是异步代码。在大多数语言中，代码通常是同步的，这意味着语句一个接一个地运行。如果有语句`A`，`B`和`C`，语句`B`在语句`A`完成之前无法运行，语句`C`在语句`B`完成之前无法运行。然而，在异步编程中，如果语句`A`是异步的，它将开始，但紧接着，语句`B`将立即开始。因此，语句`B`在运行之前不会等待`A`完成。这对性能来说很好，但使代码更难阅读和修复。JavaScript 中的`async` `await`试图解决其中一些困难。

因此，异步编程提供了更快的性能，因为语句可以同时运行，而无需等待彼此。然而，为了理解异步编程，我们首先需要理解回调。回调是 Node.js 编程自诞生以来的核心特性，因此理解它是很重要的。让我们看一个回调的例子。创建一个名为`callback.js`的新文件，并输入以下代码：

```ts
function letMeKnowWhenComplete(size, callback) {
    var reducer = 0;
    for (var i = 1; i < size; i++) {
        reducer = Math.sin(reducer * i);
    }
    callback();
}
letMeKnowWhenComplete(100000000, function () { console.log('Great it completed.'); });
```

如果我们看一下这段代码，我们可以看到`letMeKnowWhenComplete`函数有两个参数。第一个参数表示要进行数学计算的迭代的大小，第二个参数是实际的回调。从代码中可以看出，`callback`是一个在数学工作完成后执行的函数，因此得名。准确地说，技术上回调实际上并不是异步的。然而，它提供了实际上相同的能力，即次要工作，即回调，在主要工作完成后立即完成，而无需等待或轮询。现在，让我们看一下 JavaScript 的第一种异步完成方法。

JavaScript 获得的第一个执行异步的能力是使用`setTimeout`和`setInterval`函数。这些函数很简单；它们接受一个回调，一旦指定的时间完成，就会执行。在`setInterval`的情况下，唯一的区别是它会重复。这些函数之所以真正是异步的原因是，当计时器运行时，它在当前的`setTimer.js`之外运行，并输入以下代码：

```ts
// 1
console.log('Let's begin.');
// 2
setTimeout(() => {
    console.log('I waited and am done now.');
}, 3000);
// 3
console.log('Did I finish yet?');
```

让我们回顾一下这段代码。我已经添加了注释来分隔主要部分。首先，在注释 1 下，我们有一个日志消息，指示这段代码正在开始。然后，在注释 2 下，我们有`setTimeout`，它将在等待 3 秒后执行我们的箭头函数回调。当回调运行时，它将记录它已经完成。在`setTimeout`之后，我们看到另一个日志消息，在注释 3 下，询问计时器是否已经完成。现在，当您运行这段代码时，将会发生一件奇怪的事情，如下图所示：

![图 3.15 - setTimer](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.15_B15508.jpg)

图 3.15 - setTimer

最后一个日志消息询问“我完成了吗？”将首先运行，然后完成日志“我等待并且现在完成了”。为什么呢？`SetTimeout`是一个异步函数，所以当它执行时，它允许之后写的任何代码立即执行（即使`setTimeout`还没有完成）。这意味着在这种情况下，注释 3 中的日志实际上在注释 2 中的回调之前运行。因此，如果我们想象注释 3 中有一些需要立即运行的重要代码，而不需要等待注释 2，我们就可以看到使用异步调用对性能有多么有帮助。现在，让我们结合对回调和异步调用的理解，来看一下 Promise。

在`async await`之前，异步代码是使用 Promises 来处理的。`Promise`是一个在未来某个不确定的时间延迟完成的对象。`Promise`代码的一个例子可能是这样的。创建一个名为`promise.js`的文件，并添加以下代码：

```ts
const myPromise = new Promise((resolve, reject) => {
    setTimeout(() => {
        //resolve('I completed successfully');
        reject('I failed');
    }, 500);
});
myPromise
.then(done => {
    console.log(done);
})
.catch(err => {
    console.log(err);
});
```

在这段代码中，我们首先创建一个`Promise`对象，并在内部使用异步计时器在 500 毫秒后执行一个语句。在第一次尝试中，我们故意通过调用`reject`来使计时器失败，这会导致`Promise`定义下面的代码进入`catch`处理程序。现在，如果我们注释掉`reject`，然后取消注释`resolve`，底部的代码将进入`then`处理程序。显然，这段代码是有效的，但是如果想象一个更复杂的`Promise`，有许多`then`语句，甚至有许多 Promise，那么阅读和理解将变得越来越复杂。

这就是`async await`的作用。它有两个主要作用：它清理了代码，使其更简单更小，并且使代码更易于理解，因为它*看起来*像同步代码。让我们看一个例子。创建一个名为`async.js`的新文件，并添加以下代码：

```ts
async function delayedResult() {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            resolve('I completed successfully');
        }, 500);
    });
}
(async function execAsyncFunc() {
    const result = await delayedResult();
    console.log(result);
})();
```

这段代码有一个名为`delayedResult`的函数，正如您所看到的，它在前面有`async`前缀。在函数前面加上`async`告诉运行时，这个函数将返回一个`Promise`，因此应该异步处理。在`delayedResult`之后，我们看到一个名为`execAsyncFunc`的函数，它同时声明和执行。如果您不熟悉它，这种能力被称为`execAsyncFunc`函数也是`async`-capable，并且正如您所看到的，它内部使用了`await`关键字。`await`关键字告诉运行时，我们即将执行一个异步函数，因此它应该代表我们等待，然后，一旦语句完成，给我们实际的返回值。如果我们运行这段代码，我们会看到以下内容：

![图 3.16 – 异步](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.16_B15508.jpg)

图 3.16 – 异步

正如您所看到的，`result`变量包含`I completed successfully`字符串，而不是`delayedResult`通常返回的`Promise`。这种语法显然比有许多嵌套的`Promise` `then`语句更短更易读。请注意，`async`和`await`已经在 JavaScript 社区中取代了异步开发。您必须深刻理解它，才能成功地使用现代 JavaScript。我们将看一个更多的例子来加深理解。

重要提示

我们必须为`execAsyncFunc`函数使用 IIFE，因为在当前的 JavaScript 中，不允许顶层的`await`。顶层的`await`基本上意味着能够运行一个不在另一个`async`函数内部的函数的等待调用。在 JavaScript 的 ECMAScript 2020 版本中，这是被启用的，但在撰写本文时，它尚未完全在所有浏览器中得到支持。

因为`async await`非常重要，让我们再看一个例子。让我们调用一个网络资源来获取一些数据。我们将使用`fetch` API，但由于 Node 不支持它，我们需要先安装另一个`npm`包。以下是步骤：

1.  在终端中运行以下命令以安装`fetch`：

```ts
npm i node-fetch
```

1.  创建一个名为`fetch.js`的文件，并输入以下代码：

```ts
const fetch = require('node-fetch');
(async function getData() {
    const response = await fetch('https://pokeapi.co/api/v2/     pokemon/ditto/');
    if(response.ok) {
        const result = await response.json();
        console.log(result);
    } else {
        console.log('Failed to get anything');
    }
})();
```

请注意，在这个例子中，代码的易读性和自然流程。正如您所看到的，我们正在使用`fetch` API，它允许我们进行异步网络调用。在导入`fetch`之后，我们再次创建一个`async`包装函数来执行对我们的`fetch`函数的`await`调用。如果您想知道，URL 是一个不需要身份验证的宠物小精灵角色的公共 API。第一次调用`await`是为了实际的网络调用本身。一旦该调用完成，使用`response.ok`进行成功检查。如果成功，再次调用`await`将数据转换为 JSON 格式。每次调用`await`都会阻塞代码，直到函数完成并返回。

我们正在*等待*，因为没有来自网络 API 的数据，所以我们别无选择，只能等待。如果运行此代码，您将看到以下数据：

![图 3.17 – 获取](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_3.17_B15508.jpg)

图 3.17 - 获取

当这段代码运行时，你可能会注意到代码完成之前有一小段延迟。这显示了代码需要等待数据的网络调用完成。

在本节中，我们了解了什么是异步编程。我们还讨论了 Promise，这是 JavaScript 中异步编程的基础，以及`async await`，它为我们提供了一种简化异步代码的方法。你将会在 React 和 Node 开发中大量看到`async await`的使用。

# 总结

在这一章中，我们看了很多 JavaScript 编程的新功能，比如用`async await`合并对象和数组的方法，这是一种新的非常流行的处理异步代码的方式。理解这些功能非常重要，因为它们在现代 JavaScript 和 React 开发中被广泛使用。

在接下来的部分中，我们将开始深入学习使用 React 进行单页应用程序开发。我们将开始使用本章学到的许多功能。
