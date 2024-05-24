# Angular 和 BootStrap Web 开发第三版（四）

> 原文：[`zh.annas-archive.org/md5/C3E0BC11B26050B30F3DD95AAA2C59BD`](https://zh.annas-archive.org/md5/C3E0BC11B26050B30F3DD95AAA2C59BD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：依赖注入和服务

在本章中，我们将研究**依赖注入**（**DI**）。虽然 DI 不是您必须直接在 Angular 中编程的东西（因为 Angular 会为我们处理所有 DI 管道），但了解它仍然非常有用。这是因为 Angular 在管理其服务时大量使用 DI，以及您在创建 Angular 应用程序时可能编写的任何自定义服务。

在下一章中，我们将研究 Angular 最重要的内置服务之一，即其 HTTP 服务，第十二章，*集成后端数据服务*。没有 HTTP 服务，我们的应用程序将非常无聊，因为它们将无法向外部来源（包括我们自己的后端 API）发送数据或接收数据。因此，本章将有助于我们更好地理解 Angular 如何将诸如其 HTTP 服务之类的服务注入到我们的应用程序中供我们使用。此外，这个主题是进入下一章的完美过渡。

以下是本章将涵盖的主题列表：

+   什么是 DI？

+   它解决了什么问题？

+   使用 DI 的额外优势

+   揭示 Angular 用于使一切正常运行的魔法

+   我们如何防范代码最小化（以及为什么我们需要这样做）

在本章结束时，您将对这种经常被误解的软件设计模式有扎实的理解，更重要的是，它是如何工作的。我敢说，您甚至可能开始感觉比大多数同行更具技术先进性。许多开发人员有时甚至难以定义 DI——因为需要一些努力来理解它。

话不多说，让我们开始吧，通过*注入*更多软件设计知识来发现 DI 的全部内容。

# 什么是 DI？

不废话，DI 是**控制反转**（**IoC**）设计模式的一个特定案例。

为了理解 DI 的高级定义，甚至是 IoC，我们首先需要快速定义设计模式。设计模式是软件设计中常见问题的可重用解决方案。有数十种软件设计模式，它们通常被分类为以下三个高级类别：

+   创建模式

+   结构模式

+   行为模式

在我们的情况下，为了简洁起见，我们可以安全地忽略创建和结构类别的设计模式，因为 DI 是一种行为设计模式。在我们了解 IoC 设计模式之前，让我们先描述一下行为设计模式是什么。

简而言之，行为设计模式关注对象之间的通信方式。其中一种模式被称为观察者设计模式，它基本上规定了对象如何通知其依赖对象其状态何时发生变化。

另一个行为设计模式被称为发布-订阅设计模式，这是一种类似观察者模式但更加复杂的消息模式。另一个行为设计模式是模板方法。这种设计模式的目的是将算法的具体实现推迟到子类中。所有这些设计模式的总体思想都是它们之间的通信方式（即消息）。

拥有了模板方法的定义，我们离理解 DI 的本质更近了一步，但在我们开始之前，还有一个设计模式需要定义。你猜对了——IoC 设计模式。记住，DI 是 IoC 模式的一个特例，所以我们确实需要快速了解一下它是什么。

IoC 颠覆了典型的过程式或命令式代码流程。它不是由自定义对象的代码控制程序流程，而是将实例化的过程推迟到一个框架来完成。这一切马上就会变得清晰起来。有趣的是，有时候这被戏称为“不要打电话给我们，我们会打电话给你”。

我们很快将看一个例子，以便一切都说得通。然而，我需要定义一下我所说的框架实例化依赖对象的意思。你难道不喜欢我们需要了解的所有术语和概念吗？（笑）这个框架通常被称为 IoC 容器。这些容器足够智能，能够检查自定义代码，找出它依赖的其他对象，实例化这些对象，并将它们传递到自定义对象的构造函数中。这与传统方式相反，传统方式是在自定义对象本身内部实例化对象的依赖项。相反，IoC 容器为其执行这些职责。一会儿，我将把这与 Angular 联系起来，并给出 IoC 模式提供的一些非常重要的优势，但我们将从 DI 的角度来讨论——最后！

好的。让我们试着把这一切联系起来，并提供一个示例场景或用例。Angular 框架提供了 IoC 容器的功能——除了提供的所有其他功能之外。由于 Angular 是一个模块化框架，并且封装了大部分功能在分离的服务中，因此它的 IoC 功能也被封装在其中一个服务中——事实上，就是这种情况。

Angular 负责 DI 的服务是其注入器服务，恰如其名，因为它在实例化后将你的自定义类的依赖项注入到你的类构造函数中。不仅如此，它还为你调用自定义方法，回到我之前提到的，*别打电话给我们，我们会打电话给你*。我们所需要做的就是在自定义类的构造函数签名中列出依赖项的名称。

从现在开始，我不会再提 IoC，因为我们正在谈论 DI——再次强调，这在技术上不是 IoC，而是它的一个特例。我之所以提到这一点，是因为许多开发人员将 IoC 和 DI 视为同义词。

那么，让我们问几个问题：由于 DI 是一种设计模式，设计模式解决常见的软件设计问题，DI 解决了什么问题？DI 的优势是什么？这些都是很好的问题，我相信我可以在接下来的两段话中一举解答。

即使是面向对象的代码也存在一个很长时间的问题，那就是一个依赖其他类的类（这也是面向对象的重点——因为我们不希望一个类来完成所有的工作）在自身内部包含了实例化这些依赖关系的代码，并且结果是至少部分逻辑也与之交织在一起。这被称为紧密耦合的代码。紧密耦合的代码有两个问题：首先，实现逻辑通常封装在类内部——这是我们不想要的。我们不希望一个对象了解其他对象的内部工作。例如——如果我们想要更改依赖类中算法的实现，我们很可能也必须更改调用它的类中的代码。由此产生的另一个问题是，这种代码很难测试。我们的类耦合得越紧，对它们进行单元测试就越困难——这个问题已经存在了很长时间。

好的。那么 DI 是如何解决这些问题的呢？我们将会通过一个具体的用例来让我们更清楚地理解一切，但首先让我们描述一下 DI 给我们带来的一些优势。DI 原则的第一个优势是它强制我们编写解耦的代码。我们通过让我们依赖的类（用于其抽象实现）实现接口来实现这一点，我们这样做是因为我们调用的类只需要调用这些对象上的接口方法，而不关心底层类方法的实现细节。当我们以这种方式编写代码时，我们可以替换我们依赖的具有特定实现的类，用另一个具有另一种实现的类，而不需要更改我们的任何调用代码（因为我们的代码调用这些类实现的接口方法）。这有时也被称为按接口编码。还有一点有趣的是：这种技术也被用于一种称为面向方面编程（AOP）的编程风格中。

遵循 DI 设计原则所获得的一个非常有用的东西是，我们可以非常容易地测试我们的代码——与无法轻松测试我们的代码，或者根本无法测试我们的代码相比。我们如何做到这一点呢？通过编写存根和/或模拟类——这些类也实现了我们调用的这些相同的接口。

顺便说一句，存根和模拟之间有一个重要的区别。存根是愚蠢的类，通常只返回一个简单的值（通常是硬编码的）。另一方面，模拟对象通常具有完整的实现，以便测试边缘情况，以及进行数据库操作或进行 RESTful API 调用。模拟可以用来做任何你的测试需要的事情。所以，存根是愚蠢的，而模拟是聪明的。然而，它们的共同之处在于，它们通过具有相同的对象消息模式（也就是，它们的方法是通过接口调用的）来帮助我们对调用类的代码进行单元测试。

呼！我们完成了理论部分！你是不是已经睡着了，还是还在听我说话？啊，你醒着了——好的。现在所有的理论都已经讲完了，让我们来看一个使用 DI 的示例用例，以便我们可以将这些概念牢固地铭刻在我们的脑海中。

假设我们正在为一个在线商店构建一个电子商务应用程序，我们在这里出售我们自制的啤酒。我们的应用程序将需要一个购物车，我们还必须至少有一个商户账户（这是一个通道，被称为支付处理网关，这样我们就可以向我们的客户收取信用卡费用）。在这个假设的情景中，我们有两个商户账户——也许是因为我们想保留一个备用账户，以防主要的商户账户增加他们的折扣率（也就是费用），从而降低我们的利润——但重点是，我们有两个商户账户。

在实现购物车时，我们希望能够在不更改购物车类中的代码的情况下，将一个商家账户替换为另一个商家账户，如果需要的话。我们不希望更改任何代码的原因是，我们可能会在我们的应用程序（在线商店）中意外引入错误，这对顾客来说并不好看。你可能会说——*嘿，我测试我的代码——所以错误都被找出来了*——如果你这样说，那么你正好掉入了使用 DI 为我们的应用程序带来的下一个好处，那就是我们可以通过编写测试类轻松测试我们的应用程序——还记得我们的存根和模拟吗？是的——我们编写存根和模拟，这样我们就可以测试我们的代码。再次感谢 DI，我们不必更改我们的购物车类来实现这一点。我们的存根和模拟实现接口。我们会将银行的 API（即，由第三方编写的商家账户类）封装在一个实现我们接口的自定义类中，这样所有这些类（即我们的存根、模拟和封装的真实银行对象）都可以以完全相同的方式被调用。

很好。所以，作为一个额外的奖励，让我们快速看一下 Angular 如何知道我们的类需要什么，以及它如何为我们调用我们类的构造函数方法。嗯，这并不是魔术，但确实很巧妙。然而，Angular 确实需要我们的一点点前期帮助。当我们为我们的应用程序创建自定义类时，通常会将它们封装为 Angular 服务（我们将在下一章第十二章中看到服务，*集成后端数据服务*）。Angular 要求我们在其中注册这些服务，并且您将看到为什么我们需要在一会儿这样做。

Angular 的注入器服务扫描我们的代码，具体来说，扫描我们类的构造函数签名，并找出其参数。因为我们的参数是我们类需要的服务，它知道这些参数是服务。然后，它将服务名称的文本与自己的服务清单以及我们自己编写的任何自定义服务进行匹配，当找到匹配时，它实例化该服务对象。它之所以能够做到这一点，是因为它知道自己的服务，也知道我们编写的服务，因为我们必须在 Angular 中注册它们。

一旦 Angular 实例化了这些服务对象，下一步就是调用我们类的构造函数，并将对象作为参数传递进去。这就是 Angular 的注入器服务所做的注入过程。再说一遍：*不要打电话给我们，我们会打电话给你*。就像这样，Angular 背后的魔法已经被解释清楚了。不过，这仍然非常酷，我们应该向 Angular 开发团队致敬。

# 生成服务和接口

现在我们已经了解了 DI 和设计模式，在本节中，我们将学习如何创建我们的服务。Angular CLI 为我们提供了在项目内部生成服务的最快最简单的方法。我们将通过运行以下命令创建一个名为`LearningDIServices`的示例项目：

```ts
ng new LearningDIServices
```

我们使用`ng`命令创建一个新的 Angular 项目，并将项目命名为`LearningDIServices`。成功执行命令后，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/0dc77003-59b5-4b85-b4c9-b2d981395a23.png)

现在我们已经创建了项目目录，使用 Angular CLI，我们将生成一些服务和接口。我们将创建一个名为`Photos`的服务。运行以下命令，我们应该看到服务已添加到我们的项目目录中：

```ts
ng generate service photos
```

成功执行后，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/fc60bcb9-dd04-46a4-9496-239097d1edfe.png)

我们可以看到生成了两个新文件。一个是服务文件，另一个是用于编写服务测试的规范文件。让我们仔细看看包含自动生成代码的`photo.service.ts`文件：

```ts
import { Injectable } from  '@angular/core'; @Injectable({
 providedIn: 'root' })

export  class PhotosService { constructor() { } }
```

在前面的代码中，我们可以看到`Injectable`类需要从`angular/core`库中导入。`Injectable`类允许我们将服务注入到各种组件类中，以便我们可以重用方法。使用可注入的装饰器，我们明确指出服务需要在根中注入。最后，我们导出我们的`PhotosService`类，其中将包含我们将为我们的应用程序创建的构造方法和其他方法。

与 Angular 组件不同，无需更新`app.module.ts`文件以添加服务的条目。

在之前的章节中，我们学习了接口的概述。现在，让我们快速学习如何在我们的应用程序中使用接口。使用 Angular CLI，我们也可以快速创建接口：

```ts
ng generate interface photo
```

在上面的命令中，我们生成了一个名为`photo`的接口，一旦上面的命令成功执行，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f020b705-6285-4798-8da1-ca1a2ce25e9a.png)

让我们仔细看看生成的接口文件。以下是默认生成的代码：

```ts
export  interface Photo { }
```

我们可以看到它是故意留空的。由于接口用于定义实体或模型类，应用程序中创建的每个接口都将是独特的，并且特定于每个应用程序。现在，如果我们想为我们的照片创建一个接口，我们将不得不定义如下：

```ts
export interface Photo {
 photoId: number;
 photoURL: string;
 photoOwner: string;
 isActive: boolean;
}
```

在上面的示例代码中，我们为照片创建了一个带有一些属性和它们的数据类型的接口。这将允许我们为照片创建严格类型的对象。

在本节中，我们学习了如何创建 Angular 服务和接口。即使一些概念不是很清楚，不要担心，我的朋友。我们有一个完整的章节专门向您展示如何在我们的应用程序中生成和实现服务。在下一章中，我们将学习如何实现和使用它们，并将它们集成到我们的组件中。

# 防止代码最小化

有一件我想很快覆盖的最后一件事，那就是代码缩小以及我们如何防范它。代码缩小是通过去除空格以及用非常短的符号替换变量名来压缩我们的代码的过程。这是在我们编译 Angular 应用程序时完成的，这样它就成为了一个更小的包，我们的用户必须下载（一旦我们部署了我们的应用程序）来检索我们的应用程序。但这对我们来说确实存在问题。它可能会通过更改参数名称来破坏我们的一天，然后 Angular 就无法再将名称与服务清单匹配。幸运的是，有一个简单的解决方案。如果我们在参数名称周围添加单引号，我们就可以保护我们的代码免受代码缩小的影响。怎么做呢？好吧，在服务名称周围加上引号会将它们转换为文字字符串，而缩小过程不会压缩或更改字符串——它们会保持原样。这是因为文字字符串在语法之外有意义，不是代码。缩小只是缩小代码（即变量和函数名称以及空格）。这就是你需要知道的关于保护你的代码免受代码缩小的影响的一切。

# 总结

现在你应该对 DI 是什么以及它解决了什么问题感到满意。你也应该能够列举一些优势，从而能够解释为什么 DI 是我们在设计应用程序时要遵循的一个好原则。你还应该能够轻松地解释 Angular 在使一切都能开箱即用方面表现出的看似神奇的技能。最后，你现在也应该知道如何保护你的 DI 代码免受代码缩小的影响。

掌握了这些 DI 知识，我们现在可以继续我们的旅程，探索 Angular 最有用的服务之一，即它的 HTTP 服务，在第十二章中，*集成后端数据服务*。一旦你完成了下一章，你就可以准备编写代码，将你的 Angular 应用程序与几乎任何符合 RESTful API 标准的应用程序和/或服务集成，只要你的应用程序被授权与之通信。这对你来说应该是令人兴奋的！如果是的话，翻页并继续你的 Angular 启蒙之旅。


# 第十二章：集成后端数据服务

欢迎来到第十二章！这绝对是我最喜欢的一章，因为我们将为我们的应用构建许多端到端的用例。

一个温和的警告——这一章内容密集——充满了大量的信息。你可能需要以较慢的速度阅读，并花更多时间在键盘上，比你在以前的章节中花的时间更多，但我必须说，这是非常值得的努力。

这是一个很好的方式来看待本书的整体进展：

+   到目前为止，我们所看到的一切，包括最近的两章（第十章，*使用表单*，和第十一章，*依赖注入和服务*），都为这一章奠定了基础。有了这些知识，我们现在准备好把它们整合起来，以创建我们的应用。因此，从本质上讲，这一章也是为了回顾我们在以前章节中涵盖的许多主题。

+   这一章对我们来说是一个关键的转折点，因为我们将把迄今为止学到的一切都用在这一章中构建我们应用的 95%。这是一个章节中的大量材料，但我们已经花了很多时间来讨论我们需要构建应用的所有 Angular 方面，所以我们将轻松地完成它。还有一些新的和略微离题的材料——学习如何构建后端 API——这比 Angular 材料更不重要。然而，我们需要有一个 API，所以我选择了一套简单的技术，可以快速上手。我们还要讨论这个问题，以帮助你了解我们将用来构建 API 的技术。

+   在接下来的章节中，我们将为我们的应用添加一些东西（如路由守卫和自定义表单验证），并学习如何测试、调试、保护和部署我们的应用。

因此，从这个角度来看，我们已经准备好了。本章中的许多部分都是我认为重要学习的额外材料，因为我希望你不仅作为一个 Angular 开发者成功，而且作为一个网页开发者成功。这将帮助你提高你的技能，实际示例肯定会增加你作为网页开发者的技术知识。

我们将涵盖以下主题：

+   ListingApp - 概述

+   Angular 应用的基本概念

+   ListingApp - 技术要求

+   为我们的应用构建 APIs

+   Google Firestore 数据库

+   Angular HttpClient

+   集成后端服务

在这本书中，我们花了很多时间讨论了许多事情 - 主要是与 Angular 相关的（如组件、路由、flex-layout、NG Bootstrap、Angular Material 和处理表单），还有一些独立的事情（如线框、ES6、TypeScript 和 Bootstrap）。当然，拥有所有这些知识是很重要的，但我们还没有集成实时数据来使我们的 Angular 应用程序生动起来。然而，正如你从前面的项目列表中所看到的，这将发生改变。这就是 Angular 开发开始变得有趣的地方，也更加实用，因为一个不创建和使用数据的应用程序根本就不是一个应用程序。

好的。让我们立即开始学习构建任何应用程序基础的一些基本概念。然后，我们将看一下构建我们的 ListingApp 所涉及的步骤。

# ListingApp - 概述

在本章中，我们将构建我们的`ListingApp`应用程序。在本节中，我们将介绍功能需求列表。我们的整体应用程序计划可以分为三个主要部分：

+   **UI 层**：UI 方面涉及设计或构建表单、显示数据、路由和验证。

+   **服务或中间件层**：我们将学习如何编写共享服务，这些服务将负责与 API 和数据库进行后端集成。

+   **数据库或虚拟 API 设置**：我们将学习如何使用 JSON Server 设置虚拟 API，并学习如何使用 Firestore 创建我们的 NoSQL 数据库。

这是我们将在本章学习过程中构建的功能用例的完整列表：

+   显示所有列表

+   按 ID 查看列表

+   添加新的列表

+   编辑列表

+   删除列表

+   添加评论

+   更新评论

+   删除评论

+   编辑评论

列出的所有用例都需要我们实现 HTTP 调用。对于一些用例，我们需要进行 POST、GET 和 PUT HTTP 调用。

在我们进一步进行之前，现在是一个很好的时机，回顾我们在整本书中实施的所有学习和功能。我们需要回想一下我们如何设计和开发我们的表单，如何捕获表单数据，如何在组件模板中显示数据，如何使用参数实现路由，以及如何在组件内调用服务中实现的方法。

我们有很多工作要做，还有很多乐趣在等着我们，所以让我们开始吧！

# Angular 应用程序的基本概念

在本章中，我们将学习和构建许多有趣的东西，但在开始之前，我们应该了解一些基本概念，包括强类型语言概念、Angular 模型、可观察对象、NoSQL 数据库和一般的 CRUD 操作。

# 强类型语言

强类型编程语言指的是每种数据类型都是预定义的，并且与变量紧密耦合。看看下面定义的变量：

```ts
int age = 10;
```

我们声明了一个变量，并明确指出变量的类型是整数，这使得很明显变量除了整数之外不能容纳任何其他数据类型。如果我们尝试提供任何不是整数的值，TypeScript 会抛出错误。TypeScript 也是一种强类型语言，因为我们在 TypeScript 中编写我们的 Angular 应用程序，我们可以得出结论，Angular 应用程序遵循强类型格式。

# Typescript 接口

在本节中，我们将学习如何在 TypeScript 中创建我们自己的数据类型，这些类型可以在我们的 Angular 应用程序中使用。

Angular 模型是一种通过将多个数据类型组合成一个对象并定义一个新对象来创建复杂数据结构的方法，然后可以将其作为数据类型本身使用。这是 Angular 确保复杂数据对象遵守某些预定义数据规范的方式。

TypeScript 语言提供了接口，也具有相同的作用。我们还可以利用 ES6 类来定义我们的数据结构。我们可以扩展编程语法来创建我们自定义的数据类型。让我们通过创建一个示例模型来演示这一点。我们将创建一个名为`Listing`的模型，它将具有以下属性：

```ts
export class Listing {
 id: number;
 userId: number;
 title: string;
 status: string;
 price: number;
 active: boolean;
}
```

我们已经创建了一个 Angular 模型，这是一个具有属性的类，例如`id`、`userId`、`title`、`status`、`price`和`active`。现在我们可以在我们的应用程序中使用这个模型作为数据类型。我们可以将这个类导入到所有的组件和服务中，以确保我们的数据映射符合`Listing`数据规范。

在本章中，我们将在构建应用程序时使用先前定义的模型。

# 可观察对象

大多数传统应用程序都是基于请求和响应的架构运行的，这意味着我们的应用程序客户端会向服务器发出数据请求，而服务器会返回响应。在服务器返回响应的同时，我们的应用程序会进入等待模式，直到接收到所有响应，这显然会使应用程序变慢。

这种架构有多个缺点。首先，应用程序等待响应，这会导致应用程序延迟。其次，我们无法处理在一段时间内传入的多个数据。第三，由于我们的应用程序等待直到获得响应，这使得同步调用，我们无法执行异步编程。最后，事件处理对开发人员来说是一场噩梦。那么，我们如何解决上述问题？答案是使用可观察对象。

可观察对象是一种在一段时间内异步返回数据的数组类型。Angular 使用一个名为**Reactive Extensions** (**RxJS**)的第三方库，在框架内部实现了可观察对象，主要用于事件处理、树摇动等。我们还可以轻松导入、创建和订阅自定义可观察对象。

# NoSQL 数据库概念

在本节中，我们将学习有关 NoSQL 数据库的知识。真的吗？NoSQL？我们不打算使用数据库来存储我们的关键数据吗？当然我们会使用数据库来存储我们的数据；但是，它不会是传统的关系型数据库，它具有严格的预定义模式和具有标准数据类型的列。使用 NoSQL 数据库，一切都是面向文档的，我们可以在一个地方存储数据，而不必担心数据类型。NoSQL 数据库保存文档集合。

我们仍然可以执行以下数据库活动：

+   创建文档

+   插入文档

+   编辑现有文档

+   删除文档

我们还可以执行许多高级功能，如索引和身份验证。有许多开源和商业解决方案提供 NoSQL 数据库。以下是一些 NoSQL 数据库提供商的快速列表：

+   MongoDB

+   Redis

+   RavenDB

+   Firestore

+   MemcacheDB

在本章开发我们的应用程序过程中，我们将实现 Firestore 作为我们的后端系统。在下一节中，我们将了解一些涉及这些数据库的重要任务。

# CRUD 操作-概述

每当我们考虑将数据库作为应用程序的后端存储系统时，主要目标是能够添加、检索、搜索或修改数据，这更常被称为 CRUD 操作。

CRUD 代表计算机编程中的创建、读取、更新和删除，这些术语如下所述：

+   **创建**：在数据库中创建或添加新数据。我们通常会在数据库中运行 INSERT 查询。这与 HTTP POST 方法相关联。

+   **读取**：根据过滤器或搜索条件读取或检索数据。我们将在数据库中运行 SELECT 查询来执行此操作。这与 HTTP GET 方法相关联。

+   **更新**：更新或编辑数据库中的现有记录。我们将在数据库中使用 UPDATE 查询。这与 HTTP PUT 方法相关联。

+   **删除**：删除数据库中的现有记录。我们可以使用 DELETE 查询来删除记录，或者只是使用 UPDATE 查询设置一个指示记录已被删除的列。这与 DELETE 方法相关联。

在接下来的章节中，我们将使用这些概念来构建我们的`ListingApp`功能和我们应用程序的技术要求。

# ListingApp - 技术要求

任何良好的动态应用程序都需要我们处理 API，并且我们需要将数据存储在数据库中。本节涵盖了构建任何动态应用程序所需的两个非常重要的技术方面 - JSON API 和动态数据库。我们将使用 JSON 服务器，而对于数据库，我们将使用 Google 的 Firestore 数据库。

# 为 ListingApp 构建 API

在任何项目的开发周期中，作为前端开发人员，我们将需要处理 API 并将其集成到我们的应用程序中。我们需要定义并就我们期望从 API 中得到的 JSON 合同达成一致。在本节中，我们将了解我们在后端开发人员仍在开发实际 API 时可以使用的各种生成 API 的选项。当我们有虚假 API 可用时，开发人员可以独立工作。

有各种各样的工具和库（可免费使用），我们可以用来处理虚假 API。我们将使用 JSON 服务器库来提供我们的 API。所以，让我们从以下步骤开始：

1.  要安装`json-server`库，请在命令行界面中运行以下命令：

```ts
 npm i json-server --save
```

当命令成功运行时，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/4e3c93b3-afdb-45b8-9161-78dda48b28e0.png)

1.  现在我们已经安装了`json-server`库，是时候创建我们的 API 和 JSON 结构了。在我们的项目目录中，我们将创建一个名为 APIs 的新文件夹，并创建一个名为`data.json`的新文件，其中将保存我们的 JSON 数据。创建文件夹和文件后，查看文件夹结构：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/8237c689-9d04-4083-98a3-9e6ede3a2808.png)

1.  由于我们创建了两个 JSON 文件，现在是时候向文件添加一些列表和用户的 JSON 数据了。通过向`listings.json`文件添加以下数据来打开`listings.json`文件：

```ts
      {
        "listings": [
          { "id": 1, "title": "Sunset in New York", "price":"190", 
             "status": "Active" },
          { "id": 2, "title": "Dawn at Miami", "price":"150", 
              "status": "Active" },
          { "id": 3, "title": "Evening in California","price":"70", 
             "status": "Inactive" }
        ],
        "users": [
          { "id": 1, "username": "andrew", 
            "userEmail": "andrew@localhost.com" },
          { "id": 2, "username": "stacy", 
            "userEmail": "stacy@localhost.com" },
          { "id": 3, "username": "linda", 
            "userEmail": "linda@localhost.com" },
          { "id": 4, "username": "shane", 
            "userEmail": "shane@localhost.com" }
        ],
        "cities": [ 
            { "id":1, "name": "New York" },
            { "id":1, "name": "California" },
            { "id":1, "name": "Miami" }
        ]
       }
```

我们正在为列表、用户和城市创建 JSON 数组的虚拟数据。从技术上讲，在实际应用场景中，这些数据将在运行时从数据库中检索。

1.  要开始提供带有数据的虚假 API，我们需要启动和初始化 JSON 文件。我们将转到我们创建了`data.json`文件的`API`文件夹，并运行以下命令：

```ts
 json-server --watch data.json
```

1.  当我们成功运行命令时，应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/89bc400c-4dc3-4bfa-b467-1bafd834cf43.png)

请注意，在资源下，我们可以看到列出的虚假 API；即`http://localhost:3000/listings`。

1.  尝试在浏览器中打开 URL。您应该看到 JSON 数据显示为列表、用户和城市。输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/6cf12696-4bd4-49c2-9fec-e7309c1bc69d.png)

太棒了！现在我们可以在我们的 HTTP 调用中使用这些 API。在我们直接学习 HTTP 功能之前，我们只需要再等待一个部分。对于那些全栈开发人员并且知道如何设置数据库的朋友来说，下一部分肯定是给你们的。我们将学习如何设置我们的 Firestore 数据库，用于存储我们的数据。稍后，我们将使用它来实现我们的应用程序。

# Google Firestore 数据库

Google Firestore 数据库是 Google Cloud 平台的一部分。Google Cloud 的官方网站描述如下：

**Cloud Firestore** 是一个快速、完全托管的、无服务器的、云原生的 NoSQL 文档数据库，简化了在全球范围内为移动应用程序、Web 应用程序和物联网应用程序存储、同步和查询数据。参考：[`cloud.google.com/firestore/`](https://cloud.google.com/firestore/)

Firestore 是由 Google 提供的作为服务的数据库，并提供易于使用的 NoSQL 文档数据库。由于 Firestore 也来自 Angular 的制造商，因此自然会有支持两者之间轻松集成的库。在本节中，我们将学习如何设置 Firestore 数据库。所以，让我们开始：

1.  我们需要使用我们的凭据登录到我们的 Firebase 应用程序。成功登录后，我们应该看到欢迎屏幕，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f0a7086f-2b95-410c-b9ec-0d48243ad883.png)

主页将列出我们在 Firebase 应用程序中创建的所有项目，您还会注意到一个大的“添加项目”链接。

1.  现在，让我们通过单击“添加项目”链接为我们的应用程序创建一个新项目。我们将收到一个模态窗口的提示，需要为我们的项目输入一个“项目名称”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/b3635d56-27a4-41d2-ac9a-e7d101d1bbad.png)

在这里，我们将输入“列表”作为我们的项目名称。一旦我们的项目被配置，我们将被带到新创建的项目页面。

1.  现在，我们在侧边栏菜单中点击“数据库”。我们将被提示选择初始化数据库的模式。我们将为我们的测试选择测试模式，一旦我们执行了实现，我们将切换安全模式：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/7899d48c-9591-4553-9148-0102594e5337.png)

如前面的屏幕截图所示，我们正在使用测试模式中的数据库，这将使我们能够轻松地读取或写入文档。

如果您希望在生产环境中使用数据库，请不要忘记更改数据库的设置。

1.  我们现在将继续创建我们的“评论”集合。我们将添加一个名为`commentId`的唯一标识符。此外，我们正在为将存储在集合中的文档添加三个字段作为模式，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/143676a1-eaea-42ce-8193-f0e4785ffd31.png)

由于 Firestore 是一个 NoSQL 文档数据库，其模式不受任何数据类型的限制。我们现在可以执行 CRUD 操作，例如添加新文档，编辑，甚至删除 Firestore 数据库中的文档。

在过去的两个部分中，我们已经学习了如何使用 JSON Server 创建虚拟 API，并且还使用 Firestore 创建了一个 NoSQL 文档数据库。现在我们已经达到了一个阶段，我们已经学习了开始实现`ListingApp`端到端功能所需的所有基本概念，让我们进入 HTTP 世界吧！

# Angular HttpClient

在本节中，我们将学习 Angular 最重要的方面——`HttpClient`。使用`HttpClient`接口，我们可以执行 HTTP 请求和响应调用。在上一章中，我们学习了依赖注入和服务；在本章中，我们将学习如何编写包含方法的服务，以便我们可以使用`HttpClient`进行 HTTP 调用和处理响应。

`HttpClient`是一个小巧、易于使用、功能强大的库，用于执行 HTTP 请求和响应调用。使用`HttpClient`，我们可以轻松地与后端服务进行通信，该模块支持大多数现代 Web 浏览器。`HttpClient`具有许多高级功能，如拦截器和进度事件。`HttpClient`支持各种 HTTP 方法，包括 GET、POST、PUT、PATCH、DELETE、JSONP 和 options。这些调用中的每一个都会返回一个 observable。我们必须订阅这些 observable 以处理响应。如果我们不订阅，将不会发生任何事情。

`HttpClientModule`位于`@angular/common/http`库中，需要被导入到`app.module.ts`文件中；否则，我们将遇到错误。

我们现在了解了`HttpClient`模块，但在我们开始在应用程序中实现该模块之前，了解一些被添加到`HttpClient`中的关键功能是很重要的：

+   `HttpClient`提供了强类型的响应体。

+   `HttpClient`中的请求/响应对象是不可变的。

+   JSON 格式的响应是默认的。我们不再需要将其映射为 JSON 对象。

+   `HttpClient`提供了拦截器，这在中间件中拦截`HttpRequest`以进行转换或处理响应非常有帮助。

+   `HttpClient`包括可测试性功能。我们可以轻松模拟请求并更有效地处理标头。

在接下来的部分中，我们将学习`HttpClient`模块，它需要被导入到组件或服务中，我们可以在那里进行 HTTP 调用。我们还将学习现代应用程序中可用的 HTTP 动词以及它们的目的。

# HttpClient 和 HTTP 动词

如果前一部分是对`HttpClientModule`和`HttpClient`及其优势的介绍，那么在本节中，我们将深入了解并学习如何编写一些实现`HttpClient`的示例代码。

正如我们之前提到的，`HttpClient`支持 GET、POST、PUT、PATCH、DELETE、JSONP 和 options 方法，这些方法将返回可观察对象。`HttpClient`还提供了模块，可以使用`HttpHeaders`和`HttpParams`轻松传递各种选项和数据。

为了使用`HttpClient`，我们需要将`HttpClientModule`导入到我们的应用程序模块（`app.module.ts`）文件中，还需要将`HttpClient`导入到我们的服务或组件中，并在构造函数中注入`HttpClient`，以便我们可以使用它进行 HTTP 调用。将以下代码添加到您的`app.module.ts`文件中，并不要忘记将其添加到导入模块的列表中：

```ts
// Import the module into the component or service
import { HttpClient } from '@angular/core/http';

// Inside the constructor method inject the HttpClient and create an instance
constructor(private http: HttpClient)
```

现在，让我们实现一些最常用的 HTTP 动词。

我们将分别为 JSON 服务器 API 和 Firestore 数据库实现 HTTP 方法。

# HTTP GET

我们使用 HTTP GET 方法与后端服务通信，从特定 URL 资源中检索信息。获取所有列表的示例代码如下：

```ts
getAllListings():Observable<any>
{
   return this.http.get<Observable>('api/get-listing');
}
```

我们创建了一个名为`getAllListings`的方法，并明确指出该方法将返回任何数据类型的可观察值。我们需要将 URL 传递给 GET 方法。URL 是我们需要传递的必需值。我们还可以传递可选数据，如`Headers`、`Params`、`reportProgress`和`responseType`。GET 方法将返回 RxJS 可观察对象的实例，我们可以订阅以监听响应。

在类似的条件下，我们可以轻松地使用 POST、PUT 和 DELETE 方法创建 HTTP 调用。

# HTTP POST

每当我们需要安全地向服务器发送任何数据或信息，例如用户名、密码和电子邮件时，我们总是使用 POST 方法。HTTP POST 动词总是与创建或添加新数据相关联。它是安全的，不像 GET 方法那样在 URL 中显示数据。在 POST 方法中，我们需要将数据传递给 URL，以及 URL 作为字符串。我们还可以向 POST 方法传递选项，例如 Headers 和 Params。以下是编写示例 HTTP POST 调用的示例代码：

```ts
addNewListing(listing) {
     let httpHeaders  = new HttpHeaders();
     httpHeaders.set('Content-Type', 'application/json');
     let options =  { headers: httpHeaders};

    return this.http.post('api/add-listing', listing, options);

}
```

在前面的代码中，我们正在创建一个名为`addNewListing`的新方法，它接受一个名为 listing 的参数，我们将使用它作为我们的数据。我们正在创建一个`HttpHeaders`的实例，所以我们创建了一个类的对象，并且我们正在将`Content-Type`对象的值设置为`application/json`。然后，我们正在创建变量选项并对其进行格式化以发送标头。最后，我们正在使用`http.post`方法进行 POST 请求。

# HTTP PUT

在这一部分，我们将学习如何进行 HTTP PUT 调用。PUT 方法用于更新或编辑服务器中的现有数据集。HTTP PUT 方法涉及一个两步过程。首先，我们需要检索需要更新的数据，然后使用 POST 方法将更新后的信息传递回服务器。以下是创建 PUT 方法的示例代码：

```ts
this.http.put(url, options);
```

我们需要将 URL 作为 PUT 方法的必需参数传递。幸运的是，有各种可用的选项。例如，我们可以在选项中传递标头、参数等。

# HTTP DELETE

DELETE 是 CRUD 功能的重要操作。我们可以使用 HTTP DELETE 方法轻松执行删除操作。`delete`操作可以根据用例和应用程序的合规性来实现。我们可以进行两种类型的删除操作——软删除和硬删除：

+   **软删除**：在使用软删除时，我们不会从数据库系统中删除或擦除记录；相反，我们会更新记录并设置一个列或字段，并将其标记为已删除，以便用户不会看到这些记录。

+   **硬删除**：请求的数据从数据库系统中永久删除。一旦数据被删除，就无法恢复或恢复。

让我给你举一个很好的例子。如果你试图删除你的谷歌账户，它会通知你，在*x*天内你可以回来恢复你的账户，之后数据将会从他们的服务器上完全删除。

回到我们的实现。我们可以使用`http.delete()`方法来实现应用程序中的 DELETE 功能。示例代码如下：

```ts
this.http.delete(url, options);
```

我们需要将 URL 值作为 PUT 方法的必需参数传递，而选项则是可选的。

# 通过承诺进行 HTTP。

Promises 只是对现实世界承诺的技术实现！假设你答应了老板你会完成分配给你的任务。如果你做到了，那意味着承诺已经实现，如果你没有，那意味着它被拒绝了。同样，HTTP 实现中的 Promise 意味着我们将等待未来的数据，无论是 resolved 还是 rejected，然后我们将根据收到的输出进行一些逻辑处理。

HTTP promises 是一种基于成功或失败状态的未来数据的占位符。这听起来是否类似于常规的 HTTP 调用？是的，它们是，但有一个重大的区别——*promises 是异步的*。当我们在 Angular 中进行 HTTP 调用时，它会等待直到请求完成并收到响应；JavaScript 将继续执行，如果遇到同步赋值/操作，它将立即执行并在它们依赖于先前状态或数据时失败。

一个 promise 接受一个回调方法，该方法将带有两个参数——`resolve`和`reject`。`resolve`意味着该方法将返回一个带有给定消息的 promise 对象，而`reject`意味着 promise 对象被拒绝了。然后，你可以期待`.then`和`.catch`被调用，如果一切顺利或不顺利的话。以下是编写 promise 的示例代码，展示了对`resolve`和`reject`的处理响应：

```ts
//check if the listing status is active
ListingDetails(listing){
let promise = new Promise(function(resolve, reject) {
if(listing.status == 'active') { 
  resolved("listing is active");
}
else {
  reject("listing is not active");
}

promise.then((s => { 
//next steps after the promise has returned resolved
}).catch((err => {
// what to do when it's error or rejected
})

}
```

让我们详细分析前面的代码。我们已经实现了一个 promise，并且按照规定，`callback`方法将会带有两个参数，`resolve`和`reject`。我们检查列表的状态是否为活动状态；如果是，我们就会 resolve 这个 promise；否则，我们会 reject 这个 promise。默认情况下，resolved 方法返回的数据将会传递给`.then`方法，而任何失败或异常将会传递给`.catch`方法。

由于 promises 是异步的，这意味着我们可以链接事件或方法，继续添加一个将在`.then`方法内调用的方法。

太棒了！我们现在掌握了关于 Angular 提供的用于 HTTP 功能的类和模块的所有理论知识。我们了解了`HttpClientModule`，`HttpClient`，最重要的是，我们了解了我们可以在应用程序中使用的各种 HTTP 动词。我们还了解了 HTTP observables 和 promises。

现在，是时候动手写代码了。我们将学习如何创建我们需要使用 HTTP 调用集成的多个数据源。第一个将使用虚假的 JSON 服务器 API，而第二个将使用 Firestore 数据库。在下一节中，我们将学习并创建我们在开始端对端集成功能之前需要的服务。

# 集成后端服务

我们在这里取得了非常好的进展，所以让我们继续前进。软件开发中的最佳实践之一是创建可重用、通用和可维护的代码。在大多数动态应用程序中，我们需要进行大量的 HTTP 调用来根据应用程序的功能需求创建、保存、检索、编辑或删除数据。如果我们没有共享的 HTTP 调用，可能会导致有很多具有 HTTP 实现的方法，并且在长期内很难维护它们。我们如何解决这种情况？你已经知道答案了，我的朋友。没错——通过使用服务。在第十一章中，依赖注入和服务，我们学习了关于 Angular 服务和依赖注入的最佳实践。

Angular 指南明确规定所有 HTTP 调用和功能应该放在服务中，这样可以轻松地重用现有代码。Angular 服务是共享函数，允许我们访问其中定义的属性和方法。我们还将创建自定义服务，在其中实现我们的 HTTP 调用，并可以在各种组件中轻松重用。让我们创建两个服务——一个用于使用 JSON 服务器 API，另一个用于 Firestore 数据库操作。对于使用 JSON 服务器 API，我们将调用我们的`DbOperationsService`服务，对于使用 Firestore 数据库，我们将调用我们的`CRUDService`服务。这些服务中的每一个都将具有用于创建、读取、更新和删除数据的方法。现在，让我们运行以下`ng`命令，它将生成我们的服务：

```ts
ng generate service db-operations
```

在成功执行上述命令后，我们将执行以下命令来生成另一个服务。让我们称之为`crud`。我们将使用以下`ng`命令来生成该服务。

```ts
ng generate service crud
```

成功运行后，我们应该看到服务文件和它们各自的规范文件被生成。到目前为止，一切顺利。当我们开始端到端集成工作时，我们将需要这些服务。这可能看起来很复杂，但相信我，接下来的章节中所有这些都会有很多意义。

# 将 Angular HTTP 与后端 API 集成

这一部分非常重要，因为这是我们在整本书中学到的大部分主题的熔炉。我们将进行完整的端到端集成，从 UI 到服务，再到数据源。

我们需要生成我们将在应用程序中使用的组件。让我们运行以下`ng`命令来生成四个组件：

```ts
ng g component createListing
ng g component viewListing
ng g component deleteListing
ng g component updateListing
```

当这些命令成功运行时，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/944fdf72-407c-45c0-95cc-7b26877b9220.png)

现在我们已经生成了我们的组件，我们将利用在上一节中生成的`DbOperationsService`服务。我们还将使用我们使用 JSON 服务器创建的虚拟 API。我们将实现获取所有列表、查看特定列表、编辑现有列表以及最后删除列表的方法。为了实现这一点，我们需要将`HttpClientModule`导入到我们的`app.module.ts`文件中。我们还需要将`HttpClient`导入到我们的`db-operations.service.ts`服务文件中。我们还将导入`HttpHeaders`模块。这不是强制性的，但是出于良好的实践，我们将在进行 HTTP 调用时导入并使用它。我们将向`db-operations.service.ts`文件添加以下代码：

```ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';

@Injectable({
    providedIn: 'root'
})
export class DbOperationsService {

constructor(private http: HttpClient) { }

getListings(){
    return this.http.get('http://localhost:3000/listings');
}
viewListing(id){
    return this.http.get('http://localhost:3000/listings/'+id);
}
addListing(newList){
    let headers = new HttpHeaders({ 'Content-Type': 'application/json' });
    return this.http.post('http://localhost:3000/listings', newList);
}
editListing(id, newList){
    let headers = new HttpHeaders({ 'Content-Type': 'application/json' });
    return this.http.put('http://localhost:3000/listings/'+id, newList);
}
    deleteListing(id){
    return this.http.delete('http://localhost:3000/listings/'+id);
}

}
```

让我们详细分析前面的代码。首先，我们正在导入所需的模块：`Injectable`、`HttpClient`、`HttpHeaders`和`HttpParams`。然后我们将`HttpClient`注入到我们的构造函数中，并创建一个名为`http`的实例。然后，我们创建了四种方法，分别是`getListings`、`viewListing`、`editListing`和`deleteListing`。在`getListings`方法中，我们使用 HTTP GET 方法调用 API URL。这将从我们之前创建的`data.json`文件中返回所有列表。在`viewListing`中，我们传递 Listing 的 ID 以使用 HTTP GET 方法检索列表的数据。在`addListing`方法中，我们调用 API 并使用 HTTP POST 方法传递数据对象。这将在我们的 JSON 文件中创建一行新数据。接下来是`editListing`方法，它接受两个参数——列表的 ID 和我们需要保存的更新后的数据对象。最后一个方法是`deleteListing`，我们将传递要删除的列表的 ID。

在更实际的世界中，我们需要传递身份验证令牌、额外的安全性、清理数据等等。

我们现在已经制作了我们的自定义服务，其中包括将进行 HTTP 调用的方法。在我们开始处理组件之前，我们将创建一些路由，我们将在其中映射我们生成的组件。打开`app-routing.module.ts`文件，并在其中导入我们所有的组件。然后，我们需要将路由添加到其中，如下面的代码块所示：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import {UpdateListingComponent} from './update-listing/update-listing.component';
import {CreateListingComponent} from './create-listing/create-listing.component';
import {ViewListingComponent} from './view-listing/view-listing.component';
import {DeleteListingComponent} from './delete-listing/delete-listing.component';

const routes: Routes = [
  {path:'create-listing', component:CreateListingComponent   },
  { path:'view-listing', component:ViewListingComponent },
  { path:'delete-listing/:id', component:DeleteListingComponent},
  {path:'update-listing/:id', component:UpdateListingComponent}
];

@NgModule({
 imports: [RouterModule.forRoot(routes)],
 exports: [RouterModule]
})
export class AppRoutingModule { }
```

在前面的代码中，我们正在更新我们的`AppRoutingModule`并添加五个路由。我们创建了`create-listing`和`view-listing`路由，并将它们分别映射到`CreateListingComponent`和`ViewListingComponent`。这非常直接了当。对于`delete-listing`和`update-listing`路由，注意我们传递了一个名为 ID 的参数。我们将使用这些参数传递列表 ID 以便删除或更新列表的数据。

现在我们已经创建了我们的服务和路由，它们已经准备好在我们的组件中实现。让我们开始处理我们的组件。首先，我们将从`ViewListingComponent`开始。打开`view-listing.component.ts`文件，并添加检索所有列表的功能，如下面的代码块所示：

```ts
import { Component, OnInit } from '@angular/core';
import {DbOperationsService} from '../db-operations.service';
import { Listing} from '../models/listing';
import {Observable} from 'rxjs';

@Component({
 selector: 'app-view-listing',
 templateUrl: './view-listing.component.html',
 styleUrls: ['./view-listing.component.scss']
})

export class ViewListingComponent implements OnInit {

 listArr: Observable<any[]>;
 viewList:Observable<Listing>;
 isViewPage: boolean = false;

 constructor(private dbOps: DbOperationsService ) { }

 ngOnInit() {
 this.dbOps.getListings().subscribe((data) =>  {this.listArr = data});
 }

 showListing(listing){
 this.isViewPage = true;
 this.dbOps.viewListing(listing.id).subscribe((data) => {this.viewList = data});
 }
}
```

让我们详细分析上述代码。首先，我们需要导入所有必需的模块和类。我们导入了我们创建的`DbOperationsService`。我们还导入了之前创建的 listing 接口类。由于我们将使用`Listing`接口类，我们需要从`rxjs`中导入`Observable`。接下来，我们将声明我们的选择器为`app-view-listing`；我们将在模板`view-listing.component.html`文件中调用这个指令。我们现在将创建三个变量，名为`listArr`，`viewList`和`isViewPage`。请注意，`listArr`和`viewList`被声明为`Observable`。`listArr`和`viewList`变量之间的区别在于，`listArr`是 Listing 类型的 observable 并且是一个数组，而`viewList`是 Listing 类型的`Observable`并且将保存单个列表值。由于我们导入了一个服务，我们需要在构造方法中创建一个名为`dbOps`的实例。我们将在这里实现`ngOnInIt`方法；我们正在使用`dbOps`服务的实例调用`getListings`方法。我们正在订阅该方法，这意味着我们将把数据映射到`listArr`变量上。然后我们将使用`listArr`变量在模板文件中显示它。最后，我们正在创建一个`showListing`方法，我们正在将列表对象传递给它。使用服务的实例，我们正在调用`viewListing`方法并传递列表 ID。我们正在订阅数据并将其映射到`viewList`变量上。

现在，我们需要更新`view-listing.component.html`文件中的模板，并使用`listArr`和`viewList`变量在页面中显示数据，如下面的代码块所示：

```ts
<h4>Show All Listings</h4>

<table class="table table-bordered"> 
 <tbody>
 <tr>
 <th>Title</th>
 <th>Description</th>
 <th>Price</th>
 <th>Status</th>
 <th>Actions</th>
 </tr>
 <tr *ngFor="let listing of listArr;let i = index">
 <td>{{listing.title}}</td>
 <td>{{listing.description}}</td>
 <td>{{listing.price}}</td>
 <td>{{listing.status}}</td>
 <td><a [routerLink]="'/update-listing/'+listing.id">Edit</a> | 
    <a [routerLink]="'/delete-listing/'+listing.id">Delete</a></td>
 </tr>
 </tbody>
</table>
```

在上面的代码中，我们创建了一个表格。使用`ngFor`，我们正在循环从 API 获取的数据，并使用插值在表格行中显示数据。请注意，对于锚标签，我们使用`routerLink`指令动态创建链接，并传递编辑和删除链接的 ID。

我相信你对最终结果感到兴奋。让我们运行`ng serve`命令。您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/ea6ccfac-c281-415e-806d-ca198cb3ef63.png)

太棒了！现在事情真的开始变得有意思了！看到代码在运行中没有比这更好的鼓励了。我们已经添加了“添加新列表”菜单链接，现在是时候在我们的`createListing`组件中实现该功能了。

打开`createListingComponent`，并通过向其中添加以下代码来修改`create-listing.component.ts`文件：

```ts
import { Component, OnInit } from '@angular/core';
import {DbOperationsService} from '../db-operations.service';

@Component({
 selector: 'app-create-listing',
 templateUrl: './create-listing.component.html',
 styleUrls: ['./create-listing.component.scss']
})

export class CreateListingComponent implements OnInit { 
 userId = 1;
 newListing;
 successMsg;

 constructor(private dbOps: DbOperationsService) { }

 ngOnInit() {
 }
 addNewList(listForm)
 {
  this.newListing = {
 "userId":this.userId,
 "id": 152,
 "title":listForm.title,
 "price":listForm.price,
 "status":listForm.status,
 };

 this.dbOps.addListing(this.newListing).subscribe((data) => {
 this.successMsg = data;
 });
}
}
```

让我们详细分析上述代码。我们正在文件中导入所需的模块。我们还导入了我们之前创建的`DbOperationsService`。我们创建了一些变量，即`userId`、`newListing`和`successMsg`，并分配了一些初始值。我们创建了一个`addNewList`方法，并传递了`listForm`数据。我们还创建了一个类似于我们创建的列表模型的数据结构。接下来，使用服务的实例，我们调用`addListing`方法并传递我们需要保存的数据对象。这将在我们的`data.json`文件中创建一个新记录。最后，我们将结果映射到`successMsg`变量。我们将使用这个变量向用户显示成功消息。

由于我们使用的是虚拟 API，我们已经存根化了 ID 的值。在更实时的情况下，这个 ID 将在数据库端自动递增，并且始终是一个唯一的值。

现在，是时候更新我们的模板文件，以便我们可以使用表单从用户那里获取数据。打开`create-listing.component.html`文件，并将以下代码添加到其中：

```ts
<h4>Add New Listing</h4>
<p>
<div class="container">

<div *ngIf="successMsg">List Added Successful</div>

<form #listingForm="ngForm" (ngSubmit)="addNewList(listingForm)">
 <div class="form-group">
 <label for="title">Enter Listing Title</label>
 <input type="text" [ngModel]="title" name="title" class="form-control" 
    placeholder="Enter title">
 </div>
 <div class="form-group">
 <label for="price">Enter Description</label>
 <input type="text" [ngModel]="description" name="description" 
   class="form-control" placeholder="Enter Description">
 </div>
 <div class="form-group">
 <label for="price">Enter Price</label>
 <input type="number" [ngModel]="price" name="price" class="form-control" 
    placeholder="Enter price here">
 </div>
 <div class="form-group form-check">
 <input type="checkbox" [ngModel]="status" name="status" 
    class="form-check-input">
 <label class="form-check-label" for="status">Active?</label>
 </div>
 <button type="submit" class="btn btn-primary">Add New Listing</button>
</form>
</div>
```

在上述代码中，我们正在使用基于模板的表单创建表单。我们创建了一些表单字段来捕获数据，例如标题、描述、价格和活动状态。我们正在使用模板变量来引用表单和字段。我们还在`ngSubmit`事件上调用`addNewList`方法并提交整个表单。通过运行`ng serve`命令，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/25cfa752-5dbf-406c-9cb5-c36306ff7bf5.png)

现在，继续向表单字段添加一些数据，然后单击“提交”按钮。如果记录已成功创建，您应该会看到成功消息：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/45a7f6dd-fc19-4f86-b688-57a958605088.png)

现在，点击菜单中的“获取所有列表”链接。您应该在表中看到新创建的记录显示在列表中。您还记得我们为列表添加了编辑和删除链接吗？现在是时候实现它们了。我们将首先实现编辑功能，然后再实现删除功能。

打开我们的更新列表组件，编辑`update-listing.component.ts`文件，然后将以下代码添加到其中：

```ts
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from "@angular/router";
import {DbOperationsService} from '../db-operations.service';
import { Listing} from '../models/listing';
import {Observable} from 'rxjs';

@Component({
    selector: 'app-update-listing',
    templateUrl: './update-listing.component.html',
    styleUrls: ['./update-listing.component.scss']
})
export class UpdateListingComponent implements OnInit {

 listId;
 successMsg = false;
 viewList: Observable<Listing>;

 constructor(private route:ActivatedRoute, private 
   dbOps:DbOperationsService) { }

ngOnInit() {
    this.listId = this.route.snapshot.paramMap.get("id");
    this.dbOps.viewListing(this.listId).subscribe((data) 
     => {this.viewList = data});
 }
editListing(updatedList){
    this.dbOps.editListing(updatedList.id, updatedList).subscribe((data) => {
        this.successMsg = data;
    });
  }
}
```

让我们详细分析前面的代码。我们正在将所需的模块导入到我们的组件文件中。我们正在导入`ActivatedRoute`，我们的服务，列表接口类和可观察对象到组件文件中。为了实现更新功能，我们需要做两件事。首先，我们需要检索传递了 ID 的列表的数据。一旦用户更新了数据并单击“提交”按钮，我们将持久化该列表的数据。我们还需要将路由器和服务注入到我们的构造函数中。在`ngOnInit`方法中，使用路由器快照，我们正在从 URL 中捕获列表的 ID。然后，使用服务的实例，我们正在调用`viewListing`方法来获取基于传递的 ID 的列表的详细信息。最后，我们创建了一个`editListing`方法。使用服务的实例，我们正在调用`editListing`方法，因此我们需要传递两个参数，一个用于传递列表的 ID，另一个用于传递列表的更新数据。

现在，让我们更新我们的模板文件。打开`update-listing.component.html`文件并添加以下代码：

```ts
<div class="container">
<div *ngIf="successMsg">List Updated Successful</div>
<form #editlistingForm="ngForm" (ngSubmit)="editListing(editlistingForm)">
 <div class="form-group">
 <input type="hidden" class="form-control" name="id" 
    [(ngModel)]="viewList.id" ngModel #id>
 </div>
 <div class="form-group">
 <input type="hidden" class="form-control" name="userId" 
    [(ngModel)]="viewList.userId" ngModel #userId>
 </div>
 <div class="form-group">
 <label for="title">Enter Listing Title</label>
 <input type="text" class="form-control" name="title" 
    [(ngModel)]="viewList.title" ngModel #title required>
 </div>
 <div class="form-group">
 <label for="price">Enter Description</label>
 <input type="text" name="description" [(ngModel)]="viewList.description" 
    ngModel #description class="form-control" required>
 </div>
 <div class="form-group">
 <label for="price">Enter Price</label>
 <input type="number" [(ngModel)]="viewList.price" name="price" 
    class="form-control" ngModel #price required>
 </div>
 <div class="form-group form-check">
 <input type="checkbox" [(ngModel)]="viewList.status" 
   checked="{{viewList.status}}" name="status" ngModel 
   #status class="form-check-input" required>
 <label class="form-check-label" for="status">Active?</label>
 </div>
 <button type="submit" [disabled]="!editListingForm.valid" 
   class="btn btn-primary">Update Listing</button>
</form>
</div>
```

在上述代码中，我们再次基于模板驱动的表单方法创建了一个表单。您会注意到编辑表单与创建列表表单非常相似。你几乎是正确的，但有一些重要的区别。请注意，我们现在正在使用`ngModel`进行双向数据绑定，并将值绑定到表单字段。有了这个，当我们获取初始数据时，它会显示在表单字段中。现在，用户可以编辑数据，当单击“更新列表”按钮时，数据将被发送到`addListing`方法并持久化在后端 API 中。现在，让我们看看它的运行情况。通过运行`ng serve`命令，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/a1dd547e-7a4d-4337-9167-8ff0b66d54ad.png)

请注意，URL 中包含作为参数传递的列表的 ID。数据已被检索并显示在页面加载上。现在，当用户更新表单中的详细信息并单击“提交”按钮时，这将更新列表的数据。这是你的作业。

好了，我们已经实现了创建、编辑和查看功能。接下来，我们将实现列表的删除功能。请记住，对于删除和编辑功能，用户将始终通过单击锚标签导航到页面。打开`DeleteListingComponent`并更新`delete-listing.component.ts`文件，如下面的代码块所示：

```ts
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from "@angular/router";
import {DbOperationsService} from '../db-operations.service';
import { Listing} from '../models/listing';
import {Observable} from 'rxjs';

@Component({
 selector: 'app-delete-listing',
 templateUrl: './delete-listing.component.html',
 styleUrls: ['./delete-listing.component.scss']
})
export class DeleteListingComponent implements OnInit {
viewList:Observable<Listing>;
listId;
successMsg:Observable<Listing>;

constructor(private route:ActivatedRoute, private dbOps:DbOperationsService) { }

ngOnInit() {
 this.listId = this.route.snapshot.paramMap.get("id");
 this.dbOps.deleteListing(this.listId).subscribe((data) => {
 this.successMsg = data;
 });
 }

}
```

让我们详细分析上述代码。我们在组件文件中导入所需的模块；即`ActivatedRoute`、`DbOperationsService`、`Listing`和`Observable`。我们还创建了一些变量——`viewList`、`ListId`和`successMsg`。然后，我们将路由和服务注入到构造方法中。最后，使用`ngOnInIt`方法，我们传递需要删除的列表的 ID。我们订阅数据并将其映射到`successMsg`。

在本节中，我们学习了如何为我们的`ListingApp`实现基本的 CRUD 操作。然后，我们学习了如何对 GET、POST、PUT 和 DELETE 方法进行 HTTP 调用。最后，我们学习了如何使用 JSON Server 创建虚拟 API。在下一节中，我们将学习如何使用云 NoSQL Firestore 数据库实现 CRUD 操作。

# 将 Angular HTTP 与 Google Firebase 集成

在本节中，我们将学习如何为 NoSQL Firestore 数据库实现 HTTP 功能。我们在之前的部分中创建了我们的 Firestore 数据库。现在是集成 Angular HTTP 调用的合适时机，它将调用并与 Firestore 数据库一起工作。

我们将实现哪些用例？对于我们的`ListingApp`，我们将需要一个评论系统。作为用户，我们应该能够添加、编辑、删除和查看评论。所有这些用例都将需要我们调用 API 来保存、检索和删除评论。

Angular Fire 是 Firebase 的官方库。该库提供了许多内置模块，支持诸如身份验证、与 Firestore 数据库的交互、基于 observable 的推送通知等活动。

我们需要在`@angular/fire`下安装此模块。在命令行界面中运行以下命令以安装库：

```ts
npm i @angular/fire 
```

当我们成功运行上述命令时，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/30d643f3-d22c-424b-8b87-083dfdafaa46.png)

安装完库后，我们将继续创建一个新的自定义服务，用于与 Firestore 数据库集成。

运行以下命令生成一个新的服务：

```ts
ng generate service crudService
```

当我们成功运行上述命令时，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/64a22473-60eb-46b9-8af7-75c4fac4adbe.png)

您会注意到生成了两个文件。我们将在服务内实现所有我们的 HTTP 调用。正如我们之前提到的，我们需要创建一些组件，这些组件将映射到每个功能，并在内部调用具有 HTTP 实现的服务。

运行以下`ng generate`命令为评论功能生成组件：

```ts
ng generate component addComments

ng generate component viewComments ng generate component editComments ng generate component deleteComments
```

当我们成功运行上述命令时，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/07b0c36b-c14c-493d-b2ae-a4fc5e72edac.png)

您会注意到组件已经生成并添加到我们的项目目录中。您还会注意到`app.module.ts`文件已经更新，其中包含了组件的条目。

我们已经生成了我们的组件和所需的服务，还安装了 Angular Fire 库。为了在我们的应用程序中使用 Angular Fire 库，我们需要将该库导入到我们的`app.module.ts`文件中。将所需的模块导入到应用程序模块文件中，并在应用程序的导入列表中列出这些模块，如下所示：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpClientModule} from '@angular/common/http';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { CreateListingComponent } from './create-listing/create-listing.component';
import { ViewListingComponent } from './view-listing/view-listing.component';
import { DeleteListingComponent } from './delete-listing/delete-listing.component';
import { UpdateListingComponent } from './update-listing/update-listing.component';

import {FormsModule} from '@angular/forms';

import { AngularFireModule} from 'angularfire2';
import {AngularFireDatabaseModule} from 'angularfire2/database';
import { AngularFireAuth } from '@angular/fire/auth';
import { environment } from './firebase-config';
import { AngularFirestore } from '@angular/fire/firestore';
import { AddCommentsComponent } from './add-comments/add-comments.component';
import { EditCommentsComponent } from './edit-comments/edit-comments.component';
import { ViewCommentsComponent } from './view-comments/view-comments.component';
import { DeleteCommentsComponent } from './delete-comments/delete-comments.component';

@NgModule({
  declarations: [
    AppComponent,
    CreateListingComponent,
    ViewListingComponent,
    DeleteListingComponent,
    UpdateListingComponent,
    AddCommentsComponent,
    EditCommentsComponent,
    ViewCommentsComponent,
    DeleteCommentsComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    AppRoutingModule,
    AngularFireModule.initializeApp(environment.firebaseConfig),
    AngularFireDatabaseModule,
    FormsModule
  ],
  providers: [AngularFirestore],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

在上述代码中需要注意的一点是，我们正在从 Angular Fire 导入所需的模块，并在导入模块列表下列出它们。请注意，我们导入了一个名为`firebase-config`的文件。这些是环境变量，将保存用于与 Firebase 进行身份验证的 API 密钥。我们可以在 Firebase 帐户下找到列出的 API 密钥，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/8fe5f267-e6da-4265-8b00-f27ae9974cd0.png)

我们需要将详细信息复制到`firebase-config.ts`文件中。以下屏幕截图显示了我们的`ListingApp`中指定的设置：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/56f1af0c-5dc6-47e0-b652-87daf31e2832.png)

到目前为止，一切顺利。现在我们已经安装了所需的库，导入了模块，并完成了配置设置，现在是时候开始处理我们的应用程序组件了。我们在这里取得了很大的进展。让我们保持这种势头。

现在我们已经创建了我们的组件，我们将快速修改我们的`app-routing.module.ts`文件，并为每个组件创建一个新的路由。

我们已经掌握了 Angular 路由，在第四章 *路由*。如果需要快速复习，请重新阅读该章节。

在以下代码中，我们已经将所有所需的组件类导入到`app-routing.module.ts`文件中，并在路由文件中添加了相应的路由：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import {UpdateListingComponent} from './update-listing/update-listing.component';
import {CreateListingComponent} from './create-listing/create-listing.component';
import {ViewListingComponent} from './view-listing/view-listing.component';
import {DeleteListingComponent} from './delete-listing/delete-listing.component';

import { AddCommentsComponent } from './add-comments/add-comments.component';
import { EditCommentsComponent } from './edit-comments/edit-comments.component';
import { ViewCommentsComponent } from './view-comments/view-comments.component';
import { DeleteCommentsComponent } from './delete-comments/delete-comments.component';

const routes: Routes = [
  { path:'create-listing', component:CreateListingComponent },
  { path:'view-listing', component:ViewListingComponent },
  { path:'delete-listing/:id', component:DeleteListingComponent},
  { path:'update-listing/:id', component:UpdateListingComponent},
  { path:'add-comment', component:AddCommentsComponent },
  { path:'view-comment', component:ViewCommentsComponent },
  { path:'delete-comment/:id', component:DeleteCommentsComponent},
  { path:'update-comment/:id', component:EditCommentsComponent}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

我们将使用四个新创建的路由来在`ListingApp`中实现评论功能。我们将使用 Firestore 数据库添加 CRUD 操作。我们需要将`AngularFirestore`模块导入到我们的服务中，如下所示：

```ts
import { AngularFirestore } from '@angular/fire/firestore';
```

在我们将模块导入到我们的文件后，我们需要在`constructor`方法中注入它，如下所示：

```ts
constructor(private afStore : AngularFirestore, private route: Router ) { }
```

现在我们可以利用`AngularFirestore`模块并使用 Firestore 实现 CRUD 操作。查看`crud-service.service.ts`文件中的完整更新代码。

```ts
import { Injectable } from '@angular/core';
import { AngularFireAuth } from '@angular/fire/auth';
import { environment } from './firebase-config';
import { AngularFirestore } from '@angular/fire/firestore';

@Injectable({
  providedIn: 'root'
})
export class CrudServiceService {

  constructor(private afStore : AngularFirestore) { }

  getComments() {
    return this.afStore.collection('comments');
  }

  deleteComment(id) {
    this.afStore.collection('comments').doc(id).delete();
  }

  addComment(newComment) {
    this.afStore.collection('comments').add(newComment);
  }

  updateComment(id, editedComment) {    
    this.afStore.collection('comments').doc(id).set(editedComment);
  }
}
```

让我们详细分析前面的代码。我们已经导入了所有必需的模块，包括我们的 Angular Fire 模块和我们的`firebase-config`文件。由于我们已经导入了`AngularFireStore`模块，我们需要将其注入到我们的`constructor`方法中并创建一个实例。我们为评论功能的每个操作创建了方法。在`getComments`方法中，我们正在从*comments*集合中检索所有数据。在`deleteComment`方法中，我们正在传递需要删除的评论的 ID。在`addComment`方法中，我们正在传递我们想要存储在我们的集合中的数据。在`updateComment`方法中，我们传递了两个参数；第一个是我们想要更新的评论的 ID，第二个是我们需要在数据库中持久保存的更新数据。

你可能会想为什么我们在这些方法中没有进行任何 HTTP 调用？`AngularFireStore`模块在内部对服务进行 HTTP 调用，并将从 firebase 配置文件中进行身份验证并获取特定于帐户的信息。

在早期的章节中，我们学习了如何从组件发送数据到服务，对吧？沿着同样的思路，继续尝试评论功能。这是你的家庭作业。

# 总结

你感觉如何？你应该感到很棒，应该为自己感到骄傲！这一章节是很多工作，但我们做完了会变得更好。它汇集了我们迄今为止学到的所有方面，如表单、组件、路由、服务等。

对于前端开发人员来说，在本地开发环境中设置一个虚拟 API 总是有助于我们独立工作，而不依赖后端开发人员或 API。我们学习了如何使用 JSON 服务器构建虚拟 API。我们学习了 NoSQL 文档数据库，特别是由谷歌云提供的 Firestore 数据库。我们深入研究了 Angular HTTP 的概念和功能。我们学会了如何进行 HTTP POST、GET、PUT 和 DELETE 调用。我们还使用 JSON 服务器和 Firestore 数据库实现了整个应用程序的功能用例。

到目前为止，我们取得了巨大的进步。我们现在能够端到端地开发 Angular 应用程序，利用 Angular 提供的所有超能力，包括表单、组件、服务、路由等等。在本章结束时，我相信我们能够将 Angular 框架的所有部分整合到一个正常运行的应用程序中。

拥有一个正常运行的应用程序是进步的一个好迹象。但在评估应用程序时的重要因素是查看质量检查或单元测试。

在下一章中，我们将学习如何编写单元测试，以确保在产品开发生命周期的早期发现任何缺陷。编写测试脚本可以确保质量，并且是处理应用程序的所有用例的一个很好的标志，包括应用程序的正常和负面路径。


# 第十三章：单元测试

您可能已经为传统的服务器端代码编写了单元测试，比如 Java、Python 或 C#。当然，在客户端，单元测试同样重要，在本章中，您将了解 Angular 测试，包括 Jasmine 和 Karma 框架，这两个优秀的工具用于对客户端代码进行单元测试。

我们将一起探讨如何对 Angular 应用的各个部分进行单元测试，例如组件、路由和依赖注入（DI）。

本章将涵盖以下主题：

+   Jasmine 和 Karma 简介

+   测试指令

+   测试组件

+   测试路由

+   测试依赖注入

+   测试 HTTP

# 测试框架简介

在本节中，我们将学习两个重要的测试框架，即 Jasmine 和 Karma。

测试和开发本身一样重要。这是一个备受争议的话题，一些专家认为**测试驱动开发**（TDD）非常重要，这意味着在编写开发代码之前编写测试脚本非常重要。

Angular 框架的美妙之处在于它原生支持测试框架，并提供了许多测试工具，使开发人员的工作变得轻松愉快。我们一点也不抱怨。

Angular 为我们提供了一个核心测试模块，其中有很多我们可以利用的优秀类，并且原生支持两个重要的测试框架，即 Jasmine 和 Karma：

+   我们使用 Jasmine 框架编写我们的测试脚本。

+   我们使用 Karma 框架来执行测试脚本。

# 关于 Jasmine 框架

Jasmine 是一个领先的开源测试框架，用于编写和测试现代 Web 框架的自动化测试脚本。

当然，对于 Angular 来说，Jasmine 已经成为事实上的首选框架。以下摘自官方网站：

"Jasmine 是一个用于测试 JavaScript 代码的行为驱动开发框架。它不依赖于任何其他 JavaScript 框架。它不需要 DOM。它有一个清晰明了的语法，让您可以轻松编写测试。"

编写 Jasmine 测试脚本的理念是基于行为和功能驱动的。测试脚本有两个重要的元素——`describe`和规范（`it`）：

+   `describe`函数用于将相关的规范分组在一起。

+   规范是通过调用`it`函数来定义的。

以下是一个用 Jasmine 编写的示例测试脚本：

```ts
describe("Test suite", function() {
  it("contains spec with an expectation", function() {
    expect(true).toBe(true);
  });
});
```

在编写测试规范的过程中，我们必须使用大量的条件检查来匹配数据、元素、结果、断言条件等等。Jasmine 框架提供了许多匹配器，我们可以在编写测试规范时方便地使用。在前面的示例代码中，toBe 就是一个匹配器的例子。

以下是 Jasmine 中最常用的匹配器列表：

+   等于

+   为真

+   为假

+   大于或等于

+   小于或等于

+   已调用

+   具有类

+   匹配

我们将在接下来的几节中学习如何使用这些匹配器。好的，我们已经编写了我们的测试规范，那么现在怎么办？我们如何运行它们？谁会为我们运行它们？答案可以在下一节找到。

# 关于 Karma 框架

Karma 是一个测试运行器框架，用于在服务器上执行测试脚本并生成报告。

以下内容来自官方网站：

“Karma 本质上是一个工具，它生成一个 Web 服务器，针对每个连接的浏览器执行源代码与测试代码。针对每个浏览器的每个测试的结果都会被检查，并通过命令行显示给开发人员，以便他们可以看到哪些浏览器和测试通过或失败。”

Karma 框架被添加到我们的依赖列表中，因为它包含在 Angular CLI 安装中。在我们继续编写和执行测试脚本之前，验证我们是否已在`package.json`文件中正确安装了 Jasmine 和 Karma 是一个良好的实践。我们还可以验证正在使用的库的版本号。

我敢打赌你已经猜到这也是指定要使用的 Jasmine 和 Karma 的特定版本的地方。

在下面的截图中，我们可以验证我们已将 Jasmine 和 Karma 添加到`package.json`文件中的`devDependencies`列表中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/2e79829a-5f66-40fa-8453-e8ff426ea822.png)

太好了。现在，是时候深入了解 Angular 测试概念并编写一些测试脚本了。

# Angular 测试自动化

我相信你会同意测试自动化是产品开发中最重要的方面之一。在前面的部分中，我们探讨了 Jasmine 和 Karma 框架。在接下来的部分中，我们将通过一些实际示例来学习如何自动化各种 Angular 框架构建模块。我们将学习如何测试 Angular 组件、指令、路由等等。让我们开始吧。

# 测试 Angular 组件

在使用 Angular CLI 的过程中，我们已经生成了多个组件和服务。暂停一下，查看文件和文件夹结构。您会注意到，对于每个组件和服务，都生成了一个`.spec.ts`文件。

恍然大悟！Angular CLI 一直在为相应的组件和服务生成所需的外壳测试脚本。让我们在这里进行一个快速的实践练习。让我们生成一个名为`auto-list`的组件：

```ts
ng g component auto-list
```

Angular CLI 会自动生成所需的文件，并在所需的文件（`AppModule`，`Angular.json`等）中进行条目。

以下截图描述了 CLI 生成的测试规格：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/b5672937-3116-499f-8c6b-0fc1a37a54f7.png)

仔细看一下生成的文件。您会看到为组件生成了以下文件：

+   `auto-list.component.html`

+   `auto-list.component.spec.ts`

+   `auto-list.component.ts`

+   `auto-list.component.scss`

我们对 Angular CLI 生成的 spec 文件感兴趣。spec 文件是为相应组件生成的测试脚本。spec 文件将导入基本所需的模块，以及`Component`类。spec 文件还将包含一些基本的测试规格，可以用作起点，或者作为我们的动力。

让我们更仔细地看一下在 spec 文件中生成的代码：

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { AutoListComponent } from './auto-list.component';
```

在上面的代码中，您会注意到所需的模块是从 Angular 测试核心导入的。这当然不是我们将使用的模块的最终列表，而只是基本的起始模块。您还会注意到新创建的组件`AutoListComponent`也被导入到我们的 spec 文件中，这意味着我们可以在 spec 文件中创建我们类的一个实例，并开始模拟测试目的的对象。很酷，对吧？继续看代码行，我们可以看到以下内容：

```ts
describe('AutoListComponent', () => {
    let component: AutoListComponent;
    let fixture: ComponentFixture<AutoListComponent>;
beforeEach(async(() => {
    TestBed.configureTestingModule({
    declarations: [ AutoListComponent]
 })
 .compileComponents();
 }));

beforeEach(() => {
    fixture = TestBed.createComponent(AutoListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
});
```

在上面的代码中，您会注意到一些关键点。有一个`describe`语句，用于将相关的测试规格分组在一起。我们将在`describe`函数内创建测试规格。在 spec 文件中定义了两个`beforeEach`方法。

第一个`beforeEach`方法是一个异步 promise，它将设置我们的`TestBed`，这意味着在继续之前必须解决其中声明的所有内容；否则，我们的测试将无法工作。第二个`beforeEach`方法将为测试创建一个`AutoList`组件的实例。您会注意到调用`fixture.detectChanges()`，这会强制 Angular 的变更检测运行并影响测试中的元素。

现在，是时候了解实际的测试规范了，这是在规范文件中生成的：

```ts
it('should create', () => {
 expect(component).toBeTruthy();
 });
```

正如我们之前提到的，Jasmine 测试规范是写在`it`语句内的，这种情况下，只是一个简单的断言，用于检查组件是否存在并且为真，使用`toBeTruthy`匹配器。

这就是我们的规范文件。乐趣在于看到它的工作。让我们运行 Angular 为我们生成的默认测试。要运行 Angular 应用程序中编写的测试，我们在命令行界面上使用`ng test`命令：

```ts
ng test
```

如果你看到一个新窗口被打开，不要惊慌。您会注意到 Karma 运行器打开了一个新的浏览器窗口来执行测试，并生成了测试执行报告。以下截图显示了为我们的组件生成的测试规范的报告：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/571e4b63-7965-449c-b422-0f6984cca8d2.png)

测试通过了。现在，让我们稍微修改一下脚本。我们将在组件中创建一个名为`title`的变量并赋值。在我们的测试规范中，我们将验证该值是否匹配。这是一个直接的用例，相信我，这也是您在应用程序中实现的最常见的用例。让我们打开`app.component.spec.ts`文件并在测试脚本中进行更改：

```ts
it(`should have as title 'testing-app'`, () => {
 const fixture = TestBed.createComponent(AppComponent);
 const app = fixture.debugElement.componentInstance;
 expect(app.title).toEqual('AutoStop');
});
```

在上面的代码中，我们正在编写一个测试规范，并使用`TestBed`创建了`AppComponent`的 fixture 元素。使用 fixture 元素的`debugElement`接口，我们获取了`componentInstance`属性。接下来，我们编写了一个`expect`语句来断言`title`变量的值是否等于`AutoStop`。很整洁。让我们尝试再写一个测试规范。我们要解决的用例是：我们有一个`H1`元素，并且我们想要断言它，如果`H1`标签内的值等于`Welcome to Autostop`。以下是相关的示例代码：

```ts
it('should render title in a h1 tag', () => {
 const fixture = TestBed.createComponent(AppComponent);
 fixture.detectChanges();
 const compiled = fixture.debugElement.nativeElement;
 expect(compiled.querySelector('h1').textContent).toContain('Welcome to 
  AutoStop');
});
```

在上述代码中，我们断言`h1`元素的`textContent`是否包含文本`Welcome to AutoStop`。请注意，在以前的测试规范中，我们使用了`componentInstance`接口，在这个测试规范中，我们使用了`nativeElement`属性。再次使用`ng test`命令运行测试。以下屏幕截图显示了生成的测试报告：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/3f162038-f763-42e7-956c-60b616869076.png)

到目前为止，我们已经概述了 Jasmine 和 Karma 框架，还学习了如何运行我们的测试脚本。我们还了解了 Angular 为我们生成的默认 spec 文件，并学习了如何修改测试规范。

在接下来的章节中，我们将学习如何编写测试规范和脚本，以测试 Angular 内置指令、服务、路由等等。

# 测试指令

Angular 提供了许多内置的强大指令，如`ngFor`、`ngIf`等，可以用于扩展原生 HTML 元素的行为和功能。我们在第七章中学习了关于 Angular 模板和指令的知识，快速回顾从未有过害处。Angular 为我们提供了两种类型的指令，我们可以用来开发和扩展元素的行为：

+   内置指令

+   自定义指令

本节的重点是学习如何编写用于内置 Angular 指令（如`ngIf`、`ngFor`、`ngSwitch`和`ngModel`）的测试脚本。在开始编写测试用例之前，我们需要做一些准备工作，以更新我们的组件，以便我们可以开始编写测试用例。我们将编写一些变量，用于保存各种类型的数据。我们将使用`ngFor`在模板中显示数据，并使用`ngIf`编写一些条件检查。

如果您想快速复习 Angular 模板和指令，请参阅第七章 *Templates, Directives, and Pipes*。

我们将继续使用在上一节中创建的相同组件`AutoListComponent`。让我们开始吧。我们的起点将是`AutoListComponent`类，所以让我们修改`auto-list.component.ts`文件：

```ts
import { Component, OnInit } from '@angular/core';

@Component({
 selector: 'app-auto-list',
 templateUrl: './auto-list.component.html',
 styleUrls: ['./auto-list.component.scss']
})
export class AutoListComponent implements OnInit {

cars = [
 { 'id': '1', 'name': 'BMW' },
 { 'id': '2', 'name': 'Force Motors' },
 { 'id': '3', 'name': 'Audi' }
 ];

 tab = "1";

 constructor() { }

 ngOnInit() {
 }

 findAuto() {
     console.log("Method findAuto has been called");
  }

}
```

在上面的代码中，我们添加了一个名为`cars`的 JSON 对象类型的变量，并为其分配了数据。我们将通过在模板中显示数据来使用这些数据。我们还声明了一个名为`tab`的变量，并分配了一个值`1`。我们将在模板中使用`tab`变量进行条件检查。最后，我们添加了一个名为`findAuto`的方法，并在控制台中显示输出。

我们已经修改了我们的组件类。我们还需要更新我们的模板文件，以便在组件内部处理数据。以下是我们将在模板文件`auto-list.component.html`中添加的示例代码：

```ts
<h4 class="c2">ngFor directive</h4>
<ul class="cars-list">
 <li *ngFor="let car of cars">
 <a [routerLink]="[car.id]">{{ car.name }}</a>
 </li>
</ul>

<h4 class="c1">ngIf directive</h4>
<div *ngIf="cars.length" id="carLength">
 <p>You have {{cars.length}} vehicles</p>
</div>

<h4 class="c3">ngSwitch directive</h4>
<div [ngSwitch]="tab" class="data-tab">
 <p>This is ngSwitch example</p>
 <div *ngSwitchCase="1">ngSwitch Case 1</div>
 <div *ngSwitchCase="2">ngSwitch Case 2</div>
</div>
<hr>

<button (click)="findAuto()" id="btn">Click to findAutoDealers</button>
```

在上面的代码中，我们正在对模板文件进行更改。首先，我们使用`ngFor`指令循环行并显示汽车。接下来，我们添加了一个`ngIf`条件来检查汽车的长度是否大于 0，然后我们将显示`carLength`元素的计数。我们已经添加了一个`ngSwitch`指令来检查`tab`变量的值是否设置，并根据选项卡的值来相应地显示相应的选项卡。在我们的情况下，由于选项卡分配的值为`1`，我们将显示第一个选项卡。最后，我们添加了一个按钮，并将`findAuto`方法与单击事件相关联。

很好。我们的组件和模板已经准备好了，现在是时候编写一些良好的测试脚本来测试前面的逻辑，特别是 Angular 内置指令。我们将测试的一些用例包括测试 UI 中显示的汽车数量，测试哪个选项卡是活动的，验证元素内的内容等等。以下是一些用例，并且我们将学习如何为这些用例编写测试脚本：

**用例＃1**：我们有一列汽车，我们想要验证总数为`3`：

```ts
// ngFor test case to test the count is 4
 it('Should have 3 Brands coming from ngFor directive', async(() => {
 const fixture = TestBed.createComponent(AutoListComponent);
 fixture.detectChanges();
 const el = fixture.debugElement.queryAll(By.css('.cars-list > li'));
 expect(el.length).toBe(3);
 }));
```

在上面的代码中，我们正在创建`AutoListComponent`组件的 fixture。我们已经学会了如何使用`debugElement`来定位元素，并且在这个测试规范中，我们使用`queryAll`方法来获取具有`className` `.cars-list > li`的元素列表。最后，我们编写了一个`expect`语句来断言总数是否等于`3`。

使用`ng test`命令运行测试。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/aabd75b5-5309-43a1-b46e-55a970e65321.png)

**用例＃2**：我们要验证 HTML 元素内的文本是否包含`vehicles`键盘：

```ts
// ngIf test script
 it('Test ngIf directive in component', async(() => {
 const fixture = TestBed.createComponent(AutoListComponent);
 fixture.detectChanges();
 const compiled = fixture.debugElement.nativeElement;
 const el = compiled.querySelector('#carLength');
 fixture.detectChanges();
 const content = el.textContent;
 expect(content).toContain('vehicles', 'vehicles');
 }));
```

在上述代码中有一些重要的事情需要注意。我们继续使用组件`AutoListComponent`的相同装置元素。这一次，我们使用`debugElement`接口，使用`querySelector`方法来查找具有标识符`carLength`的元素。最后，我们编写一个`expect`语句来断言文本内容是否包含`vehicles`关键字。

让我们再次使用`ng test`命令运行测试。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/8800f60e-eb85-4fa2-b621-5c1908861a28.png)

**用例＃3：**我们想使用`ngSwitch`来验证是否选择了`tab1`，如果是，则显示相应的 div：

```ts
// ngSwitch test script
 it('Test ngSwitch directive in component', async(() => {
 const fixture = TestBed.createComponent(AutoListComponent);
 fixture.detectChanges();
 const compiled = fixture.debugElement.nativeElement;
 const el = compiled.querySelector('.data-tab > div');
 const content = el.textContent;
 expect(content).toContain('ngSwitch Case 1');
 }));
```

在上述代码中，我们继续使用`AutoListComponent`组件的 fixture 元素。使用`debugElement`和`querySelector`方法，我们正在使用`className '.data-tab > div'`来定位元素。我们断言`ngSwitch`条件是否为`true`，并显示相应的`div`。由于我们在组件中将选项卡的值设置为`1`，因此选项卡 1 显示在屏幕上，并且测试规范通过：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/752b84ac-61f6-4d59-bba5-64d062a30440.png)

**用例＃4：**测试`AutoListComponent`中定义的方法，并断言该方法是否已被调用：

```ts
// Test button is clicked
 it('should test the custom directive', async(() => {
 const fixture = TestBed.createComponent(AutoListComponent);
 component = fixture.componentInstance;
 fixture.detectChanges();
 spyOn(component, 'findAuto');
 component.findAuto();
 expect(component.findAuto).toHaveBeenCalled();

}));
```

在上述代码中，我们正在创建`AutoListComponent`组件的 fixture。我们使用`spyOn`方法来监听组件实例。我们正在调用`findAuto()`方法。最后，我们编写一个`expect`语句来断言`findAuto`方法是否已被调用，使用`toHaveBeenCalled`。 

使用`ng test`命令运行测试。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/b594dedb-f283-4c25-9cd3-5df794e0ac52.png)

在本节中，我们学习了如何编写单元测试脚本来测试 Angular 内置指令，例如`ngFor`，`ngIf`，`ngSwitch`，最后，断言方法是否被点击和调用。

在下一节中，我们将学习有关测试 Angular 路由的知识。

# 测试 Angular 路由

很可能，您的应用程序中会有多个链接，以导航菜单或深链接的形式存在。这些链接在 Angular 中被视为路由，并且通常在您的`app-routing.module.ts`文件中定义。

我们在第四章中学习并掌握了如何使用 Angular 路由。在本节中，我们将学习如何编写用于测试 Angular 路由和测试应用程序中的链接和导航的测试脚本。

我们的应用程序需要一个漂亮的`menu`组件。使用`ng generate component menu`命令，我们将生成`menu`组件。现在，让我们转到`menu.component.html`并创建一个名为`navbar`的菜单，其中包含两个链接：

```ts
<nav class="navbar navbar-expand-lg navbar-light bg-light">
 <a class="navbar-brand" href="#">AutoStop </a>
 <button class="navbar-toggler" type="button" data-toggle="collapse" 
    data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" 
    aria-expanded="false" aria-label="Toggle navigation">
 <span class="navbar-toggler-icon"></span>
 </button>

<div class="collapse navbar-collapse" id="navbarSupportedContent">
 <ul class="navbar-nav mr-auto">
 <li class="nav-item active">
 <a class="nav-link" routerLink="/list-cars">Cars <span class="sr-only">
   (current)</span></a>
 </li>
 <li class="nav-item">
 <a class="nav-link" routerLink="/list-trucks">Trucks</a>
 </li>
 </ul>
 </div>
</nav>
```

前面的代码并不花哨，至少目前还不是。这是使用 Bootstrap 生成`navbar`组件的标准代码。仔细看，你会发现我们在菜单栏中定义了两个链接，`list-cars`和`list-trucks`，它们的类是`nav-link`。

现在我们可以围绕菜单功能编写一些测试规范，以测试`navbar`组件，其中将涵盖导航、链接计数等。

**用例＃1**：我们需要测试`navbar`菜单是否恰好有两个链接。

以下是检查是否有确切两个链接的代码：

```ts
// Check the app has 2 links
 it('should check routerlink', () => {
 const fixture = TestBed.createComponent(MenuComponent);
 fixture.detectChanges();
 const compiled = fixture.debugElement.nativeElement;

let linkDes = fixture.debugElement.queryAll(By.css('.nav-link'));
 expect(linkDes.length).toBe(2);

});
```

在前面的代码中，我们正在为我们的`MenuComponent`组件创建一个固定装置。由于我们分配了`nav-link`类，因此很容易定位组件中对应的链接。使用`debugElement`和`queryAll`方法，我们正在查找所有类名为`nav-link`的链接。最后，我们正在编写一个`expect`语句来断言返回的链接数组的长度是否等于`2`。

使用`ng test`命令运行测试。我们应该会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/cb3ca628-e055-4f31-a9d2-0589fd3f02f8.png)

这是测试我们菜单功能的一个良好开端。现在我们知道我们的菜单中有两个链接，我们想要测试的下一个用例是第一个链接是否为`list-cars`。

以下是测试链接数组中第一个链接是否为`list-cars`的代码：

```ts
// Check the app has first link as "List Cars"
 it('should check that the first link is list-cars ', () => {
 const fixture = TestBed.createComponent(MenuComponent);
 fixture.detectChanges();
 const compiled = fixture.debugElement.nativeElement;

 let linkDes = fixture.debugElement.queryAll(By.css('.nav-link'));

 expect(linkDes[0].properties.href).toBe('/list-cars', '1st link should  
    go to Dashboard');
 });
```

在前面的代码中，我们正在为我们的`MenuComponent`组件创建一个固定装置。使用`debugElement`和`queryAll`方法，我们正在查找所有类名为`nav-link`的链接。我们将获得所有具有类名`nav-link`的链接。菜单中可能有多个链接，但我们感兴趣的是通过`index [0]`读取第一个元素的`href`属性，并断言该值是否匹配`/list-cars`。

再次运行`ng test`命令。我们应该会看到我们的测试报告已更新，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/549a54fe-1de2-4743-9569-c0f55abf7c6a.png)

好的，公平的。我们得到了一个线索，即`list-cars`菜单链接是菜单列表中的第一个。如果我们不知道我们正在搜索的链接的索引或位置会怎么样？让我们也解决这个用例。

看一下以下代码片段：

```ts
// Check the app if "List Cars" link exist
 it('should have a link to /list-cars', () => {
 const fixture = TestBed.createComponent(AppComponent);
 fixture.detectChanges();
 const compiled = fixture.debugElement.nativeElement;
 let linkDes = fixture.debugElement.queryAll(By.css('.nav-link'));
 const index = linkDes.findIndex(de => {
 return de.properties['href'] === '/list-cars';
 });
 expect(index).toBeGreaterThan(-1);
 });
```

需要注意的一些事情是，我们正在查找路由路径`/list-cars`的索引，并且我们还在使用分配的类`nav-link`，并使用`queryAll`方法获取所有匹配元素的数组。使用`findIndex`方法，我们正在循环数组元素以找到匹配`href`为`/list-cars`的索引。

再次使用`ng test`命令运行测试，更新后的测试报告应如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/549a54fe-1de2-4743-9569-c0f55abf7c6a.png)

在本节中，我们学习了各种方法来定位路由链接。同样的原则也适用于查找深链接或子链接。

这就是你的作业。

# 测试依赖注入

在之前的章节中，我们学习了如何编写测试脚本来测试 Angular 组件和路由。在本节中，我们将学习如何测试依赖注入以及如何测试 Angular 应用程序中的服务。我们还将学习如何将服务注入到 Angular 组件中，并编写测试脚本来测试它们。

# 什么是依赖注入？

**依赖注入**（**DI**）在 Angular 框架中是一个重要的设计模式，它允许在运行时将服务、接口和对象注入到类中，从而实现灵活性。

DI 模式有助于编写高效、灵活、可维护的可测试和易于扩展的代码。

如果你需要快速回顾，请转到第十一章，*依赖注入和服务*，其中深入介绍和解释了 DI 机制。

# 测试 Angular 服务

在本节中，我们将学习如何通过服务和接口测试 Angular 依赖注入。为了测试一个 Angular 服务，我们首先需要在我们的应用程序中创建一个服务！

在 Angular CLI 中使用`ng generate`命令，我们将在项目文件夹中生成服务：

```ts
ng generate service services/dealers
```

成功执行后，我们应该看到以下文件已被创建：

+   `services/dealers.service.spec.ts`

+   `services/dealers.service.ts`

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/16932a86-4c60-4be2-b764-e7b7d5b96c69.png)

现在我们已经生成了我们的经销商服务和相应的测试规范文件，我们将在服务中添加一些方法和变量，以便在我们的测试规范中使用它们。导航到我们的服务类并更新`dealers.service.ts`文件。更新后的代码应如下所示：

```ts
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class DealersService {
  dealers: any;

  constructor(private http : HttpClient) { }

  getDealers(){
    this.dealers = [
      { id: 1, name: 'North Auto'},
      { id: 2, name: 'South Auto'},
      { id: 3, name: 'East Auto'},
      { id: 4, name: 'West Auto'},
    ];

    return this.dealers;
  }

}
```

在上述代码中，我们进行了简单的更改，以便我们可以围绕经销商服务编写一些测试规范。我们定义了一个`any`类型的变量。我们正在定义一个`getDealers`方法，它将返回一个带有`id`和`name`键对的 JSON 响应。好了，现在让我们想出一些用例来编写我们的测试脚本，比如获取经销商的数量，查找匹配的经销商等。

使用案例＃1：当调用`getDealers`方法时，它应返回经销商列表，计数应等于`4`。

以下是此测试规范：

```ts
it('Test Dependency Injection to get 4 dealers', () => {
const service: DealersService = TestBed.get(DealersService);
let dealers = service.getDealers();
expect(dealers.length).toBe(4);
});
```

使用案例＃2：我们想要检查第一个经销商的名称是否为`North Auto`。

以下是此测试规范：

```ts
it('Test if the first Dealer is North Auto', () => {
const service: DealersService = TestBed.get(DealersService);
let dealers = service.getDealers();
expect(dealers[0].name).toBe('North Auto');
});
```

太棒了！到目前为止，一切顺利。因此，我们已经学会了如何为我们新创建的经销商服务编写测试规范。这只是依赖注入的一部分。作为依赖注入的一部分，我们可能需要在运行时将其他所需的类注入到服务中。

让我们快速创建一个名为`Dealers`的类，并在其中定义两个变量，即`username`和`name`。现在，让我们将此文件保存为`dealers.ts`：

```ts
export class Dealers {

 constructor(
  public username: string = '',
  public name: string = ''
 ) {};

}
```

我们现在将在我们的经销商服务中包含新创建的类，并创建一个方法来初始化该类并创建一个对象来返回一些数据：

```ts
getDealerObject()
 {
 this.dealerObj= new Dealers('World','Auto');
 return this.dealerObj;
 }
```

这将引出我们下一个要测试的用例。

使用案例＃3：测试通过已注入到服务中的类进行依赖注入。

看一下以下代码：

```ts
 it('Test if the dealer returned from object is World Auto', () => {
 const service: DealersService = TestBed.get(DealersService);
 let dealerObj = service.getDealerObject();
 expect(dealerObj.name).toBe('Auto');
 });
```

在上述代码中，我们创建了我们服务的一个实例并调用了`getDealerObject()`方法。我们断言返回的值是否与响应的`name`属性匹配`Auto`。

我们正在调用服务中定义的方法，该方法在内部依赖于`Dealers`类。

使用案例＃4：如果我们只想测试`Dealers`类的属性怎么办？

我们也可以测试。以下是此示例代码：

```ts

it('should return the correct properties', () => {
var dealer = new Dealers();
dealer.username = 'NorthWest';
dealer.name = 'Auto';

expect(dealer.username).toBe('NorthWest');
expect(dealer.name).toBe('Auto');

});
```

现在，让我们运行`ng test`命令。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/c07cd08c-8543-4d7f-9cbf-27c68f294423.png)

在同一行上，您可以编写测试脚本来测试您的服务、依赖类或接口类。

**用例＃5**：在组件内测试 Angular 服务。

我们将继续测试 Angular 依赖注入。这一次，我们将把我们的服务导入到组件中，并验证它是否按预期工作。

为了实现这个用例，我们需要对`AutoListComponent`进行更改。

看一下我们将在`auto-list.component.ts`文件中进行的更改：

```ts
import { DealersService } from '../services/dealers.service';
constructor(private _dealersService : DealersService) { }
findAuto() {
 this.dealers = this._dealersService.getDealers();
 return this.dealers;
 }
```

在上面的代码中，我们将服务商服务导入到组件中。我们在构造方法中创建了服务的实例。我们添加了一个`findAuto`方法，它使用`class _dealersService`服务的实例调用`getDealers`方法。为了在我们的组件中测试服务，让我们通过添加以下代码修改`auto-list.component.spec.ts`文件：

```ts
import { DealersService } from '../services/dealers.service';
beforeEach(() => {
 fixture = TestBed.createComponent(AutoListComponent);
 component = fixture.componentInstance;
 fixture.detectChanges();
 service = TestBed.get(DealersService);
 });
```

在上面的代码中，我们已经将我们的服务商导入到`AutoListComponent`的测试规范文件中。我们在`beforeEach`方法中使用`TestBed`创建了服务的实例。现在我们可以开始编写我们的测试规范，以测试服务。在`auto-list.component.spec.ts`中添加以下代码：

```ts
it('should click a button and call method findAuto', async(() => {
    const fixture = TestBed.createComponent(AutoListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
    spyOn(component, 'findAuto');
    let dealers = component.findAuto();
    expect(dealers.length).toEqual(4);

  }));
```

在上面的代码中，使用组件的实例，我们调用`findAuto`方法，它将从服务返回数据。它期望计数等于`4`。

使用`ng test`命令运行测试。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/e5594392-e6b7-4f21-9b7c-e7734dda862a.png)

在本节中，我们学习了各种测试 Angular 依赖注入的技术，包括服务、依赖类和在 Angular 组件内测试服务。

# 测试 HTTP

在第十二章中，*集成后端数据服务*，我们学习了如何集成后端服务，还学习了`HTTPModule`和`HTTPClient`。我们还学习了如何向服务器发出 HTTP 请求并处理响应。

在本节中，我们将学习如何编写测试脚本来测试 HTTP 请求和响应。我们将继续使用本章中创建的同一个项目——AutoStop 项目。在我们进一步进行之前，有必要准备好 REST API 端点，以便我们可以在我们的应用程序中使用它们。

我们将学习如何使用公共 API `https://jsonplaceholder.typicode.com/`，这在互联网上是免费的。我们还将创建一个本地服务器，从本地静态 JSON 文件返回模拟的 JSON 响应。

我们必须将`HttpClientModule`和`HttpClientTestingModule`导入到我们的`app.module.ts`文件中。

在我们继续编写用于测试 Angular HTTP 的测试脚本之前，我们需要更新我们在本章中一直使用的经销商服务。我们将实现一些方法，这些方法将进行 HTTP 调用 - POST/GET 以处理数据到 REST API 端点。

我们正在按照以下方式处理`dealers.service.ts`文件：

```ts
import { HttpClient } from '@angular/common/http';
import { HttpHeaders, HttpParams, HttpErrorResponse } from '@angular/common/http';
readonly REST_ENDPOINT = 'https://jsonplaceholder.typicode.com/users';
readonly DEALER_REST_ENDPOINT = 'https://jsonplaceholder.typicode.com/users/1';
private _carurl = 'http://localhost:3000/cars';
```

在上述代码中，我们正在导入所需的 HTTP 模块；即`HttpClient`、`HttpHeaders`、`HttpParams`和`HttpErrorResponse`，并定义了两个具有用户 API URL 和特定用户的 REST 端点。

我们也可以启动本地服务器。您可以使用 JSON 服务器创建本地 API。您可以在[`github.com/typicode/json-server`](https://github.com/typicode/json-server)了解更多信息。

是时候添加一些方法了，通过这些方法我们将对 REST 端点进行 HTTP 调用：

```ts
getAllDealers()
{
this.allDealers = this.http.get(this.REST_ENDPOINT,
{
headers: new HttpHeaders().set('Accept', 'aplication/json')
});
return this.allDealers;
}

getDealerById(){
let params = new HttpParams().set('id', '1');
this.dealerDetails = this.http.get(this.REST_ENDPOINT, {params});
return this.dealerDetails;
}
```

在上述代码中，我们正在创建两个方法，它们进行 HTTP GET 请求。第一个方法`getAllDealers`进行调用，并期望获得用户的 JSON 响应。第二个方法`getDealerById`将传递`id`为`1`，并期望获得单个用户数据的响应。在`getDealerById`方法中，我们使用`HttpParams`来设置要发送到端点的参数。我们还将修改我们的`autoListComponent`组件，向我们的`Component`类中添加一些方法。

我们将向我们的`auto-list.component.ts`文件添加以下代码：

```ts
findAuto() {
 this.dealers = this._dealersService.getDealers();
 return this.dealers;
 }

listAllDealers(){
 this.allDealers = this._dealersService.getAllDealers();
 }

listDealerById(){
 this.showDealerInfo = true;
 this.dealerDetail = this._dealersService.getDealerById();
 return this.dealerDetail;
 }

getCarList() {
 this.carList = this.http.get<Cars[]>(this._carurl);
 }
```

在上述代码中，我们正在添加一些方法，即`findAuto`、`listDealerById`和`getCarList`，它们进行了 HTTP 调用并调用了经销商服务中的方法。

好了，现在我们已经设置好了进行 HTTP 调用的组件和服务，我们可以开始编写我们的 HTTP 测试了。

**用例＃1**：我们要测试是否对特定 URL 进行了`GET`调用。

我们将向`auto-list.component.spec.ts`文件添加以下代码：

```ts
// Test HTTP Request From Component
 it('Test HTTP Request Method', async(() => {
 const fixture = TestBed.createComponent(AutoListComponent);

 component = fixture.componentInstance; 
 httpMock = TestBed.get(HttpTestingController);

 let carList = component.getCarList();

 fixture.detectChanges();
 const req = httpMock.expectOne('http://localhost:3000/cars');

 expect(req.request.method).toBe('GET');
 req.flush({});

 }));
```

在上述代码中，我们正在创建`AutoListComponent`的实例，使用它来调用`getCarList`方法。在`getCarList`方法中，我们正在调用`http://localhost:3000/cars`的 URL 来检索数据。我们创建了一个名为`httpMock`的`HttpTestingController`类的实例。使用`httpMock`实例，我们断言至少应该对该 URL 进行一次调用。

**用例＃2**：我们希望期望结果返回的数据多于`1`：

```ts
it('Test HTTP Request GET Method With subscribe', async(() => {
const fixture = TestBed.createComponent(AutoListComponent);
component = fixture.componentInstance;
component.listDealerById().subscribe(result => 
expect(result.length).toBeGreaterThan(0));

}));
```

在上述代码中，我们使用`AutoListComponent`的实例调用`listDealerById`方法。使用`subscribe`，我们正在映射结果并验证结果数据长度是否大于`0`。

**用例＃3**：我们想要验证从 HTTP 调用返回的数据是否匹配数据。以下是此用例场景的示例代码。

```ts
it('Test if the first Dealer is North Auto', () => {
const service: DealersService = TestBed.get(DealersService);
let dealers = service.getDealers();
expect(dealers[0].name).toBe('North Auto');
});
```

在上述代码中，我们使用`DealersService`实例调用`getDealers`方法。我们断言第一个索引属性名称的数据应为`North Auto`。

使用`ng test`命令运行测试。我们应该看到以下输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/949ad4eb-06bf-4092-a884-3c8e71f19e27.png)

如果您看到了上述输出，那太棒了。

在本节中，我们学习了如何测试进行 HTTP 请求调用的组件、服务和方法。

# 摘要

测试是应用程序生命周期中的重要方面，编写测试脚本对于应用程序开发成功至关重要。我们首先概述了 Angular 支持的框架，即 Jasmine 和 Karma。我们学习了如何使用`ng test`命令运行测试。然后，我们学习了如何使用 Angular 自动生成的 spec 文件来为所有组件和服务编写测试脚本。

我们学习了如何编写测试脚本来测试 Angular 组件、内置指令、服务和路由。我们为内置指令编写了测试脚本，例如`ngFor`、`ngIf`、`ngSwitch`和`ngModel`。我们还涵盖了用于测试 Angular 路由的用例。然后，我们创建了一个`menu`组件，并编写了测试脚本来测试`menu`组件的各种用例。

我们还探讨了测试依赖注入和服务。我们学习了各种用例，并为 Angular 服务和 HTTP 调用编写了测试脚本。

在下一章中，我们将探讨高级的 Angular 主题，如自定义指令和自定义表单验证。

继续阅读！


# 第十四章：高级 Angular 主题

在之前的章节中，我们学习了如何使用指令和表单验证器。在本章中，我们将通过自定义指令和自定义验证器来扩展我们的知识。我们还将学习如何使用 Angular 构建单页应用（SPA）。

此外，我们将探讨如何将身份验证集成到我们的 Angular 应用程序中，使用两个流行的身份验证提供者：Google Firebase 身份验证和 Auth0。

本章将涵盖以下主题：

+   自定义指令

+   自定义表单验证器

+   构建 SPA

+   用户身份验证

+   使用 Firebase 身份验证进行身份验证

+   使用 Auth0 进行身份验证

+   客户端的连接

# 自定义指令

在本节中，我们将学习如何创建自定义指令。

**首先，让我们了解什么是 Angular 指令。**

Angular 指令是扩展 HTML 功能和元素行为的一种方式。

在之前的章节中，我们学习了并实现了许多内置指令，比如`*ngIf`、`*ngFor`、`*ngSwitch`和`ngModel`。

在本节中，我们将学习如何创建我们自己的自定义指令来扩展 HTML 元素的功能。

**用例：**我们想为表单元素和`onfocus`创建一个自定义指令。背景颜色应设置为浅蓝色，边框为深蓝色，`onblur`事件应以红色突出显示。所以，让我们开始：

1.  让我们使用`ng`命令生成指令：

```ts
 ng g directive onFocusBlur
```

运行上述命令后，屏幕上会显示以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/3cd1e54a-d931-4fc0-8139-5ddec3a42f17.png)

请注意，指令文件已经生成，并且我们的`app.module.ts`文件也已更新，这意味着该指令可以在整个应用程序中使用，在任何组件中使用。

1.  在指令文件`on-focus-blur.directive.ts`中，添加以下代码行：

```ts
      import { Directive } from '@angular/core';
      import { HostListener, HostBinding } from '@angular/core';

      @Directive({
      selector: '[appOnFocusBlur]'
      })
      export class OnFocusBlurDirective {

      constructor() { }

      @HostBinding("style.background-color") backgroundColor;

      @HostListener('focus') onFocus() {
        this.backgroundColor = '#19ffe4';
      }

      @HostListener('blur') onBlur() {
        this.backgroundColor = '#ff1934';
      }

      }
```

在上面的代码中，应注意以下重要事项：

+   我们正在导入所需的模块，即`Directive`、`HostListener`和`HostBinding`。

+   使用`@directive`装饰器，我们通过选择器定义指令的名称。

+   `@HostBinding`用于在元素上设置属性。

+   `@HostListener`用于监听宿主元素上的事件。

+   在上面的示例中，我们绑定了样式背景颜色属性。我们可以在宿主元素上绑定任何样式、类或事件属性。

+   使用`@HostListener`，我们监听事件，并使用`onFocus`改变背景颜色。通过使用`onBlur`，我们重置颜色。

现在，我们可以在应用程序的任何地方使用这个装饰器。

1.  我们将在`app.component.html`文件中的表单控件输入元素中使用它：

```ts
      <input type="text" appOnFocusBlur class="nav-search" >
```

1.  使用`ng serve`命令运行应用程序，并单击`Input button`。我们应该看到以下截图中显示的输出和行为：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/cdf89346-2c82-4201-81be-8a2418dbdf4e.png)

很好。现在我们知道如何编写自定义指令，我们将继续尝试创建我们自己的自定义指令。

在下一节中，我们将学习如何编写自定义表单验证。

# 自定义表单验证

在之前的章节中，我们学习了表单和实现表单验证。我们使用了内置的表单验证或 HTML5 属性验证。但是，在更复杂的场景中，我们将需要实现自定义表单验证。这些验证因应用程序而异。在本节中，我们将学习自定义表单验证。简而言之，Angular 通过`Validators`模块为我们提供了各种选项，通过它们我们可以在 Angular 表单中实现表单验证。

以下代码示例中展示了使用验证器：

```ts
loginForm = new FormGroup({
 firstName: new FormControl('',[Validators.required, 
 Validators.maxLength(15)]),
 lastName: new FormControl('',[Validators.required]),
 });
```

在上述代码中，我们使用`Validators`模块应用了`required`、`maxLength`等验证。

现在，让我们学习如何创建我们自己的自定义表单验证。首先，我们将生成一个组件，在其中我们将实现一个表单和一些元素，以便我们可以应用我们新创建的指令：

```ts
ng g c customFormValidation
```

成功运行上述命令后，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/284630e6-e257-49e4-a9cb-aeff46dd93d7.png)

现在我们已经生成了我们的组件，让我们生成一个指令，在其中我们将实现自定义表单验证。

我们将实现一个自定义指令来检查 ISBN 字段。

**什么是 ISBN？** ISBN 是每本出版书籍的唯一标识符。

以下是 ISBN 号码所需的条件：

+   ISBN 号码应该正好是 16 个字符

+   只允许使用整数作为 ISBN。

现在，使用`ng`命令，我们将生成我们的指令：

```ts
ng g directive validISBN
```

成功执行上述命令后，我们应该看到以下截图中显示的输出

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f28be244-663e-4cb2-af58-3629cdb61b26.png)

在`valid-isbn.directive.ts`文件中，添加以下代码行：

```ts
import { Directive } from  '@angular/core'; import { NG_VALIDATORS, ValidationErrors, Validator, FormControl } from  '@angular/forms'; 
@Directive({
    selector: '[validISBN]',
    providers: [
         { provide: NG_VALIDATORS, 
            useExisting: ValidISBNDirective, multi: true }
    ]
})  
export  class ValidISBNDirective implements Validator { static validateISBN(control: FormControl): ValidationErrors | null {       
 if (control.value.length <  13) {
 return { isbn: 'ISBN number must be 13 digit long' };        }
 if (!control.value.startsWith('Packt')) {
 return { isbn: 'Value should start with Packt' };        }
 return  null;
    }

    validate(c: FormControl): ValidationErrors | null {        return ValidISBNDirective.validateISBN(c);    }
}
```

让我们详细分析上面的代码片段。首先，使用`ng` CLI 命令，我们生成了一个名为`validISBN`的指令。Angular CLI 将自动生成所需的文件，并预填充基本语法。我们正在导入所需的模块，即`NG_VALIDATORS`、`ValidationErrors`、`Validator`和`FormControl`。我们正在将所需的模块作为我们的提供者的一部分注入。接下来，我们实现了一个名为`validateISBN`的方法，它接受`FormControl`类型的参数。我们将我们的表单控件字段传递给这个方法，它将验证表单控件的值是否与方法中实现的条件匹配。最后，我们在`validate`方法中调用`validateISBN`方法。

现在，我们可以在任意数量的地方使用这个自定义表单验证，也就是说，无论我们需要验证或验证 ISBN 号码的地方。让我们使用`ng serve`命令运行应用程序。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/96859ad5-94e1-450c-b8a7-0df0ae0d4521.png)

到目前为止，在本章中，我们已经在一些情况下应用了一些开箱即用的想法，并学习了如何构建我们自定义的指令和自定义表单验证。我们还学会了如何轻松地将它们集成到现有或任何新的应用程序中。所有这些也可以成为单页应用的一部分。等等。什么？单页应用？那是什么？在下一节中，我们将学习关于单页应用的一切，并构建我们自己的单页应用。

# 构建单页应用

在本节中，我们将学习构建单页应用。

**什么是单页应用？**

单页应用是一种与用户交互的 Web 应用程序或网站，它通过动态重写当前页面与用户交互，而不是从服务器加载全新的页面。

把它想象成一个只有一个 HTML 文件的应用程序，页面的内容根据用户的请求动态加载。我们只创建在运行时动态渲染在浏览器中的模板。

让我给你一个很好的例子。

在第十五章中，*部署 Angular 应用程序*，使用`ng build`命令，我们生成了 Angular 应用程序的编译代码。

查看由 Angular 生成的编译源代码：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/5efe3043-eabe-4d01-8840-dfbc4b6585be.png)

在上面的截图中，你将只看到一个名为`index`的 HTML 文件。

继续打开文件 - 您会发现它是空白的。这是因为 Angular 应用程序是单页面应用程序，这意味着内容和数据将根据用户操作动态生成。

可以说所有的 Angular 应用程序都是单页面应用程序。

以下是构建单页面应用程序的一些优势：

+   页面是动态呈现的，因此我们的应用程序源代码是安全的。

+   由于编译后的源代码在用户的浏览器中呈现，页面加载速度比传统的请求和响应模型快得多。

+   由于页面加载速度更快，这导致了更好的用户体验。

+   使用`Router`组件，我们只加载特定功能所需的组件和模块，而不是一次性加载所有模块和组件。

在本书的整个过程中，我们创建了许多 Angular 应用程序，每个应用程序都是单页面应用程序。

# 用户认证

在本节中，我们将学习如何在我们的 Angular 应用程序中实现用户认证。

在广义上，用户认证包括安全地将用户登录到我们的应用程序中，用户应该能够在安全页面上查看、编辑和创建数据，最后从应用程序中注销！

在现实世界的应用程序中，需要进行大量的额外检查和安全实施，以清理用户输入，并检查他们是否是有效用户，或验证会话超时的身份验证令牌，以及其他数据检查，以确保不良元素不会进入应用程序。

以下是一些重要的用户认证模块：

+   注册新用户

+   现有用户的登录

+   密码重置

+   已登录用户的会话管理

+   一次性密码或双重认证

+   注销已登录的用户

在接下来的章节中，我们将学习如何使用 Firebase 和 Auth0 框架实现上述功能。

# 使用 Firebase 进行用户认证

在本节中，我们将学习如何使用 Firebase 实现用户认证。

**什么是 Firebase？**

Firebase 是由 Google 提供的托管服务。Firebase 为我们提供了诸如分析、数据库、消息传递和崩溃报告等功能，使我们能够快速移动并专注于我们的用户。您可以在[`firebase.com`](https://firebase.com)了解更多有关该服务的信息。现在，让我们立即开始在我们的 Angular 应用程序中实现 Firebase。

第一步是创建一个谷歌账户来使用 Firebase 服务。您可以使用您的谷歌账户登录 Firebase。一旦您成功创建了 Firebase 账户，您应该会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f161ba0f-5805-4ce3-8f99-63d49865c3b5.png)

要创建一个新项目，请点击“添加项目”链接。

您将看到以下对话框窗口，提示您输入项目名称；在我们的情况下，我们正在将我们的项目命名为 AutoStop：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/171935b2-bfb4-4c12-b7cc-9d7a9534f42d.png)

请注意，谷歌将为您的项目分配一个唯一的项目 ID。

现在，点击左侧菜单上的认证链接，设置用户认证功能，我们可以在我们的 Angular 应用程序中嵌入和设置：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/d4d69032-fb5a-4baf-b146-f22c19e9235f.png)

我们可以在这里做很多其他很酷的事情，但现在我们将专注于认证模块。

现在，点击登录方法选项卡，设置如何允许用户登录到我们的 Angular 应用程序的选项：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/0981bfab-bb5f-4c86-9f5a-2f4fedee1a15.png)

在上述截图中，您将注意到以下重要事项：

+   谷歌 Firebase 提供了各种选项，我们可以启用这些选项，通过这些选项，我们希望我们应用程序的用户登录。

+   我们需要单独启用每个提供者选项。

+   我们已在我们的应用程序中启用了电子邮件/密码和谷歌选项。

+   为了启用 Facebook、Twitter 和其他应用程序，我们需要输入各自服务提供的开发者 API 密钥。

现在，在页面上向下滚动一点，您将看到一个名为授权域的设置选项。

我们将看到 Firebase 应用程序上设置了两个默认值，即 localhost 和一个唯一的子域，在下面的截图中显示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/4a79ada7-380a-4fc1-934c-a37b910ec01e.png)

我们已经做出了必要的更改。现在，我们需要设置 Google Firebase 的应用设置。现在是在我们的 Angular 应用程序中实现用户认证的时候了。

**先决条件：**我们期望用户已经有一个正在运行的 Angular 应用程序。

打开 Angular CLI 命令提示符；我们需要安装一些模块。我们需要先安装 Angular Fire2 和 Firebase：

请注意，Angular Fire2 现在是 Angular Fire。

我们需要运行以下命令在我们的应用程序中安装 Angular Fire：

```ts
npm install angularfire2 
```

在成功执行上述命令后，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/8d6bb008-a169-42f7-a493-6da0b51b88d5.png)

一切就绪。现在，我们需要创建一个处理身份验证功能的服务。

```ts
ng g service appAuth
```

使用`ng`命令，我们正在生成一个名为`appAuth`的新服务：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/7e87e822-d886-4deb-9fff-9119466bb08e.png)

现在，是时候修改`appAuth.service.ts`文件并添加以下代码了：

```ts
import { Injectable } from '@angular/core';
import { AngularFireAuth } from '@angular/fire/auth';
import { auth } from 'firebase/app';
import { Router } from '@angular/router';

@Injectable({
providedIn: 'root'
})
export class AppAuthService {

    private authUser:any;
    private authState:any;
    private loggedInUser = false;
    private userToken ='';

constructor(public afAuth: AngularFireAuth, private router :Router) { }

login() {
this.afAuth.auth.signInWithPopup(new auth.GoogleAuthProvider());

this.loggedInUser = true;

this.afAuth.currentUser.getIdToken(true).then(token => this.userToken = token);

this.afAuth.authState.subscribe((auth) => {
this.authState = auth;
});

this.router.navigate(['/profile']);
}

isLoggedInUser(){
if(this.userToken != '')
return true;
else 
return false;
}

logout() {
this.afAuth.auth.signOut();
this.loggedInUser = false;
this.userToken = '';
}

}
```

在上述代码中，我们正在对`app-auth.service.ts`文件进行更改。应注意以下重要点：

+   我们正在将所需的类，即`AngularFireAuth`，`Auth`和`Router`，导入到服务中。

+   使用`@Injectable`，我们指定该服务在 Angular 树结构中的根级别注入。

+   我们正在定义一些私有变量，我们将在整个应用程序中使用。

+   在构造函数方法中，我们正在注入`AngularFireAuth`和`Router`类。

+   我们正在定义三种方法：`Login`，`Logout`和`isLoggedInUser`。

+   在`login`方法中，我们正在使用`this.afAuth`实例，调用`signInWithPopup`方法，并传递`auth.GoogleAuthProvider`参数，该参数来自我们在本地安装的 Firebase 应用程序：

```ts
this.afAuth.auth.signInWithPopup(new auth.GoogleAuthProvider());
```

+   当调用此方法时，将打开一个新窗口，在其中我们可以看到谷歌登录选项，使用它我们可以登录到应用程序。

+   我们正在将`this.loggedInUser`变量设置为`true`。

+   我们将已登录用户的令牌设置为`this.userToken`变量。

+   我们还订阅以获取`authState`响应。

+   最后，使用路由器实例和使用`navigate`方法，我们将用户重定向到个人资料页面。

+   在`isLoggedInUser`方法中，我们正在验证`userToken`是否已设置。如果用户已正确登录，`userToken`将被设置；否则，该方法将返回`false`。

+   在`logout`方法中，再次使用`afauth`的实例，我们正在调用`signout`方法，这将注销用户。

+   最后，我们将`userToken`设置为`empty`。

太棒了。我们已经在`app-auth.service.ts`文件中完成了所有繁重的工作。现在，是时候在我们的组件中调用这些方法了：`login`，`profile`和`log out`。

在`login.component.html`文件中，我们将添加以下登录表单：

```ts
<div *ngIf="!_appAuthService.loggedInUser">
<form [formGroup]="loginForm" (ngSubmit)="onSubmit()">

<label>
First Name:
<input type="text" formControlName="firstName">
</label>

<label>
Last Name:
<input type="text" formControlName="lastName">
</label>

<button>Login</button>

</form>
</div>
```

在上述代码中，我们只是使用`FormGroup`和`FormControllers`添加了一个 Angular 响应式登录表单。

登录表单的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f839e4c3-7077-4f1b-9572-32342ecbd4f4.png)

在`profile.component.ts`文件中，我们只是调用了`login`方法：

```ts
onSubmit(){
 this._appAuthService.login();
 console.warn(this.loginForm.value);
 }
```

现在，在`profile.component.ts`文件中，我们添加了一个检查，以查看用户是否已登录：

```ts
<div *ngIf="_appAuthService.isLoggedInUser">
<p>
profile works!
</p>

User Token is {{_appAuthService.userToken}}
</div>
```

当用户导航到个人资料页面时，如果他们已登录，他们将看到详细信息；否则，用户将被重定向到登录页面。

现在，进入最后一部分；我们将在我们的`app.component.html`文件中有一个注销链接：

```ts
<nav>
 <a routerLink='/login' *ngIf="!_appAuthService.isLoggedInUser()">Login</a>
 <a routerLink='/register'>Register</a>
 <a routerLink='/logout' *ngIf="_appAuthService.isLoggedInUser()">Logout</a>
</nav>
```

我们正在添加带有`*ngIf`条件的链接，以在用户已登录或未登录时显示相应的链接：

```ts
 ngOnInit() {
 this._appAuthService.logout();
 this.router.navigate(['/login']);
 }
```

当用户点击注销链接时，我们调用`appAuthService`的注销方法，并在成功注销后将用户重定向回登录页面。

现在，让我们使用`ng serve`命令来运行应用程序。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f7d425f0-5387-430c-a217-066b2e675169.png)

# 使用 Auth0 进行用户身份验证

在本节中，我们将学习如何使用 Auth0 实现用户身份验证。在我们继续在我们的 Angular 应用程序中实现 Auth0 之前，我们需要实现一些先决条件。让我们开始吧：

1.  首先，我们需要在 Auth0.com 上创建一个帐户。成功登录到帐户后，我们应该看到以下仪表板屏幕：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/92b08610-8389-4261-9123-c434ccc805c5.png)

我们将不得不注册我们的应用程序，以便我们可以创建所需的设置来在我们的应用程序中实现`Auth0`。

1.  点击左侧菜单上的“应用程序”链接：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/5b8583b7-7cb0-4b2a-999b-ce56a4481b66.png)

1.  现在，点击“创建应用”按钮创建一个应用：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/5748b7e1-b1a5-429d-99a9-bace80b4880a.png)

1.  我们需要输入应用程序的名称并选择我们正在构建的应用程序类型。在我们的情况下，这是一个单页 Web 应用程序，所以请继续选择该选项并点击“创建”按钮。

1.  我们需要做的下一件事是更新应用程序的重要设置。因此，点击应用程序名称并导航到“设置”选项卡：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/2c8b132e-a199-481c-880e-ce8f011e8485.png)

以下是一些需要牢记的重要事项：

+   我们需要更新允许的回调 URL、允许的 Web 起源和允许的起源（CORS）。

+   如果我们更新了允许的 Web 起源和允许的起源的详细信息，我们将收到跨源请求（CORS）错误。

我们已经在 Auth0 中调整了所需的设置，所以现在可以在我们的应用程序中实现 Auth0 了。

为了在我们的应用程序中实现 Auth0，我们需要安装一些模块，即`auth0-js`，`auth0-lock`和`angular2-jwt`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/346d273a-4246-49df-adaf-3d84e1098e9e.png)

在上述截图中，使用`npm install`命令，我们安装了所需的`Auth0`模块。现在，是时候为我们的应用程序生成服务和组件了。

首先，我们需要生成我们的服务；让我们称之为`authService`。我们需要运行以下命令来生成我们的服务：

```ts
ng g service services/auth
```

在成功执行上述命令后，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/e5103f9e-b704-4367-974a-954c468f1332.png)

我们可以验证并确认我们的服务已经生成，以及规范文件（用于编写我们的测试规范的文件）。现在我们已经创建了我们的服务，是时候生成组件了。我们将使用`ng` CLI 运行以下命令以生成所需的组件：

```ts
ng g c login
ng g c profile
```

在成功执行上述命令后，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/feacc766-c992-4b57-a824-7bf0f92b9e2e.png)

在上述截图中，我们可以验证并确认我们的所需组件，即`login`和`profile`，已成功生成。现在，我们可以继续实现我们组件的功能了。

为了使我们的应用程序更美观，让我们也安装`bootstrap` CSS 框架：

```ts
npm i bootstrap 
```

我们还需要安装`jquery`模块：

```ts
npm i jquery 
```

在成功执行上述命令后，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/76143367-3d5f-427f-93f8-64f80ae8ab07.png)

太酷了。现在，是时候在`Nav`组件中添加一些链接了：

```ts
<nav class="navbar navbar-expand-lg navbar-light bg-light">
 <a class="navbar-brand" href="#">Auth0</a>
 <button class="navbar-toggler" type="button" 
    data-toggle="collapse" data-target="#navbarSupportedContent" 
    aria-controls="navbarSupportedContent" aria-expanded="false" 
    aria-label="Toggle navigation">
 <span class="navbar-toggler-icon"></span>
 </button>

<div class="collapse navbar-collapse" id="navbarSupportedContent">
 <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="#">Home 
         <span class="sr-only">(current)</span></a>
      </li>
      <li class="nav-item">
        <a class="nav-link" *ngIf="!authService.isLoggedIn();" 
           (click)="authService.login()">Login</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" *ngIf="authService.isLoggedIn();" >Profile</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" *ngIf="!authService.isLoggedIn();"
           href="#">Register</a>
      </li>
       <li class="nav-item">
        <a class="nav-link" *ngIf="authService.isLoggedIn()" 
           (click)="authService.logout()">Logout</a>
      </li>
    </ul>
 </div>
</nav>
```

在上述代码中，应该注意以下重要点：

+   我们正在使用 Bootstrap 的`nav`组件。

+   我们正在添加一些链接并附加点击事件，例如根据用户状态登录和注销。如果用户已登录，我们将显示注销链接，否则我们将显示注册链接。

+   我们将在我们的 nav.component.ts 文件中实现这些方法。

+   我们正在使用`*ngIf`来检查用户是否已登录，并相应地切换登录和注销链接。

上述代码的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/d902fda2-9707-4a73-9c1c-42c965b1209d.png)

现在我们需要在我们生成的`auth`服务上工作。在`services/auth.service.ts`文件中，我们需要首先导入所需的模块，然后添加我们的方法`login`和`logout`：

```ts
import { tokenNotExpired } from 'angular-jwt';
import { Auth0Lock} from 'auth0-lock';
```

一旦我们导入了`Auth0Lock`和`TokenNotExpired`类，我们将创建实例以便我们可以使用它们。

看一下基本的`Auth0Lock`对象实例创建代码：

```ts
var lock = new Auth0Lock( 'YOUR_CLIENT_ID', 'YOUR_AUTH0_DOMAIN' );
```

为了创建一个`Lock`类的新对象，我们需要将客户端 ID 和域名传递给实例。

让我们在我们的`auth.service.ts`文件中实现这个：

```ts
public _idToken: string;
private _accessToken: string;
private _expiresAt: number;

 lock = new Auth0Lock('XvVLuuMQr3kKAR3ECAmBZOiPPyVYehvU','srinix.auth0.com',{
 allowedConnections: ["Username-Password-Authentication","google-oauth2"],
 rememberLastLogin: false,
 socialButtonStyle: "big",
 languageDictionary: {"title":"Auth0"},
 language: "en",
 responseType: 'token id_token',
 theme: {}
 });
```

在上述代码中，应该注意以下重要点：

+   我们创建了三个变量，分别是`_idToken`、`_accessToken`和`_expiresAt`。

+   我们正在创建一个`Auth0Lock`的实例，并且需要向对象传递参数。

+   `Auth0Lock`对象将需要传递两个必需的参数。第一个参数是`ClientId`，第二个是域名。

+   第三个参数包括`allowedConnections`、主题等选项，因为它说它们是可选的。

+   客户端 ID 和域名可以从 Auth0 应用程序设置中获取，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/002c661a-20db-48b6-8d42-877fb5bf05fd.png)

我们现在可以监听附加到`lock`对象的事件：

```ts
constructor(private router: Router) {

this.lock.on('authenticated', (authResult: any) => {
localStorage.setItem("userToken", authResult.accessToken);
this.router.navigate(['/profile']); 
});

this.lock.on('authorization_error', error => {
console.log('something went wrong', error);
});

}
```

在上述代码中，我们正在执行以下步骤：

1.  在`constructor`方法中，我们正在监听`authenticated`和`authorization_error`状态的`on`事件。

1.  当我们从`lock`实例获得认证消息时，我们正在存储一个名为`userToken`的`localStorage`项目，并将`accessToken`设置为其值。

1.  我们还在监听错误消息并将消息记录在控制台中。

现在，是时候实现`login`和`logout`方法了：

```ts
login() {
 this.lock.show(function(err, profile, token){
 console.log(err);
 console.log(profile);
 console.log(token);
 });
 }
```

在`login`方法中，我们正在调用`lock`对象的`show`方法。这将带您进入 Auth0 的对话框，其中有登录、注册或忘记密码的选项。如果您选择了任何社交选项，登录对话框将包含社交选项。

对于`logout`方法，我们只需清除用户登录时设置的`userToken`，并将用户重定向回主页登录页面。

```ts
logout(){
localStorage.setItem('userToken','');
this.router.navigate(['/']);
}
```

清除`userToken`后，应用程序将知道用户未登录。

我们已经实现了`login`和`logout`方法，但我们还需要一个方法来检查用户是否已登录：

```ts
 isLoggedIn() {
 var token = localStorage.getItem('userToken');
 if(token != '')
 {
 return true;
 }
 else {
 return false;
 }
 }
```

在`isLoggedIn`方法中，我们正在检查本地存储中`userToken`变量的值是否设置。如果设置了值，这意味着用户已登录；否则，用户未登录。

只需将服务导入到我们的`app.component.ts`文件中，并将其注入到构造函数中：

```ts
import { Component } from '@angular/core';
import { AuthService } from './services/auth.service';

@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.scss']
})
export class AppComponent {
 title = 'Auth0 Tutorial';
 userToken:string;

 constructor(private authService: AuthService) {}
}
```

就是这样。是不是很简单？

我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/f5ad21f4-0db1-4521-9926-36055712db9b.png)

如果我们点击登录链接，我们应该看到 Auth0 对话框弹出窗口：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/79c791e3-7840-462a-b7de-7c3cd67d5828.png)

现在，继续点击“注册”选项卡创建一个账户，一旦成功注册，您应该看到该用户也已添加到 Auth0 仪表板中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/6208686e-8b0a-4e39-845d-ebc4c44b3eff.png)

成功登录后，我们应该只能看到注销链接，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/63ae6c9f-5546-4853-810c-5f09b9c876d3.png)

当我们点击注销链接时，用户应该被带回默认的登陆页面，并应该看到登录和注册选项。还要注意 URL 中提供的参数，如`access_token expires_in`等。

太棒了！我们刚刚在我们的应用程序中使用 Auth0 实现了整个用户身份验证。

# 总结

在本章中，我们学习了一些高级的 Angular 主题，从创建自定义指令到扩展原生 HTML 元素的行为。我们还创建了自定义表单验证，这在开发具有许多验证和合规性要求的复杂应用程序时非常有用。我们深入研究了 Angular 单页应用程序，并了解了它们的工作和行为。我们通过原生代码在我们的 Angular 应用程序中实现了用户身份验证。

我们还学习了如何使用现有框架构建和实现安全的用户身份验证管理系统，即 Firebase 和 Auth0。然后，我们学习了如何实现登录、注册和注销功能，以确保我们可以保护应用程序的数据和功能。现在我们已经掌握了前面的概念，可以实现一个完整的、有线的端到端 Angular 应用程序了。

现在我们已经学会了如何开发我们的 Angular 应用程序，唯一隔我们的应用程序和真实用户之间的就是部署我们的应用程序。这是我们下一章的重点。在本书的下一章和最后一章中，我们将学习如何部署我们的 Angular 应用程序。
