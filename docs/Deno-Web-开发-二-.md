# Deno Web 开发（二）

> 原文：[`zh.annas-archive.org/md5/05CD4283AEDF57F3F0FCDC18A95F489E`](https://zh.annas-archive.org/md5/05CD4283AEDF57F3F0FCDC18A95F489E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：构建应用程序

在这个动手实践的环节，你将创建一个 Deno 应用程序，从服务器端渲染的网站开始，然后过渡到**代表性状态传输**（**REST**）**应用程序编程接口**（**APIs**），这些接口与数据库相连并具备认证功能。

本部分包含以下章节：

+   第*4*章，[构建 Web 应用程序](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=27af6495-f282-9e92-d711-5f324262765f)

+   第*5*章，[向系统中添加用户并将系统迁移到 Oak](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=7ba1253a-67f3-ded3-ed2a-5f324271642a)

+   第*6*章，[向系统中添加认证并连接数据库](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=9932a37e-89e6-72d0-adbb-5f3242397a64)

+   第*7*章，[HTTPS、提取配置以及 Deno 在浏览器中的使用](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=27af6495-f282-9e92-d711-5f324262765f)


# 第四章：构建 Web 应用程序

到这里我们来了！我们走过了漫长的一段路才到达这里。这里才是所有乐趣的开始。我们已经经历了三个阶段：了解 Deno 是什么，探索它提供的工具链，以及通过其运行时了解其细节和功能。

前几章的大部分内容将在这一章中证明是有用的。希望，入门章节让您有信心开始应用我们一起学到的内容。我们将使用这些章节以及您现有的 TypeScript 和 JavaScript 知识，来构建一个完整的 Web 应用程序。

我们将编写一个包含业务逻辑、处理身份验证、授权和日志记录等内容的 API。我们将涵盖足够的基础知识，以便您最终可以自信地选择 Deno 来构建您下一个伟大的应用程序。

在本章中，我们不仅要谈论 Deno，还要回顾一些关于软件工程和应用程序架构的基本思想。我们认为，在从头开始构建应用程序时，牢记一些事情至关重要。我们将查看一些基本原理，这些原理将被证明是有用的，并帮助我们构建代码，使其易于在未来变化中进化。

稍后，我们将开始引用一些第三方模块，查看它们的方法，并决定从这里开始我们将使用什么来帮助我们处理路由和与 HTTP 相关的挑战。我们还将确保我们以一种使第三方代码隔离并作为我们想要构建的功能的使能者而不是功能本身来工作的方式来构建我们的应用程序。

本章我们将涵盖以下主题：

+   构建 Web 应用程序的结构

+   探索 Deno HTTP 框架

+   让我们开始吧！

## 技术要求

本章使用的代码文件可在以下链接找到：[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter04/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter04/museums-api)。

# 构建 Web 应用程序的结构

当开始一个应用程序时，花时间思考其结构和架构是很重要的。这一节将从这个角度开始：通过查看应用程序架构的骨架。我们将看看它带来了什么优势，并使自己与一套原则保持一致，这些原则将帮助我们在应用程序增长时扩展它。

然后，我们将开发出将成为应用程序第一个端点的部分。然而，首先，我们将从业务逻辑开始。持久层将紧随其后，最后我们将查看一个 HTTP 端点，它将作为应用程序的入口点。

## Deno 作为一个无偏见的工具

当我们使用低级别的工具，并将许多决策权委托给开发者时，如 Node.js 和 Deno，构建应用程序是随之而来的一个重大挑战。

这与具有明确观点的 Web 框架，如 PHP Symfony、Java SpringBoot 或 Ruby on Rails，有很大的不同，在这些框架中，许多这些决策已经为我们做出。

这些决策大多数与结构有关；也就是说，代码和文件夹结构。这些框架通常为我们提供处理依赖项、导入的方法，甚至在不同的应用程序层次结构上提供一些指导。由于我们使用的是*原始*语言和几个包，因此在这本书中我们将自己负责这些结构。

前述框架不能直接与 Deno 相比较，因为它们是构建在诸如 PHP、Java 和 Ruby 等语言之上的框架。但是当我们查看 JS 世界，尤其是 Node.js 时，我们可以观察到最常用来创建 HTTP 服务器的最受欢迎工具是 Express.js 和 Kao.js。这些通常比前述框架轻量级得多，尽管还有一些坚固完整的替代方案，如 Nest.js 或 hapi.js，但 Node.js 社区更倾向于采用*库*方法，而不是*框架*方法。

尽管这些非常流行的库提供了大量功能，但许多决策仍然委托给开发者。这不是库的错，更多的是一个社区偏好。

一方面，直接访问这些原语让我们能够构建非常适合我们用例的应用程序。另一方面，灵活性是一个权衡。拥有大量的灵活性随之而来的是做出无数决策的责任。而当需要做出许多决策时，就有很多机会做出糟糕的决策。难点在于，这些通常是对代码库扩展方式产生巨大影响的决策，这也是它们如此重要的原因。

在当前状态下，Deno 及其社区在框架与库这一问题上遵循与 Node.js 非常相似的方法。社区主要押注于由开发者创建的轻量级且小巧的软件，以适应他们的特定需求。我们将在本章后面评估其中的一些。

从现在开始，在这本书的其余部分，我们将使用一种我们相信对当前用例有很大好处的应用程序结构。然而，不要期望这种结构和架构是灵丹妙药，因为我们深信软件世界中不存在这样的东西；每种架构都将随着成长而不断进化。

我们想要的不仅仅是扔进一个食谱并遵循它，而是要熟悉一种思维方式——一种推理。这应该能让我们在将来做出正确的决策，目标只有一个：*编写易于更改的代码*。

通过编写易于更改的代码，我们总是准备好在不需要太多努力的情况下改进我们的应用程序。

## 应用程序最重要的部分

应用程序是为了适应一个目的而被创建的。无论这个目的是支持一个企业还是一个简单的宠物项目都不重要。归根结底，我们希望它能做些什么。那*些什么*就是使应用程序变得有用的原因。

这可能听起来很显然，但有时对于我们这些开发者来说，我们很容易因为对一种技术的热情而忘记，它只是达到目的的一种手段。

正如 Uncle Bob 在他的*Architecture – the lost years*演讲中所说([`www.youtube.com/watch?v=hALFGQNeEnU`](https://www.youtube.com/watch?v=hALFGQNeEnU)),人们很容易忘记应用程序的目的，而更多地关注技术本身。在我们开发应用程序的所有阶段，记住这一点非常重要，尤其是在建立其初始结构时更是如此。接下来，我们将探讨本书剩余部分我们将要构建的应用程序的需求。

## 我们的应用程序是关于什么的？

虽然我们确实相信在任何应用程序中业务逻辑是最重要的事情，但在这本书中，情况有点不同。我们将创建一个示例应用程序，但它只是一个达到主要目标：学习 Deno 的手段。然而，为了使过程尽可能真实，我们希望在心中有一个清晰的目标。

我们将构建一个允许人们创建和与博物馆列表互动的应用程序。我们可以通过将其功能作为用户故事列出使其更清晰，如下所示：

+   用户能够注册和登录。

+   用户能够创建一个带有标题、描述和位置的博物馆。

+   用户可以查看博物馆列表。

在这个旅程中，我们将开发 API 和支持这些功能的逻辑。

既然我们已经熟悉了最终目标，我们可以开始思考如何组织应用程序。

## 理解文件结构和应用程序架构

关于文件结构，我们首先需要意识到的一点，特别是当我们从零开始一个没有框架的项目时，它将随着项目的发展而不断演变。对于只有几个端点的项目来说好的文件结构，对于有数百个端点的项目来说可能不那么好。这取决于许多事情，从团队规模，到定义的标准，最终到偏好。

在定义文件结构时，重要的是我们要达到一个地步，使我们能够促进关于代码放置位置的未来决策。文件结构应该为如何做出良好的架构决策提供清晰的提示。

同时，我们当然不希望创建一个过度工程化的应用程序。我们将创建足够的抽象，使模块非常独立，并且没有超出它们领域的知识，但不会超过这个程度。牢记这一点也迫使我们构建灵活的代码和清晰的接口。

最终，最重要的是架构能够使代码库具备以下特点：

+   可测试。

+   易于扩展。

+   与特定技术或库解耦。

+   易于导航和理解。

在创建文件夹、文件和模块时，我们必须要记住，绝不能有任何妥协前面提到的话题。

这些原则与软件设计中的 SOLID 原则非常一致，由“Uncle Bob”Robert C. Martin 在一次演讲中提出（[`en.wikipedia.org/wiki/SOLID`](https://en.wikipedia.org/wiki/SOLID)），该演讲值得一看（[`youtu.be/zHiWqnTWsn4`](https://youtu.be/zHiWqnTWsn4)）。

本书我们将要使用的文件夹结构，如果你有 Node.js 背景，可能会觉得熟悉。

正如发生在 Node.js 一样，我们完全可以在一个文件中创建一个完整的 API。然而，我们不会这样做，因为我们认为在初始阶段对关注点进行一些分离将大大提高我们的灵活性，而不会牺牲开发者的生产力。

在下一节中，我们将探讨不同层次的责任以及它们在我们开发应用程序功能时的相互配合。

遵循这种思路，我们努力确保模块之间的解耦程度。例如，我们希望通过确保在 web 框架中的更改不会影响到业务逻辑对象。

所有这些建议，以及我们在这本书中将会提出的建议，将有助于确保我们应用程序的核心部分是业务逻辑，其他所有内容只是插件。JSON API 只是一种将我们的数据发送给用户的方式，而数据库只是一种持久化数据的方式；这些都不应该是应用程序的核心部分。

确保我们这样做的一种方法是在编写代码时进行以下心理练习：

当你在编写业务逻辑时，想象这些对象将在不同的上下文中使用。例如，使用不同的交付机制（例如 CLI）或不同的持久化引擎（内存数据库而非 NoSQL 数据库）。

在接下来的几页中，我们将引导您如何创建不同的层次，并解释所有设计决策以及它们所启用的功能。

让我们来实际操作，开始构建我们项目的基础框架。

### 定义文件夹结构。

在我们项目的文件夹中，我们首先要创建一个 `src` 文件夹。

这里， predictably，是我们的代码将要存放的地方。我们不希望项目的根目录有任何代码，因为可能会在这里添加配置文件、READMEs、文档文件夹等。这会使代码难以区分。

在接下来的章节中，我们将在`src`文件夹内度过大部分时间。由于我们的应用程序是关于博物馆的，我们将在`src`文件夹内创建一个名为`museums`的文件夹。这个文件夹将存放本章将编写的 most of the logic。稍后，我们将创建类型、控制器和方法文件。然后，我们将创建`src/web`文件夹。

控制器的文件是我们的业务逻辑将存放的地方。仓库将处理与数据访问相关的逻辑，而网络层将处理所有与*网络相关*的事情。

您可以通过查看本书的 GitHub 仓库来查看最终结构：[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter04/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter04/museums-api)。

本章的初始要求是有一个路由，我们可以在此路由上执行 GET 请求，并接收以 JSON 格式表示的博物馆列表。

我们将在控制器文件（`src/museums/controller.ts`）中开始编写所需的业务逻辑。

文件夹结构应该如下所示：

```js
└── src
    ├── museums
    │   ├── controller.ts
    │   ├── repository.ts
    │   └── types.ts
    └── web
```

这是我们开始的地方。与博物馆有关的所有内容都将在`museums`文件夹内，我们将称之为一个模块。`controller`文件将托管业务逻辑，`repository`文件将托管数据获取功能，而`types`文件将位于我们的类型。

现在，让我们开始编写代码！

## 编写业务逻辑

我们之前说过，我们的业务逻辑是应用程序最重要的部分。尽管我们的业务逻辑现在非常简单，但这是我们首先开发的。

由于我们将使用 TypeScript 来编写我们的应用程序，让我们创建一个定义`Museum`对象的接口。按照以下步骤操作：

1.  进入`src/museums/types.ts`，并创建一个定义`Museum`的类型：

    ```js
    export type Museum = {
      id: string,
      name: string,
      description: string,
      location: {
        lat: string,
        lng: string
      }
    }
    ```

    确保它被导出，因为我们将跨其他文件使用此文件。

    现在我们已经知道了类型，我们必须创建一些业务逻辑来获取博物馆列表。

1.  在`src/museums/types.ts`中，创建一个接口，定义`MuseumController`。它应该包含一个列出所有博物馆的方法：

    ```js
    export interface MuseumController {
      getAll: () => Promise<Museum[]>;
    }
    ```

1.  在`src/museums/controller.ts`中，创建一个类，作为控制器。它应该包含一个名为`getAll`的函数。将来，这里将存放业务逻辑，但现在，我们只需返回一个空数组：

    ```js
    import type { MuseumController } from "./types.ts";
    export class Controller implements MuseumController {
      async getAll() {
        return [];
      }
    } 
    ```

    我们可以用这个直接访问数据库并获取某些记录。然而，由于我们希望能够使我们的业务逻辑孤立，并且不与应用程序的其他部分耦合，所以我们不会这样做。

    此外，我们还希望我们的业务逻辑能够在没有数据库或服务器连接的情况下独立测试。为了实现这一点，我们不能直接从我们的控制器访问数据源。稍后，我们将创建一个抽象，它将负责从数据库获取这些记录。

    目前，我们知道我们需要调用一个外部模块，它将为我们获取所有的博物馆，并将它们交给我们的控制器——它来自哪里无关。

    请记住以下软件设计最佳实践：*"面向接口编程，而不是面向实现。"*

    简单地说，这句话的意思是我们应该定义模块的签名，然后才开始考虑它的实现。这大大有助于设计清晰的接口。

    回到我们的控制器，我们知道控制器的`getAll`方法最终必须调用一个模块来从数据源获取数据。

1.  在`src/museums/types.ts`中，定义`MuseumRepository`，这个模块将负责从数据源获取博物馆：

    ```js
    export interface MuseumRepository {
      getAll: () => Promise<Museum[]>
    }
    ```

1.  在`src/museums/controller.ts`中，向构造函数中添加一个注入的类`museumRepository`：

    ```js
    museumRepository that implements the MuseumRepository interface. By creating this and *lifting the dependencies*, we no longer need to return an empty array from our controller.Before we write any more logic, let's make sure our code runs and check if it is working. We're just missing one thing.
    ```

1.  创建一个名为`src/index.ts`的文件，导入`MuseumController`，实例化它，并调用`getAll`方法，记录其输出。现在，你可以注入一个伪仓库，它只是返回一个空数组：

    ```js
    import { Controller as MuseumController } from
      "./museums/controller.ts";
    const museumController = new MuseumController({
      museumRepository: {
        getAll: async () => []
      }
    })
    console.log(await museumController.getAll())
    ```

1.  运行它以检查它是否正常工作：

    ```js
    $ deno run src/index.ts 
    []
    ```

    就这样！我们刚刚从伪仓库函数接收到了一个空数组！

有了我们创建的这种抽象，我们的控制器现在与数据源解耦。其依赖关系通过构造函数注入，允许我们稍后不更改控制器而更改仓库。

我们刚才所做的称为**依赖倒置**——SOLID 原则中的**D**——它包括将部分依赖性提升到函数调用者。这使得独立测试内部函数变得非常容易，正如我们将在*第八章**测试——单元和集成*中看到的，我们将涵盖测试。

为了将我们刚刚编写的代码转换为完全功能的应用程序，我们需要有一个数据库或类似的东西。我们需要能够存储和检索博物馆列表的东西。我们现在来创建这个东西。

## 开发数据访问逻辑

在开发控制器的过程中，我们注意到我们需要能够获取数据；也就是说，仓库。这个模块将抽象所有对数据源的调用，在这个案例中，数据源存储博物馆。它将有一套非常明确的方法，任何想要访问数据的人都应该通过这个模块来访问。

我们已经在`src/museums/types.ts`中定义了其部分接口，所以让我们写一个实现它的类。现在，我们不会将它连接到真实数据库。我们将其作为内存数据库使用 ES6 Map。

让我们进入我们的仓库文件，并按照以下步骤开始编写我们的数据访问逻辑：

1.  打开 `src/museums/repository.ts` 文件并创建一个 `Repository` 类。

    它应该有一个名为 `storage` 的属性，这将是一个 JavaScript `Map`。`Map` 的键应该是字符串，值应该是 `Museum` 类型的对象：

    ```js
    import type { Museum, MuseumRepository } from
      "./types.ts";
    export class Repository implements MuseumRepository {
      storage = new Map<string, Museum>();
    }
    ```

    我们正在使用 TypeScript 泛型来设置我们的 `Map` 类型。请注意，我们引入了来自博物馆控制器 的 `Museum` 接口，以及由我们的类实现的 `MuseumRepository`。

    现在“数据库”已经“就绪”，我们必须暴露某些方法，这样人们就可以与它交互。上一节的要求是我们可以从数据库中获取所有记录。让我们接下来实现它。

1.  在仓库类内部，创建一个名为 `getAll` 的方法。它应该负责返回我们 `storage` `Map` 中的所有记录：

    ```js
    export class Repository implements MuseumRepository {
      storage = new Map<string, Museum>();
    src should only be accessible from the outside through a single file. This means that whoever wants to import stuff from src/museums should only do so from a single src/museums/index.ts file.
    ```

1.  创建一个名为 `src/museums/index.ts` 的文件，该文件导出博物馆的控制器 和仓库：

    ```js
    export { Controller } from "./controller.ts";
    export { Repository } from "./repository.ts";
    export type { Museum, MuseumController,
      MuseumRepository } from "./types.ts"; 
    ```

    为了保持一致性，我们需要去所有之前从不是 `src/museums/index.ts` 的文件导入的导入，并更改它们，使它们只从这个文件导入东西。

1.  将 `controller.ts` 和 `repository.ts` 的导入更新为从 `index` 文件导入：

    ```js
    import type { MuseumController, MuseumRepository }
      from "./index.ts";
    ```

    你可能已经猜到我们接下来必须做什么了…… 你还记得上一节的末尾，我们在博物馆控制器中注入了一个返回空数组的伪函数吗？让我们回到这里并使用我们刚刚编写的逻辑。

1.  回到 `src/index.ts`，导入我们刚刚创建的 `Repository` 类，并将其注入到 `MuseumController` 构造函数中：

    ```js
    import {
      Controller as MuseumController,
      Repository as MuseumRepository,
    } from "./museums/index.ts";
    const museumRepository = new MuseumRepository();
    const museumController = new MuseumController({
      museumRepository })
    console.log(await museumController.getAll())
    ```

    现在，让我们向我们的“数据库”添加一个 fixture，这样我们就可以检查它是否实际上正在打印一些内容。

1.  访问 `museumRepository` 中的存储属性并为其添加一个 fixture。

    这目前是一个反模式，因为我们直接访问模块的数据库，但我们将创建一个方法，以便我们以后可以正确添加 fixtures：

    ```js
    const museumRepository = new MuseumRepository();
    …
    museumRepository.storage.set
      ("1fbdd2a9-1b97-46e0-b450-62819e5772ff", {
      id: "1fbdd2a9-1b97-46e0-b450-62819e5772ff",
      name: "The Louvre",
    description: "The world's largest art museum 
        and a historic monument in Paris, France.",
      location: {
        lat: "48.860294",
        lng: "2.33862",
      },
    });
    console.log(await museumController.getAll())
    ```

1.  现在，让我们再次运行我们的代码：

    ```js
    $ deno run src/index.ts
    [
      {
        id: "1fbdd2a9-1b97-46e0-b450-62819e5772ff",
        name: "The Louvre",
        description: "The world's largest art
          museum and a historic monument in Paris,
            France.",
        location: { lat: "48.860294", lng: "2.33862" }
      }
    ]
    ```

    有了这个，我们的数据库连接就可以工作了，正如我们通过打印的 fixture 所看到的那样。

我们在上一节中创建的抽象使我们能够在不更改控制器的情况下更改数据源。这是我们正在使用的架构的一个优点。

现在，如果我们回顾一下我们的初始需求，我们可以确认我们已经完成了一半。我们已经创建了满足用例的业务逻辑——我们只是缺少 HTTP 部分。

## 创建网络服务器

现在我们已经有了我们的功能，我们需要通过一个网络服务器来暴露它。让我们使用我们从标准库中学到的知识来创建它，并按照以下步骤进行：

1.  在 `src/web` 文件夹中创建一个名为 `index.ts` 的文件，并在那里添加创建服务器的逻辑。我们可以从上一章的练习中复制和粘贴它：

    ```js
    import { serve } from
      "https://deno.land/std@0.83.0/http/server.ts";
    const PORT = 8080;
    const server = serve({ port: PORT });
    console.log(`Server running at
      https://localhost:${PORT}`);
    for await (let req of server) {
      req.respond({ body: 'museums api', status: 200 })
    }
    ```

    由于我们希望应用程序易于配置，我们不希望`port`在这里是硬编码的，而是可以从外部配置的。我们需要将这个服务器创建逻辑作为一个函数导出。

1.  将服务器逻辑创建包裹在一个函数中，该函数接收配置和`port`作为参数：

    ```js
    import { serve } from
      "https://deno.land/std@0.83.0/http/server.ts";
    port defining its type. 
    ```

1.  将这个函数的参数改为`interface`。这将有助于我们的文档，同时也会增加类型安全和静态检查：

    ```js
    interface CreateServerDependencies {
      configuration: {
        port: number
      }
    }
    export async function createServer({
      configuration: {
        port
      }
    }: CreateServerDependencies) {
    …
    ```

    现在我们已经配置了 Web 服务器，我们可以考虑将其用于我们的用例。

1.  回到`src/index.ts`，导入`createServer`，并使用它创建一个在端口`8080`上运行的服务器：

    ```js
    import { createServer } from "./web/index.ts";
    …
    createServer({
      configuration: {
        port: 8080
      }
    })
    …
    ```

1.  运行它，看看它是否正常工作：

    ```js
    $ deno run --allow-net src/index.ts
    Server running at http://localhost:8080
    [
      {
        id: "1fbdd2a9-1b97-46e0-b450-62819e5772ff",
        name: "The Louvre",
        description: "The world's largest art museum and a
          historic monument in Paris, France.",
        location: { lat: "48.860294", lng: "2.33862" }
      }
    ]
    ```

在这里，我们可以看到有一个日志记录服务器正在运行，以及来自上一节的日志结果。

现在，我们可以用`curl`测试 Web 服务器，以确保它正在工作：

```js
$ curl http://localhost:8080
museums api
```

正如我们所看到的，它起作用了——我们有一些相当基础的逻辑，但这仍然不能满足我们的要求，却能启动一个 Web 服务器。我们接下来要做的就是将这个 Web 服务器与之前编写的逻辑连接起来。

## 将 Web 服务器与业务逻辑连接

我们已经非常接近完成本章开始时计划要做的内容。我们目前有一个 Web 服务器和一些业务逻辑；缺少的是它们之间的连接。

将两件事连接起来的一个快速方法就是在`src/web/index.ts`上直接导入控制器并在此处使用它。在这里，应用程序将具有期望的行为，目前这样做没有任何问题。

然而，由于我们考虑的是一个可以无需太多问题就能扩展的应用程序架构，所以我们不会这样做。这是因为这将使我们的 Web 逻辑在隔离测试中变得非常难以实现，从而违背了我们的一条原则。

如果我们直接从 Web 服务器中导入控制器，每次在测试环境中调用`createServer`函数时，它将自动导入并调用`MuseumController`中的方法，这不是我们想要的结果。

我们再次使用依赖倒置将控制器的函数发送到 Web 服务器。如果这仍然看起来过于抽象，不用担心——我们马上就会看到代码。

为了确保我们没有忘记我们的初始目标，我们想要的是，当用户对`/api/museums`执行`GET`请求时，我们的 Web 服务器能够返回一个博物馆列表。

由于我们正在进行这项练习，所以我们暂时不会使用路由库。

我们只是想添加一个基本检查，以确保请求的 URL 和方法是我们想要回答的。如果是，我们想返回博物馆的列表。

让我们回到`createServer`函数并添加我们的路由处理程序：

```js
export async function createServer({
  configuration: {
    port
  }
}: CreateServerDependencies) {
  const server = serve({ port });
  console.log(`Server running at
    http://localhost:${port}`);
  for await (let req of server) {
    if (req.url === "/api/museums" && req.method === "GET")     
     {
req.respond({ 
body: JSON.stringify({ 
museums: [] 
}), 
status: 200 
      })
      continue
    }
    req.respond({ body: "museums api", status: 200 })
  }
}
```

我们为请求 URL 和方法添加了一个基本检查，并在它们符合初始要求时返回不同的响应。运行代码看看它的行为如何：

```js
$ deno run --allow-net src/index.ts 
Server running at http://localhost:8080
```

再次，用`curl`测试它：

```js
$ curl http://localhost:8080/api/museums
{"museums":[]}
```

它起作用了——太棒了！

现在，我们需要定义一个接口，以满足这个请求所需的内容。

我们最终需要一个函数，它返回一个博物馆列表，然后将其注入到我们的服务器中。让我们按照以下步骤在`CreateServerDependencies`接口中添加该功能：

1.  回到`src/web/index.ts`中，将`MuseumController`作为`createServer`函数的一个依赖项：

    ```js
    MuseumController type we defined in the museum's module. We're also adding a museum object alongside the configuration object.
    ```

1.  从博物馆控制器中调用`getAll`函数以获取所有博物馆的列表并响应请求：

    ```js
    export async function createServer({
      configuration: {
        port
      },
      createServer function, but we're not sending it when we call createServer. Let's fix that.
    ```

1.  回到`src/index.ts`，这是我们调用`createServer`函数的地方，并向`MuseumController`发送`getAll`函数。你也可以删除上一节直接调用控制器方法的代码，因为现在它没有任何用处：

    ```js
    import { createServer } from "./web/index.ts";
    import {
      Controller as MuseumController,
      Repository as MuseumRepository,
    } from "./museums/index.ts";
    const museumRepository = new MuseumRepository();
    const museumController = new MuseumController({
      museumRepository })
    museumRepository.storage.set
     ("1fbdd2a9-1b97-46e0-b450-62819e5772ff", {
      id: "1fbdd2a9-1b97-46e0-b450-62819e5772ff",
      name: "The Louvre",
      description: "The world's largest art museum 
        and a historic monument in Paris, France.",
      location: {
        lat: "48.860294",
        lng: "2.33862",
      },
    });
    createServer({
      configuration: { port: 8080 },
      museum: museumController
    })
    ```

1.  再次运行应用程序：

    ```js
    $ deno run --allow-net src/index.ts
    Server running at http://localhost:8080
    ```

1.  向 http://localhost:8080/api/museums 发送请求；你会得到一个博物馆列表：

    ```js
    $ curl localhost:8080/api/museums
    {"museums":[{"id":"1fbdd2a9-1b97-46e0-b450-62819e5772ff","name":"The Louvre","description":"The world's largest art museum and a historic monument in Paris, France.","location":{"lat":"48.860294","lng":"2.33862"}}]}
    ```

就这样——我们得到了博物馆列表！

我们已经完成了本节的任务，那就是将我们的业务逻辑连接到 web 服务器。

注意我们是如何使控制器方法可以被注入，而不是 web 服务器直接导入它。这之所以可能，是因为我们使用了依赖倒置。这是我们在这本书中会不断做的事情，无论何时我们想要解耦模块和函数，并提高它们的测试性。

在我们进行代码耦合的思维锻炼时，当我们想要使用不同的交付机制（如 CLI）来使用当前的业务逻辑时，没有任何阻碍。我们仍然可以重用相同的控制器和存储库。这意味着我们很好地使用了抽象来将业务逻辑与应用程序逻辑解耦。

既然我们已经了解了应用程序架构和文件结构的基础，并且也理解了背后的原因，我们可以开始查看可能帮助我们构建它的工具。

在下一节中，我们将查看 Deno 社区中现有的 HTTP 框架。我们不会花太多时间在这方面，但我们希望了解每个框架的优缺点，并最终选择一个来帮助我们完成剩余的旅程。

# 探索 Deno HTTP 框架

当你构建一个比简单教程更复杂的应用程序时，如果你不想采取纯粹的方法，你很可能会使用第三方软件。

显然，这不仅仅是 Deno 特有的。尽管有些社区比其他社区更愿意使用第三方模块，但所有社区都在使用第三方软件。

我们可以讨论人们为什么这样做或不做，但更常见的原因总是与可靠性和时间管理有关。这可能是因为你想使用经过实战测试的软件，而不是自己构建它。有时，这只是一个时间管理问题，即不想重新编写已经创建的东西。

我们必须说的一件重要事情是我们必须在对构建的应用程序进行耦合第三方软件时非常谨慎。我们并不是说你应该试图达到完全解耦的乌托邦，尤其是因为这会引入其他问题和很多间接性。我们要说的是，我们应该非常清楚将依赖项引入我们代码中的成本以及它引入的权衡。

在本章的第一部分，我们构建了一个 web 应用的基础，我们将在本书的其余部分向其添加功能。在其当前状态下，它仍然非常小，所以它除了标准库之外没有任何依赖。

在该应用中，我们做了一些我们相信不太容易扩展的事情，比如通过使用普通的`if`语句来匹配 URL 和 HTTP 方法来定义路由。

随着应用程序的增长，我们很可能会需要更高级的功能。这些需求可能从以不同格式处理 HTTP 请求体，到拥有更复杂的路由系统，处理头部和 cookies，或者连接到数据库。

因为我们不相信在开发应用程序时重新发明轮子，所以我们将分析几个目前存在于 Deno 社区中，并专注于创建 web 应用程序的库和框架。

我们将对现有的解决方案进行一般性了解，并探索它们的功能和方法。

最后，我们将选择我们认为在我们用例中提供最佳权衡的那个。

## 还有哪些替代方案？

在写作时，有一些第三方包提供了大量功能来创建 web 应用程序和 API。其中一些深受非常流行的 Node.js 包（如 Express.JS、Koa 或 hapi.js）的启发，而其他则受到 JavaScript 之外的其他框架（如 Laravel、Flask 等）的启发。

我们将探索其中的四个，它们在写作时非常流行且维护良好。请注意，由于 Deno 和提到的包正在快速发展，这可能会随时间而变化。

重要提示

Craig Morten 写了一篇非常好的文章，对可用的库进行了非常彻底的分析和解构。如果你想了解更多，我强烈推荐这篇文章（[`dev.to/craigmorten/what-is-the-best-deno-web-framework-2k69`](https://dev.to/craigmorten/what-is-the-best-deno-web-framework-2k69)）。

我们将尝试在要探索的包方面保持多样性。有一些提供了比其他更抽象和结构化的内容，而有一些提供的不仅仅是简单的实用函数和可组合功能。

我们将要探索的包如下：

+   Drash

+   Servest

+   Oak

+   Alosaur

让我们逐一看看它们。

### Drash

Drash ([`github.com/drashland/deno-drash`](https://github.com/drashland/deno-drash)) 旨在与现有的 Deno 和 Node.js 框架不同。这一动机在其维护者 Edward Bebbington 的一篇博客文章中明确提到，他比较了 Drash 与其他替代方案，并解释了其创建的动机 ([`dev.to/drash_land/what-makes-drash-different-idd`](https://dev.to/drash_land/what-makes-drash-different-idd)).

这些动机很好，灵感来自于非常流行的软件工具如 Laravel、Flask 和 Tonic，这些决策大部分得到了证实。你一查看 Drash 的代码，就能发现一些相似之处。

与 Express.js 或 Koa 等库相比，它确实提供了一种不同的方法，正如文档所述：

“Deno 与 Node.js 的不同之处在于，Drash 旨在与 Express 或 Koa 不同，利用资源并采用完整的类式系统。”

主要区别在于，Drash 不想提供应用程序对象，让开发者可以注册他们的端点，像一些流行的 Node.js 框架那样。它将端点视为在类中定义的资源，与以下内容相似：

```js
import { Drash } from
  "https://deno.land/x/drash@v1.2.2/mod.ts";
class HomeResource extends Drash.Http.Resource {
  static paths = ["/"];
  public GET() {
    this.response.body = "Hello World!";
    return this.response;
  }
}
```

这些资源随后被插到 Drash 的应用程序中：

```js
const server = new Drash.Http.Server({
  response_output: "text/html",
  resources: [HomeResource]
});
server.run({
  hostname: "localhost",
  port: 1447
});
```

在这里，我们可以直接声明它实际上与我们在上面提到的其他框架不同。这些差异是有意的，旨在取悦喜欢这种方法并解决其他框架问题的开发者。这些用例在 Drash 的文档中解释得非常清楚。

Drash 基于资源的方法绝对值得关注。它从非常成熟的软件如 Flask 和 Tonic 得到的灵感确实为桌面带来了东西，并提出了一种解决方案，有助于解决无观点工具的常见问题。文档完整且易于理解，这使得在选择构建应用程序的工具时，它成为了一个很好的资产。

### Servest

Servest ([`servestjs.org/`](https://servestjs.org/)) 自称为适用于 Deno 的*“渐进式 HTTP 服务器”*。

它被创建的一个原因是因为其作者希望让标准库的 HTTP 模块中的一些 API 更容易使用，并实验新特性。后者是在需要稳定性的标准库中真正难以实现的事情。

Servest 直接关注与标准库的 HTTP 模块的比较。其项目主页上直接声明的一个主要目标，就是使其容易从标准库的 HTTP 模块迁移到 Servest。这很好地总结了 Servest 的愿景。

从 API 角度来看，Servest 与我们从 Express.js 和 Koa 熟悉的东西非常相似。它提供了一个应用程序对象，可以在其中注册路由。你也可以看到明显受到了标准库模块所提供内容的启发，正如我们在以下代码片段中所见：

```js
import { createApp } from
  "https://servestjs.org/@v1.1.4/mod.ts";
const app = createApp();
app.handle("/", async (req) => {
  await req.respond({
    status: 200,
    headers: new Headers({
      "content-type": "text/plain",
    }),
    body: "Hello, Servest!",
  });
});
app.listen({ port: 8899 });
```

我们可以识别出知名 Node.js 库中的应用对象和标准库中的请求对象，以及其他内容。

在此基础上，Servest 还提供了诸如直接渲染 JSX 页面、服务静态文件和认证等常见功能，文档也非常清晰，充满了示例。

Servest 试图利用 Node.js 用户的知识和熟悉度，同时利用 Deno 提供的好处，这是一个有希望的混合。其渐进性质为桌面带来了非常漂亮的功能，承诺会让开发者的生产力比使用标准库 HTTP 包时更高。

### Oak

Oak ([`oakserver.github.io/oak/`](https://oakserver.github.io/oak/)) 目前是创建 web 应用程序的最受欢迎的 Deno 库。它的名字来源于 Koa 的词语游戏，Koa 是一个非常流行的 Node.js 中间件框架和 Oak 的主要灵感来源。

由于其深受启发，其 API 使用异步函数和上下文对象与 Koa 相似并不令人意外。Oak 还包括一个路由器，也是受`@koa/router`启发的。

如果你熟悉 Koa，下面的代码可能看起来会很熟悉：

```js
import { Application } from
  "https://deno.land/x/oak/mod.ts";
const app = new Application();
app.use((ctx) => {
  ctx.response.body = "Hello world!";
});
await app.listen("127.0.0.1:8000");
```

对于那些不熟悉 Koa 的人来说，我们会简要地解释一下，因为理解它将帮助你理解 Oak。

Koa 通过使用现代 JavaScript 特性提供了一个最小化和无观点的方法。Koa 最初被创建（由创建 Express.js 的同一团队）的原因之一是，其创作者想要创建一个利用现代 JavaScript 特性的框架，而不是像 Express 那样，Express 是在 Node.js 的早期创建的。

团队想要使用诸如 promises 和 async/await 等新特性，然后解决开发者在使用 Express.JS 时面临的挑战。其中大多数挑战与错误处理、处理回调和某些 API 的不清晰有关。

Oak 的流行并非空穴来风，它在 GitHub 上的星级与其他选项的距离反映了这一点。单凭 GitHub 的星级并不能说明什么，但结合打开和关闭的问题、发布的版本等，我们可以看出人们为什么信任它。当然，这种熟悉度在的这个包的流行中起了很大的作用。

在其当前状态下，Oak 是一个构建 web 应用程序的固体（就 Deno 的社区标准而言），因为它提供了一组非常清晰和直接的功能。

### Alosaur

Alosaur ([`github.com/alosaur/alosaur`](https://github.com/alosaur/alosaur)) 是一个基于装饰器和类的 Deno web 应用程序框架。它在某种程度上与 Drash 相似，尽管最后的实现方式有所不同。

在其主要功能中，Alosaur 提供了诸如模板渲染、依赖注入和 OpenAPI 支持等功能。这些功能是在所有我们在这里介绍的替代方案的标准之上添加的，如中间件支持和路由。

这个框架的方法是使用类定义控制器，并使用装饰器定义其行为，如下面的代码所示：

```js
import { Controller, Get, Area, App } from
  'https://deno.land/x/alosaur@v0.21.1/mod.ts';
@Controller() // or specific path @Controller("/home")
export class HomeController {
    @Get() // or specific path @Get("/hello")
    text() {
        return 'Hello world';
    }
}
// Declare module
@Area({
    controllers: [HomeController],
})
export class HomeArea {}
// Create alosaur application
const app = new App({
    areas: [HomeArea],
});
app.listen();
```

在这里，我们可以看到应用程序的实例化与 Drash 有相似之处。它还使用 TypeScript 装饰器来声明框架的行为。

Alosaur 与前面提到的大多数库采取了不同的方法，主要原因在于它并不试图简约。相反，它提供了一组在构建某些类型的应用程序时证明有用的特性。

我们决定对其进行研究，不仅因为它能完成预期的工作，还因为它在 Node.js 和 Deno 领域拥有的一些不常见的特性。这包括诸如依赖注入和 OpenAPI 支持等功能，这是其他展示的解决方案所没有的。同时，它保留了诸如模板渲染等特性，这可能你们从 Express.JS 中熟悉，但在更现代的框架中就不那么熟悉了。

最终解决方案在提供的功能方面非常有前途且完整。这绝对是值得关注的东西，这样你就可以看到它是如何发展的。

## 结论

在审视了所有展示的解决方案并认识到它们都有优点之后，我们决定在本书的剩余部分使用 Oak。

这并不意味着本书将重点介绍 Oak。不会的，因为它只会处理 HTTP 和路由。Oak 的简约方法将与我们接下来要做的非常吻合，帮助我们逐步创建功能，而不会让它成为障碍。它还是 Deno 社区中最稳定、维护良好和最受欢迎的选项之一，这对我们的决定有明显的影响。

请注意，这个决定并不意味着我们将在接下来的几章中学到的内容不能在任何替代方案中完成。事实上，由于我们将如何组织和架构我们的代码，我们相信很容易就能跟上使用不同框架我们要做的绝大多数事情。

在本书的剩余部分，我们将使用其他第三方模块来帮助我们构建我们提出的功能。我们决定深入研究处理 HTTP 的库，原因是这是我们即将开发的应用程序的基本交付机制。

# 摘要

在本章中，我们终于开始构建一个利用我们对 Deno 知识的应用程序。我们首先考虑了构建应用程序时我们将拥有的主要目标及其架构。这些目标将为我们本书中关于架构和结构的多数对话定下基调，因为我们将会不断回顾它们，确保我们与它们保持一致。

我们首先创建了我们的文件结构，并试图实现我们第一个应用程序目标：拥有一个列出博物馆的 HTTP 端点。我们先构建了简单的业务逻辑，并在需要关注分离和职责隔离等需求时逐步推进。这些需求定义了我们的架构，证明了我们所创建的层和抽象的好处，并展示了它们所提供的价值。

通过明确责任和模块接口，我们理解到我们可以暂时使用内存数据库来构建我们的应用程序，这就是我们所做的。借助这种方法，我们能够构建出符合本章要求的应用程序，并且层次分离允许我们稍后回来，无需任何问题地将它更改为一个适当的持久层。在定义了业务和数据访问逻辑之后，我们使用标准库创建了一个 Web 服务器作为交付机制。在创建了一个非常简单的路由系统之后，我们插入了之前构建的业务逻辑，满足了本章的主要要求：拥有一个返回博物馆列表的应用程序。

我们在不创建业务逻辑、数据获取和交付层之间直接耦合的情况下做到了这一切。这是我们认为当我们开始添加复杂性、扩展我们的应用程序并向其添加测试时将非常有用的东西。

本章通过查看 Deno 社区目前存在的 HTTP 框架和库，并理解它们之间的差异和方法来结束。其中一些使用对 Node.js 用户熟悉的方法，而其他则深入使用 TypeScript 及其特性来创建更具结构的 Web 应用程序。通过查看四个目前可用的解决方案，我们了解到了社区正在开发的内容以及他们可能采取的方向。

我们最终选择了 Oak，这是一个非常最小化和相对成熟解决方案，以帮助我们解决在本书剩余部分遇到的路由和 HTTP 挑战。

在下一章中，我们将开始将 Oak 添加到我们的代码库中，并添加一些有用特性，如认证和授权，使用中间件等概念，并使我们的应用程序达到我们设定的目标。

让我们开始吧！


# 第五章：添加用户和迁移到 Oak

至此，我们已经为 Web 应用程序奠定了基础，其结构将使我们能够随着进展添加更多功能。正如您可能从本章的名称中猜到的那样，我们将从向当前 Web 应用程序中添加我们选择的的中间件框架开始本章，这个框架就是 Oak。

与 Oak 一起，由于我们的应用程序开始有更多的第三方依赖项，我们将使用前一章节中学到的知识来创建一个锁文件并在安装依赖项时执行完整性检查。这样，我们可以保证我们的应用程序在无依赖问题的情况下顺利运行。

随着本章的深入，我们将开始了解如何使用 Oak 的功能简化我们的代码。我们将使我们的路由逻辑更具可扩展性，同时也更具可伸缩性。我们最初的解决方案是使用`if`语句和标准库创建一个 DIY 路由解决方案，我们将在这里重构它。

完成这一步后，我们将得到更干净的代码，并能够使用 Oak 的功能，例如自动内容类型定义、处理不允许的方法和路由前缀。

然后，我们将添加一个在几乎每个应用程序中都非常重要的功能：用户。我们将创建一个与博物馆并列的模块来处理所有与用户相关的事情。在这个新模块中，我们将开发创建用户的业务逻辑，以及使用散列和盐等常见做法在数据库中创建新用户的代码。

在实现这些功能的过程中，我们将了解到 Deno 提供的其他模块，比如标准库的散列功能或包含在运行时中的加密 API。

新增这个模块并与应用程序的其他部分进行交互，将是一种很好的测试应用程序架构的方法。通过这样做，我们将了解它是如何保持相关上下文的一切在单一位置的同时进行扩展的。

本章将涵盖以下主题：

+   管理依赖项和锁文件

+   使用 Oak 编写 Web 服务器

+   向应用程序添加用户

+   让我们开始吧！

## 技术要求

本章将在前一章我们开发的代码基础上进行构建。本章的所有代码文件都可以在这本书的 GitHub 仓库中找到，网址为[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter05/sections`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter05/sections)。

# 管理依赖项和锁文件

在第二章《工具链》中，我们学习了 Deno 如何让我们进行依赖管理。在本节中，我们将使用它在一个更实用的上下文中。我们首先将我们代码中所有分散的带有 URL 的导入移除，并将它们移到集中式依赖文件中。此后，我们将创建一个锁定文件，以确保我们的尚处于初级阶段的应用程序在任何安装的地方都能顺利运行。最后，我们将学习如何根据锁定文件安装项目的依赖项。

## 使用集中式依赖文件

在上一章中，你可能注意到了我们直接在代码中使用 URL 来依赖项。尽管这是可能的，但我们在几章前就 discouraged 过这种做法。在我们第一个阶段，这种方法对我们有效，但随着应用程序开始增长，我们必须适当地管理我们的依赖项。我们希望避免与冲突的依赖版本、URL 中的拼写错误以及依赖项分散在各个文件中等问题作斗争。为了解决这个问题，我们必须做以下几步：

1.  在`src`目录的根目录创建一个`deps.ts`文件。

    这个文件可以有任何你喜欢的名字。我们目前称之为`deps.ts`，因为这是 Deno 文档中提到的，也是许多模块使用的命名约定。

1.  将所有外部依赖从我们的代码中移动到`deps.ts`。

    目前，我们唯一拥有的依赖项是标准库中的 HTTP 模块，可以在`src/web/index.ts`文件中找到。

1.  将导入移动到`deps.ts`文件中，并将`import`更改为`export`：

    ```js
    export { serve } from
      "https://deno.land/std@0.83.0/http/server.ts"
    ```

1.  注意固定版本是如何出现在 URL 上的：

    ```js
    export { serve } from
      "https://deno.land/std@0.83.0/http/server.ts"
    ```

    正如我们在第二章《工具链》中学到的，这是 Deno 中版本控制的工作方式。

    现在我们需要更改依赖文件，使它们直接从`deps.ts`导入，而不是直接从 URL 导入。

1.  在`src/web/index.ts`中，从`deps.ts`导入`serve`方法：

    ```js
    import { serve } from "../deps.ts";
    ```

通过拥有一个集中式依赖文件，我们也有了确保我们所有依赖项都本地下载的一种简单方式，而无需运行任何代码。有了这个，我们现在有了一个可以运行`deno cache`命令（在第二章《工具链》中提到）的单文件。

## 创建锁定文件

在将依赖项集中后，我们需要确保安装项目的人能够获得与我们相同的依赖项版本。这是确保代码以相同方式运行的唯一方式。我们将通过使用锁定文件来实现这一点。我们在第二章《工具链》中学习了如何做到这一点；在这里，我们将将其应用于我们的应用程序。

让我们运行带有`lock`和`lock-write`标志的`cache`命令，以及锁定文件的路径和集中式依赖文件`deps.ts`的路径：

```js
$ deno cache --lock=lock.json --lock-write src/deps.ts
```

在当前目录下应该会生成一个`lock.json`文件。如果你打开它，它应该包含一个 URL 的键值对，以及用于执行完整性检查的哈希。

这个锁文件应该然后添加到版本控制中。后来，如果一个同事想要安装这个同样的项目，他们只需要运行同样的命令，但不带`--lock-write`标志：

```js
$ deno cache --lock=lock.json src/deps.ts
```

这样一来，`src/deps.ts`中的所有依赖项（应该是全部依赖项）将被安装，并根据`lock.json`文件检查它们的完整性。

现在，每次我们在项目中安装一个新的依赖时，我们必须运行带有`lock`和`lock-write`标志的`deno` `cache`命令，以确保锁文件被更新。

这一节就到这里！

在这一节中，我们学习了一个确保应用程序运行顺畅的简单但非常重要的步骤。这帮助我们避免未来可能出现的诸如依赖冲突和版本间行为不匹配等复杂问题。我们还保证了资源完整性，这对于 Deno 来说尤为重要，因为它的依赖项是存储在 URL 中，而不是注册表中。

在下一节中，我们将从标准库 HTTP 服务器开始将我们的应用程序重构为 Oak，这将使我们的网络代码得到简化。

# 使用 Oak 编写网络服务器

在上一章的末尾，我们查看了不同的网络库。经过短暂的分析后，我们最终选择了 Oak。在本节中，我们将重写我们网络应用程序的一部分，以便我们可以使用它而不是标准库的 HTTP 模块。

让我们打开`src/web/index.ts`，并一步步开始处理它。

遵循 Oak 的文档([`deno.land/x/oak@v6.3.1`](https://deno.land/x/oak@v6.3.1))，我们唯一需要做的是实例化`Application`对象，定义一个中间件，并调用`listen`方法。让我们来这样做：

1.  在`deps.ts`文件中添加 Oak 的导入：

    ```js
    export { Application } from
      "https://deno.land/x/oak@v6.3.1/mod.ts"
    ```

    如果你使用的是 VSCode，那么你可能会注意到有一个警告，它说在当地找不到这个版本的依赖。

1.  让我们运行上一节中的命令来下载它并添加到锁文件中。

    不要忘记每次添加依赖时这样做，这样我们就有更好的自动完成，并且我们的锁文件总是更新的：

    ```js
    $ deno cache --lock=lock.json --reload --lock-write src/deps.ts
    Download https://deno.land/std@0.83.0/http/server.ts
    Download https://deno.land/x/oak@v6.3.1/mod.ts
    Download https://deno.land/std@0.83.0/encoding/utf8.ts
    …
    ```

    所有必要的依赖项都下载完成后，让我们开始在代码中使用它们。

1.  删除`src/web/index.ts`中`createServer`函数的所有代码。

1.  在`src/web/index.ts`内部，导入`Application`类并实例化它。创建一个非常简单的中间件（如文档中所述）并调用`listen`方法：

    ```js
    import { Application } from "../deps.ts";
    …
    export async function createServer({
      configuration: {
        port
      },
      museum
    }: CreateServerDependencies) {
      const app = new Application ();
      app.use((ctx) => {
        ctx.response.body = "Hello World!";
      });
      await app.listen({ port });
    }
    ```

请记住，在删除旧代码的同时，我们也删除了`console.log`，所以它现在还不会打印任何内容。让我们运行它并验证它是否有问题：

```js
$ deno run --allow-net src/index.ts  
```

现在，如果我们访问`http://localhost:8080`，我们将在那里看到“Hello World!”响应。

现在，您可能想知道 Oak 应用程序的`use`方法是什么。嗯，我们将使用这个方法来定义中间件。现在，我们只是想让它修改响应并在其主体中添加一条消息。在下一章，我们将深入学习中间件函数。

记得当我们移除了`console.log`，并且如果应用程序正在运行，我们就不会得到任何反馈吗？在我们学习如何向 Oak 应用程序添加事件监听器的同时，我们将学习如何做到这一点。

## 在 Oak 应用程序中添加事件监听器

到目前为止，我们已经设法让应用程序运行，但此刻，我们没有任何消息来确认这一点。我们将利用这一点来学习 Oak 中的事件监听器。

Oak 应用程序分发两种不同类型的事件。其中一个是`listen`，而另一个是`the listen event`，我们将用它来在应用程序运行时向控制台记录。另一个是`error`，我们将用它来在发生错误时向控制台记录。

首先，在我们调用`app.listen`语句之前，让我们添加一个`listen`事件的监听器：

```js
app.addEventListener("listen", e => {
  console.log(`Application running at 
    http://${e.hostname || 'localhost'}:${port}`)
})
…
await app.listen({ port });
```

请注意，我们不仅将消息打印到控制台，还打印出事件中的`hostname`并为其发送默认值，以防它未定义。

为了安全起见，并确保我们捕获任何意外错误，让我们也添加一个错误事件监听器。如果应用程序中发生了一个未处理的错误，将触发这个错误事件：

```js
app.addEventListener("error", e => {
  console.log('An error occurred', e.message);
})
```

这些处理程序，特别是`error`处理程序，将在我们开发时帮助我们很多，当我们想要快速了解发生了什么时。后来，当接近生产阶段时，我们将添加适当的中间件日志记录。

现在，您可能认为我们仍然缺少我们在本章开始时拥有的功能，您是对的：我们从我们的应用程序中移除了列出所有博物馆的端点。

让我们再次添加它，并学习如何在 Oak 应用程序中创建路由。

## 在 Oak 应用程序中处理路由

Oak 提供了另一个对象，与`Application`类一起使用，允许我们定义路由——`Router`类。我们将使用这个来重新实现我们之前的路由，该路由列出了应用程序中的所有博物馆。

让我们通过向构造函数发送前缀属性来创建它。这样做意味着那里定义的所有路由都将带有该路径的前缀：

```js
import { Application, Router } from "../deps.ts";
…
const apiRouter = new Router ({ prefix: "/api" })
```

现在，让我们恢复我们的功能，通过向`/api/museums`发送一个`GET`请求返回博物馆列表：

```js
apiRouter.get("/museums", async (ctx) => {
  ctx.response.body = {
    museums: await museum.getAll()
  }
});
```

这里发生了一些事情。

这里，我们使用 Oak 的路由 API 定义路由，通过发送一个 URL 和一个处理函数。然后，我们的处理程序用一个上下文对象（`ctx`）调用。所有这些都在 Oak 的文档中详细说明（[`doc.deno.land/https/deno.land/x/oak@v6.3.1/mod.ts#Router`](https://doc.deno.land/https/deno.land/x/oak@v6.3.0/mod.ts#Router)），但我留给您一个简短的总结。

在 Oak 中，所有处理程序能做的事情都是通过上下文对象完成的。发出的请求在`ctx.request`属性中可用，而当前请求的响应在`ctx.response`属性中可用。头信息、cookies、参数、正文等都在这些对象中可用。一些属性，如`ctx.response.body`，是可写的。

提示

您可以通过查看 Deno 的文档网站更好地了解 Oak 的功能：[`doc.deno.land/https/deno.land/x/oak@v6.3.1/mod.ts`](https://doc.deno.land/https/deno.land/x/oak@v6.3.0/mod.ts)。

在这种情况下，我们使用响应体属性来设置其内容。当 Oak 能够推断出响应的类型（这里是 JSON）时，它会自动在响应中添加正确的`Content-Type`头。

我们将在本书中了解更多关于 Oak 及其功能的内容。下一步是连接我们最近创建的路由器。

## 将路由器连接到应用程序

既然我们的路由器已经定义好了，我们需要在应用程序上注册它，这样它就可以开始处理请求了。

为此，我们将使用我们之前使用过的应用程序实例的方法——`use`方法。

在 Oak 中，一旦定义了一个`Router`（并将其注册），它提供了两个返回中间件函数的方法。这些函数可以用来在应用程序上注册路由。它们如下所示：

+   `routes`：在应用程序中注册已注册的路由处理程序。

+   `allowedMethods`：为在路由器中未定义的 API 调用注册自动处理程序，返回`405 – Not allowed`响应。

我们将使用它们来在我们的主应用程序中注册我们的路由器，如下所示：

```js
const apiRouter = new Router({ prefix: "/api" })
apiRouter.get("/museums", async (ctx) => {
  ctx.response.body = {
    museums: await museum.getAll()
  }
});
app.use(apiRouter.routes());
app.use(apiRouter.allowedMethods());
app.use((ctx) => {
  ctx.response.body = "Hello World!";
});
```

这样做后，我们的路由器在应用程序中注册了它的处理程序，它们准备好开始处理请求。

请记住，我们必须在之前定义的 Hello World 中间件之前注册这些。如果我们不这样做，Hello World 处理程序会在它们到达我们的路由器之前响应所有请求，因此它将无法工作。

现在，我们可以通过运行以下命令来运行我们的应用程序：

```js
$ deno run --allow-net src/index.ts
Application running at http://localhost:8080
```

然后，我们可以对 URL 执行一个`curl`命令：

```js
$ curl http://localhost:8080/api/museums
{"museums":[{"id":"1fbdd2a9-1b97-46e0-b450-62819e5772ff","name":"The Louvre","description":"The world's largest art museum and a historic monument in Paris, France.","location":{"lat":"48.860294","lng":"2.33862"}}]}
```

正如我们所看到的，一切都在按预期工作！我们已经成功将我们的应用程序迁移到了 Oak。

这样做后，我们大大提高了代码的可读性。我们还使用 Oak 处理了我们不想处理的事情，并且我们成功地专注于我们的应用程序。

在下一节中，我们将向应用程序添加用户概念。将创建更多的路由，以及一个全新的模块和一些处理用户的业务逻辑。

提示

本章的代码可以在[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter05/sections`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter05/sections)找到，按章节分隔。

现在，让我们向应用程序中添加一些用户！

# 向应用程序添加用户

我们目前已经有了一个端点在运行，列出了应用程序中的所有博物馆，但我们离最终要求还远着呢。

我们希望添加用户，以便可以注册、登录并以身份与应用程序交互。

我们将首先创建一个定义用户的对象，然后进入业务逻辑以创建并存储它。在此之后，我们将创建端点，以便我们能够通过 HTTP 与应用程序交互，从而允许用户注册。

## 创建用户模块

目前，我们可以称应用程序中有一个单一的“模块”：`museums`模块。从控制器到仓库、对象定义等，与博物馆相关的所有内容都在这里。这个模块有一个单一的接口，即它的`index.ts`文件。

我们这样做是为了在模块内部拥有工作的自由，同时保持其外部 API 的稳定性，以便它总是稳定的。这为我们模块之间提供了很好的解耦。为了确保模块内部的各个部分合理地解耦，我们还必须通过构造函数注入它们的依赖项，这允许我们轻松地交换部分并独立测试它们（如您将在第八章中看到的*测试 - 单元和集成*）。

遵循这些指南，我们将继续使用这个“模块”系统，并通过以下步骤为我们的用户创建一个模块：

1.  创建一个名为`src/users`的文件夹，并将`index.ts`文件放在里面。

1.  创建一个名为`src/users/types.ts`的文件。我们将在这里定义`User`类型：

    ```js
    export type User = {
      username: string,
      hash: string,
      salt: string,
      createdAt: Date
    } 
    ```

    我们的用户对象将非常简单：它将有一个`username`，一个`createdAt`日期，然后是`hash`和`salt`两个属性。我们将使用这些来保护存储时用户密码的安全。

1.  在`src/users/controller.ts`中创建一个名为`register`的用户控制器方法。它应该接收一个用户名和一个密码，然后在数据库中创建一个用户：

    ```js
    type RegisterPayload = 
      { username: string, password: string };
    export class Controller {
      public async register(payload: RegisterPayload) {
        // Logic to register users
      }
    }
    ```

1.  在`src/users/types.ts`中定义`RegisterPayload`，并在`src/users/index.ts`中导出它，从`src/users/controller.ts`中删除它。

    在`src/users/types.ts`中添加以下内容：

    ```js
    // src/users/types
    export type RegisterPayload = 
      { username: string; password: string };
    ```

    在`src/users/index.ts`中添加以下内容：

    ```js
    export type {
      RegisterPayload,
    } from "./types.ts";
    ```

    让我们现在停下来，思考一下注册逻辑。

    要创建用户，我们必须检查该用户是否存在于数据库中。如果不存在，我们将使用输入的用户名和密码创建他们，然后返回一个不包含敏感数据的对象。

    在上一章中，每次我们想要与数据源交互时，我们都使用了仓库模式。仓库保留了所有*数据访问*逻辑（`src/museums/repository.ts`）。

    在这里，我们将做同样的操作。我们已经注意到我们的控制器需要调用`UserRepository`中的两个方法：一个是为了检查用户是否存在，另一个是创建用户。这是我们接下来要定义的接口。

1.  前往`src/users/types.ts`并定义`UserRepository`接口：

    ```js
    export type CreateUser = 
      Pick<User, "username" | "hash" | "salt">;
    …
    export interface UserRepository {
      create: (user: CreateUser) => Promise<User>
      exists: (username: string) => Promise<boolean>
    }
    ```

    注意我们是如何创建一个包含`User`对象所有属性（除`createdAt`外）的`CreateUser`类型的。这个`createdAt`应该由仓库添加。

    定义了`UserRepository`接口后，我们就可以继续编写用户控制器，并确保它在构造函数中接收仓库的一个实例。

1.  在`src/users/controller.ts`中，创建一个`constructor`，它接收用户仓库作为注入参数，并使用相同名称设置类属性：

    ```js
    userRepository, we can start writing the logic for the register method.
    ```

1.  编写`register`方法的逻辑，检查用户是否存在，如果不存在则创建他们：

    ```js
    async register(payload: RegisterPayload) {
    create method of userRepository to make sure it follows the CreateUser type we defined previously. These will have to be automatically generated, but don't worry about that for now.And with this, we've pretty much finished looking at what will happen whenever someone tries to register with our application. We're still missing one thing, though. As you may have noticed, we're returning the `User` object directly from the repository, which might contain sensitive information, namely the `hash` and `salt` properties.
    ```

1.  在`src/users/types.ts`中创建一个名为`UserDto`的类型，定义了不包含敏感数据的`User`对象的格式：

    ```js
    export type User = {
      username: string,
      hash: string,
      salt: string,
      createdAt: Date
    }
    Pick to choose two properties from the User object; that is, createdAt and username.With `UserDto` ([`en.wikipedia.org/wiki/Data_transfer_object`](https://en.wikipedia.org/wiki/Data_transfer_object)) defined, we can now make sure our register is returning it. 
    ```

1.  在名为`src/users/adapter.ts`的文件中创建一个名为`userToUserDto`的函数，该函数将用户转换为`UserDto`：

    ```js
    import type { User, UserDto } from "./types.ts";
    export const userToUserDto = (user: User): UserDto => {
      return {
        username: user.username,
        createdAt: user.createdAt
      }
    }
    ```

1.  在注册方法中使用最近创建的函数，确保我们返回的是`UserDto`：

    ```js
    import { userToUserDto } from "./adapter.ts";
    …
    public async register(payload: RegisterPayload) {
      …
      const createdUser = await
        this.userRepository.create(
        payload.username,
        payload.password
      );
      return userToUserDto(createdUser);
    }
    ```

这样，`register`方法就完成了！

我们目前发送的哈希和盐是两个没有任何意义的明文字符串。

你可能想知道为什么我们不直接发送密码。这是因为我们想确保我们不会在任何数据库中以明文形式存储密码。

为了确保我们遵循最佳实践，我们将使用哈希和加盐的方法将用户的密码存储在数据库中。同时，我们还想学习一些 Deno API。我们将在下一节中进行这些操作。

## 在数据库中存储用户

即使我们使用的是内存数据库，我们决定不会以明文形式存储密码。相反，我们将使用一种常见的密码存储方法，称为哈希和加盐。如果你不熟悉这个方法，auth0 有一篇非常好的文章，我强烈推荐阅读([`auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/`](https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/)).

模式本身并不复杂，你只需要按照代码来学习它。

所以，我们所要做的就是以哈希形式存储我们的密码。我们不会存储用户输入的确切哈希密码，而是存储密码加上一个随机生成的字符串，称为盐。然后将这个盐与密码一起存储，以便稍后使用。之后，我们就不需要再次解码密码了。

有了盐，每次我们想要检查密码是否正确时，只需将盐添加到用户输入的任何密码中，对其进行哈希，并验证输出是否与数据库中存储的内容匹配。

如果这对你来说仍然很奇怪，我敢保证当你查看代码时它会变得简单得多。让我们按照这些步骤实现这些函数：

1.  在`src/users/util.ts`文件中创建一个名为`hashWithSalt`的函数，该函数使用提供的盐对字符串进行哈希：

    ```js
    import { createHash } from
      "https://deno.land/std@0.83.0/hash/mod.ts";
    export const hashWithSalt = 
      (password: string, salt: string) => {
        const hash = createHash("sha512")
          .update(`${password}${salt}`)
            .toString();
      return hash;
    };
    ```

    现在应该很清楚，这个函数将返回一个字符串，它是提供字符串的`hash`值加上一个`salt`。

    正如之前文章中提到的，被认为是最佳实践的是为不同的密码使用不同的盐。通过为每个密码生成不同的`salt`，即使一个密码的盐被泄露，我们也能确保所有的密码都是安全的。

    让我们通过创建一个生成`salt`的函数来继续。

1.  使用`crypto` API（[`doc.deno.land/builtin/stable#crypto`](https://doc.deno.land/builtin/stable#crypto)）创建一个`generateSalt`函数，以获取随机值并从那里生成盐字符串：

    ```js
    import { encodeToString } from
      "https://deno.land/std@0.83.0/encoding/hex.ts"
    …
    export const generateSalt = () => {
      const arr = new Uint8Array(64);
      crypto.getRandomValues(arr)
      return encodeToString(arr);
    }
    ```

    这就是我们为应用程序生成哈希密码所需的一切。

    现在，我们可以在我们的控制器中开始使用我们刚刚创建的实用函数。让我们创建一个方法，在那里我们可以哈希我们的密码。

1.  在`UserController`中创建一个名为`getHashedUser`的私有方法，它接收一个用户名和密码，并返回一个用户，以及他们的哈希值和盐：

    ```js
    import { generateSalt, hashWithSalt } from
      "./util.ts";
    …
    export class Controller implements UserController {
    … 
      private async getHashedUser
        (username: string, password: string) {
        const salt = generateSalt();
        const user = {
          username,
          hash: hashWithSalt(password, salt),
          salt
        }
        return user;
      }
    …
    ```

1.  在`register`方法中使用最近创建的`getHashedUser`方法：

    ```js
    public async register(payload: RegisterPayload) {
      if (await
        this.userRepository.exists(payload.username)) {
        return Promise.reject("Username already exists");
      }
      const createdUser = await
        this.userRepository.create(
        await this.getHashedUser
          (payload.username, payload.password)
      );
      return userToDto(createdUser);
    }
    ```

大功告成！这样一来，我们确保我们没有存储任何明文密码。在路径中，我们学习了 Deno 中可用的`crypto` API。

我们所有的实现都是在使用我们之前定义的`UserRepository`接口。然而，目前我们还没有一个实现它的类，所以让我们创建一个。

## 创建用户仓库

在前一部分，我们创建了定义`UserRepository`的接口，所以接下来，我们要创建一个实现它的类。让我们开始吧：

1.  创建一个名为`src/users/repository.ts`的文件，其中有一个导出的`Repository`类：

    ```js
    import type { CreateUser, User, UserRepository } from
      "./types.ts";
    export class Repository implements UserRepository {
      async create(user: CreateUser) {
      }
      async exists(username: string) {
      }
    }
    ```

    接口保证这两个公共方法必须存在。

    现在，我们需要一种存储用户的方法。为了本章的目的，我们再次使用内存数据库，这与我们之前的博物馆做法非常相似。

1.  在`src/users/repository.ts`类中创建一个名为`storage`的属性。它应该是一个 JavaScript Map，将作为用户数据库使用：

    ```js
    import { User, UserRepository } from "./types.ts";
    export class Repository implements UserRepository {
      private storage = new Map<User["username"], User>();
    …
    ```

    有了数据库，我们现在可以实现这两个方法的逻辑。

1.  在`exists`方法中从数据库获取用户，如果存在则返回`true`，否则返回`false`：

    ```js
    async exists(username: string) {
      return Boolean(this.storage.get(username));
    }
    ```

    `Map#get`函数如果无法获取记录，则返回 undefined，所以我们将它转换为 Boolean，以确保它总是返回 true 或 false。

    `exists`方法相当简单；它只需要检查用户是否存在于数据库中，相应地返回一个`boolean`。

    创建用户时，我们需要比那多做一到两个步骤。不仅仅是创建，我们还需要确保调用此函数的人还向用户发送了`createdAt`日期。

    现在，让我们回到我们的主要任务：在数据库中创建用户。

1.  打开`src/users/repository.ts`文件，实现`create`方法，以正确的格式创建一个`user`对象。

    记得向发送给函数的`user`对象中添加`createdDate`：

    ```js
    async create(user: CreateUser) {
      const userWithCreatedAt = 
        { ...user, createdAt: new Date() }
      this.storage.set
       (user.username, { ...userWithCreatedAt });
      return userWithCreatedAt;
    } 
    ```

    这样一来，我们的仓库就完成了！

    它完全实现了我们之前在`UserRepository`接口中定义的内容，并已准备好使用。

    下一步是把这些碎片串起来。我们已经创建了`User`控制器和`User`仓库，但它们目前还没有在任何地方被使用。

    在我们继续之前，我们需要将用户模块中的这些对象暴露给外部世界。我们将遵循我们之前定义的规则；也就是说，模块的接口将始终是其根目录下的`index.ts`文件。

1.  打开`src/users/index.ts`，并从模块中导出`Controller`，`Repository`类及其相应的类型：

    ```js
    export { Repository } from './repository.ts';
    export { Controller } from './controller.ts';

    export type {
      CreateUser,
      RegisterPayload,
      User,
      UserController,
      UserRepository,
    } from "./types.ts"; 
    ```

    现在，我们可以确保用户模块中的每个文件都是直接从这个文件（`src/users/index.ts`）导入类型，而不是直接导入其他文件。

现在，任何想要从用户模块导入内容的模块都必须通过`index.ts`文件进行导入。现在，我们可以开始考虑用户如何与刚刚编写的业务逻辑互动。由于我们正在构建一个 API，下一节我们将学习如何通过 HTTP 暴露它。

## 创建注册端点

业务逻辑和数据访问逻辑准备就绪，唯一缺少的是用户可以调用以注册自己的端点。

对于注册请求，我们将实现一个`POST /api/users/register`接口，预期是一个包含名为`user`的属性，该属性包含`username`和`password`两个属性的 JSON 对象。

我们首先必须做的是声明`src/web/index.ts`中的`createServer`函数将依赖于`UserController`接口被注入。让我们开始吧：

1.  在`src/users/types.ts`中创建`UserController`接口。确保它也导出在`src/users/index.ts`中：

    ```js
    RegisterPayload from src/users/controller.ts previously.
    ```

1.  现在，为了保持整洁，前往`src/users/controller.ts`，确保类实现了`UserController`：

    ```js
    import { RegisterPayload, UserController,
      UserRepository } from "./types.ts";
    export class Controller implements UserController
    ```

1.  回到`src/web/index.ts`，将`UserController`添加到`createServer`依赖项中：

    ```js
    import { UserController } from "../users/index.ts";
    interface CreateServerDependencies {
      configuration: {
        port: number
      },
      museum: MuseumController,
      user: UserController
    }
    export async function createServer({
      configuration: {
        port
      },
      museum,
      user
    }: CreateServerDependencies) {
    …
    ```

    我们现在准备好创建我们的注册处理器。

1.  创建一个处理器，响应`/api/users/register`的`POST`请求，并使用注入的控制器的`register`方法创建用户：

    ```js
    apiRouter.post method to define a route that accepts a POST request. Then, we're using the body method from the request (https://doc.deno.land/https/deno.land/x/oak@v6.3.1/mod.ts#ServerRequest) to get its output in JSON. We then do a simple validation to check if the username and password are present in the request body, and at the bottom, we use the injected register method from the controller. We're wrapping it in a try catch so that we can return HTTP status code 400 if an error happens.
    ```

这应该足以使 Web 层能够完美地回答我们的请求。现在，我们只需要连接所有东西在一起。

## 将用户控制器与 Web 层连接

我们已经创建了应用程序的基本部分。有业务逻辑，有数据访问逻辑，有 Web 服务器来处理请求。唯一缺少的是将它们连接在一起的东西。在本节中，我们将实例化我们定义的接口的实际实现，并将它们注入到期望它们的内容中。

回到`src/index.ts`。让我们做与`museums`模块类似的事情。在这里，我们将导入用户仓库和控制器，实例化它们，并将控制器发送到`createServer`函数。

按照以下步骤进行操作：

1.  在`src/index.ts`中，从用户模块导入`Controller`和`Repository`，并在实例化它们时发送必要的依赖项：

    ```js
    import {
      Controller as UserController,
      Repository as UserRepository,
       } from './users/index.ts';
    …
    const userRepository = new UserRepository();
    const userController = new UserController({
      userRepository });
    ```

1.  将用户控制器发送到`createServer`函数中：

    ```js
    createServer({
      configuration: { port: 8080 },
      museum: museumController,
      user: userController
    })
    ```

好了，到这里我们就算是完成了！为了结束这一节，让我们通过运行以下命令来运行我们的应用程序：

```js
$ deno run --allow-net src/index.ts
Application running at http://localhost:8080
```

现在，让我们用`curl`向`/api/users/register`发送请求来测试注册端点：

```js
$ curl -X POST -d '{"username": "alexandrempsantos", "password": "testpw" }' -H 'Content-Type: application/json' http://localhost:8080/api/users/register
{"user":{"username":"alexandrempsantos","createdAt":"2020-10-06T21:56:54.718Z"}}
```

正如我们所看到的，它正在运行并返回`UserDto`的内容。我们这一章的主要目标已经实现：我们创建了用户模块并在其中添加了一个注册用户的端点！

# 总结

在这一章中，我们的应用程序经历了巨大的变化！

我们首先将我们的应用程序从标准库 HTTP 模块迁移到 Oak。我们不仅迁移了服务应用程序的逻辑，而且还开始使用 Oak 的路由器定义一些路线。我们注意到，随着 Oak 封装了以前需要手动完成的任务，应用程序逻辑开始变得简单。我们成功地将标准库中的所有 HTTP 代码迁移过来，而没有改变业务逻辑，这是一个非常好的迹象，表明我们在应用程序架构方面做得很好。

我们继续前进，并学会了如何在 Oak 应用程序中监听和处理事件。随着我们开始编写更多的代码，我们也对 Oak 变得更加熟悉，理解其功能，探索其文档，并对其进行实验。

用户是任何应用程序的重要组成部分，带着这样的想法，我们把这一章的大部分时间都花在了他们身上。我们不仅在应用程序中添加了用户，还把它作为一个独立的、自包含的模块添加了进来，与博物馆并列。

一旦我们在应用程序中开发了注册用户的业务逻辑，为它添加一个持久层就变得迫切了。这意味着我们必须开发一个用户存储库，负责在数据库中创建用户。在这里，我们深入实现了一个散列和盐机制，以在数据库上安全地存储用户的密码，并在过程中学习了一些 Deno API。

用户业务逻辑完成后，我们转向了缺失的部分：HTTP 端点。我们在 HTTP 路由器中添加了注册路线，并在 Oak 的帮助下完成了所有设置。

最后，我们使用依赖注入再次连接了所有内容。由于我们所有模块的依赖都是基于接口的，我们很容易注入所需的依赖并使我们的代码工作。

这一章是我们使应用程序更具可扩展性和可读性的旅程。我们首先移除了我们的 DIY 路由器代码并将其移动到 Oak，并以添加一个重要的大*业务*实体——用户结束。后者也作为我们架构的测试，并展示了它如何随着不同的业务领域而扩展。

在下一章中，我们将通过添加一些有趣的功能来不断迭代应用程序。这样做，我们将完成在这里创建的功能，例如用户登录、授权以及在真实数据库中的持久化。我们还将处理包括基本日志记录和错误处理在内的常见 API 实践。

兴奋吗？我们也是——开始吧！


# 第六章：添加认证并连接到数据库

在上一章中，我们在应用程序中添加了一个 HTTP 框架，极大地简化了我们的代码。之后，我们在应用程序中添加了用户的概念，并开发了注册端点。目前为止，我们的应用程序已经存储了一些东西，唯一的缺点是它存储在内存中。我们将在本章解决这个问题。

在实现 oak（HTTP 框架的选择）时，我们使用的另一个概念是中间件函数。我们将从学习中间件函数是什么以及为什么它们几乎是所有 Node.js 和 Deno 框架中代码重用的*标准*开始本章。

然后我们将使用中间件函数并实现登录和授权。除此之外，我们还将学习如何使用中间件添加诸如请求日志和计时等标准功能到应用程序中。

随着我们的应用程序在需求方面几乎完成，我们将用剩余的时间学习如何连接到一个真正的持久化引擎。在这本书中，我们将使用 MongoDB。我们将使用之前构建的抽象确保过渡顺利。然后我们将创建一个新的用户存储库，以便它可以像我们使用内存解决方案一样连接到数据库。

到本章结束时，我们将拥有一个完整的应用程序，支持注册和用户登录。登录后，用户还可以获取博物馆列表。所有这些都是通过 HTTP 和持久化实现的业务逻辑完成的。

在本章之后，我们将只回来添加测试并部署应用程序，从而完成构建应用程序的完整周期。

在本章中，我们将涵盖以下主题：

+   使用中间件函数

+   添加认证

+   使用 JWT 添加授权

+   连接 MongoDB

让我们开始吧！

## 技术要求

本章所需的代码可在以下 GitHub 链接中找到：[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06)。

# 使用中间件函数

如果您使用过任何 HTTP 框架，无论是 JavaScript 还是其他框架，您可能都熟悉中间件函数的概念。如果您不熟悉，也没关系——这就是我们将在本节解释的内容。

让我们从 Express.js 文档中借用的一个定义开始：[`expressjs.com/en/guide/writing-middleware.html`](http://expressjs.com/en/guide/writing-middleware.html)

“中间件函数是具有访问请求对象(req)、响应对象(res)以及应用程序请求-响应周期中下一个中间件函数的函数。下一个中间件函数通常由一个名为 next 的变量表示。”

中间件函数拦截请求并具有对它们进行操作的能力。它们可以在许多不同的用例中使用，如下所示：

+   更改请求和响应对象

+   结束请求-响应生命周期（回答请求或跳过其他处理程序）

+   调用下一个中间件函数

中间件函数通常用于诸如检查认证令牌、根据结果自动响应、记录请求、向请求中添加特定头、用上下文丰富请求对象和错误处理等任务。

我们将在应用程序中实现一些这些示例。

## 中间件是如何工作的？

中间件作为堆栈处理，每个函数都可以通过运行代码在堆栈执行前后控制响应流程。

在 oak 框架中，中间件函数是通过`use`函数进行注册的。这个时候，你可能还记得我们之前是如何使用 oak 的路由器的。oak 的`Router`对象所做的就是为注册的路由创建处理程序，并导出带有这种行为的中间件函数，以便在主应用程序上注册。这些被称为`routes`和`allowedMethods` ([`github.com/PacktPublishing/Deno-Web-Development/blob/43b7f7a40157212a3afbca5ba0ae20f862db38c4/ch5/sections/2-2-handling-routes-in-an-oak-application/museums-api/src/web/index.ts#L38`](https://github.com/PacktPublishing/Deno-Web-Development/blob/43b7f7a40157212a3afbca5ba0ae20f862db38c4/ch5/sections/2-2-handling-routes-in-an-oak-application/museums-api/src/web/index.ts#L38)).

为了更好地理解中间件函数，我们将实现它们中的几个。我们将在下一节中这样做。

## 通过中间件添加请求计时

让我们在请求中添加一些基本日志记录。oak 中间件函数（[`github.com/oakserver/oak#application-middleware-and-context`](https://github.com/oakserver/oak#application-middleware-and-context)）接收两个参数。第一个是上下文对象，这是所有路由都得到的一个对象，而第二个是`next`函数。这个函数可以用来执行堆栈中的其他中间件，允许我们控制应用程序流程。

我们首先要添加一个中间件，为响应添加`X-Response-Time`头。按照以下步骤操作：

1.  打开`src/web/index.ts`，并注册一个通过调用`next`执行剩余堆栈的中间件。

    这为响应添加了一个头，其值为从请求开始到处理完毕的毫秒差：

    ```js
    const app = new Application();
    .use calls; this way, all the other middleware functions will run once this has been executed.The first lines are executed before the route handler (and other middleware functions) starts handling the request. Then, the call to `next` makes sure the route handlers execute; only then is the rest of the middleware code executed, thus calculating the difference from the initial value and the current date and adding it as a header.
    ```

1.  执行以下代码以启动服务器：

    ```js
    $ deno run --allow-net src/index.ts
    Application running at http://localhost:8080
    ```

1.  发起一个请求，并检查是否有了所需的头：

    ```js
    x-response-time header there. Note that we've used the -i flag so that we're able to see the response headers on curl. 
    ```

有了这个，我们首次完全理解后使用了中间件函数。我们用它们来控制应用程序的流程，通过使用`next`，并为请求添加了一个头。

接下来，我们将对刚刚创建的中间件进行组合并添加逻辑，以记录向服务器发起的请求。

## 通过中间件添加请求日志

现在我们已经构建了计算请求时间的逻辑，我们处于向应用程序添加请求日志的好位置。

最终目标是让每个向应用程序发起的请求都记录在控制台上，包括其路径、HTTP 方法和响应时间；像以下示例一样：

```js
GET http://localhost:8080/api/museums - 65ms
```

当然，我们也可以每个请求分别处理，但由于这是一件需要跨应用程序做的事情，我们将把它作为中间件添加到`Application`对象中。

我们在上一节编写的 middleware 要求处理程序（以及中间件函数）运行，以便添加响应时间（它在执行部分逻辑之前调用 next 函数）。我们需要在之前注册当前的日志中间件，它将请求时间添加到请求中。让我们开始：

1.  打开`src/web/index.ts`并在控制台上添加记录请求方法、路径和时间戳的代码：

    ```js
    X-Response-Time header, which is going to be set by the previous middleware to log the request to the console. We're also using next to make sure all the handlers (and middleware functions) run before we log to the console. We need this specifically because the header is set by another piece of middleware.
    ```

1.  执行以下代码以启动服务器：

    ```js
    $ deno run --allow-net src/index.ts
    Application running at http://localhost:8080
    ```

1.  对端点执行请求：

    ```js
    $ curl http://localhost:8080/api/museums
    ```

1.  检查服务器进程是否将请求记录到控制台：

    ```js
    $ deno run --allow-net src/index.ts
    Application running at http://localhost:8080
    GET http://localhost:8080/api/museums - 46ms
    ```

这样一来，我们的中间件函数就可以协同工作了！

在这里，我们在主要的应用程序对象上注册了中间件函数。然而，也可以通过调用相同的`use`方法在特定的 oak 路由上执行此操作。

为了给您一个例子，我们将注册一个只会在`/api`路由来执行的中间件。我们将做与之前完全相同的事情，但这次调用的是 API`Router`对象的`use`方法，如下例所示：

```js
const apiRouter = new Router({ prefix: "/api" })
apiRouter.use(async (_, next) => {
  console.log("Request was made to API Router");
  await next();
}))
…
app.use(apiRouter.routes());
app.use(apiRouter.allowedMethods());
```

想要应用程序流程正常进行的中间件函数*必须调用*`next`函数。如果这种情况没有发生，堆栈中的其余中间件和路由处理程序将不会被执行，因此请求将无法得到响应。

使用中间件函数的另一种方法是将它们直接添加到请求处理程序之前。

假设我们想要创建一个添加`X-Test`头的中间件。我们可以在应用程序对象上编写该中间件，或者我们可以在路由本身上直接使用它，如下代码所示：

```js
import { Application, Router, RouterMiddleware } from
  "../deps.ts";
…
const addTestHeaderMiddleware: RouterMiddleware = async (ctx,
   next) => {
  ctx.response.headers.set("X-Test", "true");
  await next();
}
apiRouter.get("/museums", addTestHeaderMiddleware, async (ctx)
  => {
  ctx.response.body = {
    museums: await museum.getAll()
  }
});
```

为了让之前的代码运行，我们需要在`src/deps.ts`中导出`RouterMiddleware`类型：

```js
export type { RouterMiddleware } from
  "https://deno.land/x/oak@v6.3.1/mod.ts";
```

使用这个中间件，无论何时我们想要添加`X-Test`头，只需要在路由处理程序之前包含`addTestHeaderMiddleware`。它会在处理程序代码之前执行。这不仅仅适用于一个中间件，因为可以注册多个中间件函数。

中间件函数就到这里结束！

我们已经学习了使用这种非常常见的 web 框架特性来创建和共享功能的基本知识。在我们进入下一部分时，我们将继续使用它们，在那里我们将处理认证、验证令牌和授权用户。

让我们来实现我们应用程序的认证！

# 添加认证

在上一章中，我们向应用程序添加了创建新用户的功能。这个功能本身很酷，但如果我们不能用它来进行认证，那么它就值不了多少。这就是我们在这里要做的。

我们先来创建检查用户名和密码组合是否正确的逻辑，然后实现一个端点来完成这个任务。

之后，我们将通过从登录端点返回令牌来过渡到授权主题，然后使用该令牌来检查用户是否已认证。

让我们一步一步来，从业务逻辑和持久性层开始。

## 创建登录业务逻辑

我们的一种实践是，在编写新功能时，首先从业务逻辑开始。我们认为这是直观的，因为你首先考虑“业务”和用户，然后才进入技术细节。这就是我们要在这里做的。

我们首先在`UserController`中添加登录逻辑：

1.  在开始之前，让我们在`src/users/types.ts`中为`UserController`接口添加`login`方法：

    ```js
    export type RegisterPayload = { username: string;
      password: string };
    export type LoginPayload = { username: string; password:
      string };
    export interface UserController {
      register: (payload: RegisterPayload) =>
        Promise<UserDto>;
      login: (
        { username, password }: LoginPayload,
      ) => Promise<{ user: UserDto }>;
    }
    ```

1.  在控制器上声明`login`方法；它应该接收一个用户名和密码：

    ```js
    public async login(payload: LoginPayload) {
    }
    ```

    让我们停下来思考一下登录流程应该是什么样子：

    +   用户发送他们的用户名和密码。

    +   应用程序通过用户名从数据库中获取用户。

    +   应用程序使用数据库中的盐对用户发送的密码进行编码。

    +   应用程序比较两个加盐密码。

    +   应用程序返回一个用户和一个令牌。

        现在我们不担心令牌。然而，流程的其余部分应该为当前部分设置要求，帮助我们思考`login`方法的代码。

        单从这些要求来看，我们就可以理解我们需要在`UserRepository`上有一个通过用户名获取用户的方法。让我们来看看这个。

1.  在`src/users/types.ts`中，向`UserRepository`添加一个`getByUsername`方法；它应该通过用户名从数据库中获取用户：

    ```js
    export interface UserRepository {
      create: (user: CreateUser) => Promise<User>;  
      exists: (username: string) => Promise<boolean>
      getByUsername: (username: string) => Promise<User>
    }
    ```

1.  在`src/users/repository.ts`中实现`getByUsername`方法：

    ```js
    export class Repository implements UserRepository {
    …
    UserController and use the recently created method to get a user from the database.
    ```

1.  在`UserController`的`login`方法内部使用来自仓库的`getByUsername`方法：

    ```js
    public async login(payload: LoginPayload) {
      hashPassword in the previous chapter when we implemented the register logic, so let's use that.
    ```

1.  在`UserController`内部创建一个`comparePassword`方法。

    它应该接收一个密码和一个`user`对象。然后，它应该将用户发送的密码一旦被加盐和哈希与数据库中存储的密码进行比较：

    ```js
    import {
      LoginPayload,
      RegisterPayload,
      User,
      UserController,
      UserRepository,
    } from "./types.ts";
    import { hashWithSalt } from "./util.ts"
    …
    private async comparePassword(password: string, user:
      User) {
      const hashedPassword = hashWithSalt (password,
        user.salt);
      if (hashedPassword === user.hash) {
        return Promise.resolve(true);
      }
      return Promise.reject(false);
    }
    ```

1.  在`UserController`的`login`方法上使用`comparePassword`方法：

    ```js
    public async login(payload: LoginPayload) {
      try {
        const user = await
         this.userRepository.getByUsername(payload.username);
        await this.comparePassword(payload.password, user);
        return { user: userToUserDto(user) };
      } catch (e) {
        console.log(e);
        throw new Error('Username and password combination is
          not correct')
      }
    }
    ```

有了这个，我们就有了`login`方法的工作！

它接收一个用户名和一个密码，通过用户名获取用户，比较哈希密码，如果一切按计划进行，则返回用户。

现在我们应该准备好实现登录端点——一个将使用我们刚刚创建的登录方法。

## 创建登录端点

既然我们已经创建了业务逻辑和数据获取逻辑，我们就可以开始在我们的网络层中使用它。让我们创建一个`POST /api/login`路由，该路由应该允许用户使用他们的用户名和密码登录。按照以下步骤操作：

1.  在`src/web/index.ts`中创建登录路由：

    ```js
    apiRouter.post("/login", async (ctx) => {
    })
    ```

1.  使用`request.body`函数获取请求体（[`doc.deno.land/https/raw.githubusercontent.com/oakserver/oak/main/request.ts#Request`](https://doc.deno.land/https/raw.githubusercontent.com/oakserver/oak/main/request.ts#Request))，然后将用户名和密码发送到`login`方法：

    ```js
    apiRouter.post("/login", async (ctx) => {
      400 Bad Request) if things didn't go well.
    ```

1.  如果登录成功，它应该返回我们的`user`：

    ```js
    …
    const { user: loginUser } = await user.login({ username,
      password });
    ctx.response.body = { user: loginUser };
    ctx.response.status = 201;
    …
    ```

    有了这些，我们应该拥有登录用户所需的一切！让我们试一试。

1.  运行应用程序，通过运行以下命令：

    ```js
    $ deno run --allow-net src/index.ts
    Application running at http://localhost:8080
    ```

1.  向`/api/users/register`发送请求以注册用户，然后尝试使用创建的用户登录到`/api/login`：

    ```js
    $ curl -X POST -d '{"username": "asantos00", "password": "testpw" }' -H 'Content-Type: application/json' http://localhost:8080/api/users/register
    {"user":{"username":"asantos00","createdAt":"2020-10-19T21:30:51.012Z"}}
    ```

1.  现在，尝试使用创建的用户登录：

    ```js
    $ curl -X POST -d '{"username": "asantos00", "password": "testpw" }' -H 'Content-Type: application/json' http://localhost:8080/api/login 
    {"user":{"username":"asantos00","createdAt":"2020-10-19T21:30:51.012Z"}}
    ```

而且它有效！我们在注册表上创建用户，并能够在之后使用他们登录。

在本节中，我们学习了如何向我们的应用程序添加认证逻辑，并实现了`login`方法，该方法允许用户使用注册的用户登录。

在下一节中，我们将学习如何使用我们创建的认证来获取一个令牌，该令牌将允许我们处理授权。我们将使博物馆路线只对认证用户可用，而不是公开可用。为此，我们需要开发授权功能。让我们深入了解一下！

# 使用 JWT 添加授权

现在，我们有一个允许我们登录并返回已登录用户的应用程序。然而，如果我们想要在 API 中使用登录，我们必须创建一个授权机制。这个机制应该启用 API 的用户进行认证，获取一个令牌，并使用这个令牌来标识自己并访问资源。

我们这样做是因为我们希望关闭应用程序的某些路由，使它们只对认证用户可用。

我们将开发所需内容，通过使用**JSON Web Tokens**（**JWT**），这是一种在 API 中相当标准的认证方式。

如果你不熟悉 JWT，我将留下一个来自[jwt.io](http://jwt.io)的解释：

"JSON Web Tokens 是一种开放、行业标准的 RFC 7519 方法，用于在两个方之间安全地表示声明。"

它主要用于当你希望你的客户端连接到一个认证服务，然后提供你的服务器验证该认证是否由一个你信任的服务发出。

为了避免重复[jwt.io](http://jwt.io)已经很好地解释过的风险，我将给你一个链接，完美地解释了这个标准是什么：`[`jwt.io/introduction/`](https://jwt.io/introduction/)`。确保阅读它；我相信你们都有足够的知识来理解我们接下来如何使用它。

在本节中，由于本书的范围，我们将不会实现生成和验证 JWT 令牌的全部逻辑。这段代码可以在本书的 GitHub 仓库中找到([`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06/jwt-auth`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06/jwt-auth))。

我们将要在这里做的是将我们当前的应用程序与一个具有生成和验证 JWT 令牌功能的模块集成，这对我们的应用程序至关重要。然后，我们使用该令牌来决定是否允许用户访问博物馆路线。

让我们开始吧！

## 从登录返回令牌

在前一节中，我们实现了登录功能。我们开发了一些逻辑来验证用户名和密码的组合，如果成功就返回用户。

为了授权一个用户并让他们访问私有资源，我们需要知道认证的用户是谁。一个常见的做法是通过令牌来实现。我们有各种方法可以做到这一点。它们包括基本 HTTP 认证、会话令牌、JWT 令牌等替代方案。我们选择 JWT，因为我们认为它是业界广泛使用的解决方案，你们可能会在工作中遇到。如果你们没有遇到过，也不要担心；它是足够简单的。

我们需要做的第一件事是在用户登录时向用户返回令牌。我们的`UserController`将不得不在与`userDto`结合时返回该令牌。

在提供的`jwt-auth`模块中([`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06/jwt-auth`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06/jwt-auth)),你可以检查我们导出了一个仓库。

如果我们访问文档，使用 Deno 的文档网站在[`doc.deno.land/https/raw.githubusercontent.com/PacktPublishing/Deno-Web-Development/master/Chapter06/jwt-auth/repository.ts`](https://doc.deno.land/https/raw.githubusercontent.com/PacktPublishing/Deno-Web-Development/master/Chapter06/jwt-auth/repository.ts)，我们可以看到它导出了两个方法：`getToken`和`generateToken`。

阅读方法的文档，我们可以理解，一个为用户 ID 获取令牌，另一个生成新令牌。

让我们使用这个方法，按照以下步骤在我们的登录用例中生成新令牌：

1.  首先，在`src/users/types.ts`中的`UserController`返回类型中添加令牌：

    ```js
    export interface UserController {
      register: (payload: RegisterPayload) =>
        Promise<UserDto>
      login: ({ username, password }: LoginPayload) =>
        Promise<{ user: UserDto, UserController knows how to return a token. Looking at its logic, we can see that it should be able to delegate that responsibility by calling a method that will return that token. From the previous chapters, we know that we don't want to import our dependencies directly; we'd rather have them injected into our `constructor`. That's what we'll do here. Another thing we know is that we want to use this "third-party module" that deals with authentication. We'll need to add it to our dependencies file.
    ```

1.  前往`src/deps.ts`，为`jwt-auth`模块添加导出，运行`deno cache`以更新锁文件并下载依赖项：

    ```js
    export type {
      Algorithm,
    } from "https://raw.githubusercontent.com/PacktPublishing/
     Deno-Web-Development/master/Chapter06/jwt-auth/mod.ts";
    export {
      Repository as AuthRepository,
    } from "https://raw.githubusercontent.com/PacktPublishing/
      Deno-Web-Development/master/Chapter06/jwt-auth/mod.ts";
    ```

1.  使用`AuthRepository`类型定义`UserController`构造函数的依赖项：

    ```js
    authRepository, which we've just imported. We previously discovered that it exposes a generateToken method, which will be of use to the login of UserController.
    ```

1.  打开`src/users/controller.ts`中的登录方法，并使用`authRepository`中的`generateToken`方法来获取令牌并返回它：

    ```js
    public async login(payload: LoginPayload) {
        try {
          const user = await
            this.userRepository.getByUsername
              (payload.username);
          await this.comparePassword(payload.password, user);
    authRepository to get a token. If we try to run this code, we know it will fail. In fact, we just need to open `src/index.ts` to see our editor's warnings. It is complaining that we're not sending `authRepository` to `UserController`, and we should.
    ```

1.  回到`src/index.ts`，从`jwt-auth`实例化`AuthRepository`：

    ```js
    import { AuthRepository } from "./deps.ts";
    …
    const authRepository = new AuthRepository({
      configuration: {
        algorithm: "HS512",
        key: "my-insecure-key",
        tokenExpirationInSeconds: 120
      }
    });
    ```

    你也可以通过模块的文档来检查，因为它需要一个带有三个属性的`configuration`对象发送，即`algorithm`、`key`和`tokenExpirationInSeconds`。

    `key`应该是一个秘密值，用于创建和验证 JWT，`algorithm`是令牌将编码的加密算法（支持 HS256、HS512 和 RS256），`tokenExpirationInSeconds`是令牌过期的时间。

    关于我们刚刚提到的`key`变量等不应存在于代码中的秘密值，我们将在下一章学习如何处理它们，那里我们将讨论应用程序配置。

    我们现在有一个`AuthRepository`的实例！我们应该能够将其发送到我们的`UserController`并使其工作。

1.  在`src/index.ts`中，将`authController`发送到`UserController`构造函数中：

    ```js
    const userController = new UserController({
      userRepository, authRepository });
    ```

    现在，你应该能够运行应用程序！

    现在，如果你创建几个请求来测试它，你会注意到`POST /login`端点仍然没有返回令牌。让我们解决这个问题！

1.  打开`src/web/index.ts`，在`login`路线上，确保我们从响应中的`login`方法返回`token`：

    ```js
    apiRouter.post("/login", async (ctx) => {
      const { username, password } = await
        ctx.request.body().value;
      try {
        const { user: loginUser, token } = await user.login({
          username, password });
        ctx.response.body = { user: loginUser, token };
        ctx.response.status = 201;
      } catch (e) {
        ctx.response.body = { message: e.message };
        ctx.response.status = 400;
      }
    })
    ```

我们几乎完成了！我们成功完成了第一个目标：使`login`端点返回一个令牌。

我们接下来要实现的是确保用户在尝试访问认证路线时始终发送令牌的逻辑。

我们继续完善认证逻辑。

## 创建一个认证路线

有了向用户获取令牌的能力，我们现在希望确保只有登录的用户能够访问博物馆路线。

用户必须将令牌发送到`Authorization`头中，正如 JWT 令牌标准所定义的。如果令牌无效或不存在，用户应显示`401 Unauthorized`状态码。

验证用户在请求中发送的令牌是中间件函数的一个很好的用例。

为了做到这一点，既然我们正在使用`oak`，我们将使用一个名为`oak-middleware-jwt`的第三方模块。这只是一个自动验证 JWT 令牌的中间件，基于密钥，并提供对我们有用的功能。

你可以查看其文档在[`nest.land/package/oak-middleware-jwt`](https://nest.land/package/oak-middleware-jwt)。

让我们在我们的网络代码中使用这个中间件，使博物馆路线只对认证用户可用。按照以下步骤操作：

1.  在`deps.ts`文件中添加`oak-middleware-jwt`，并导出`jwtMiddleware`函数：

    ```js
    export {
      jwtMiddleware,
    } from "https://x.nest.land/
       oak-middleware-jwt@2.0.0/mod.ts";
    ```

1.  回到`src/web/index.ts`，在博物馆路由中使用`jwtMiddleware`，在那里发送密钥和算法。

    不要忘记我们在上一节中提到的内容——中间件函数可以通过在路由处理程序之前发送它，在任何路由中使用：

    ```js
    import { Application, src/index.ts and forget to change this.This is exactly why we should extract this and expect it as a parameter to the `createServer` function.
    ```

1.  在`createServer`函数中向`configuration`内部添加`authorization`作为参数：

    ```js
    import { Algorithm type from the deps.ts file, which exports it from the jwt-auth module. We're doing this so that we can ensure, via types, that the algorithms that are sent are only the supported ones.
    ```

1.  现在，仍然在`src/web/index.ts`中，使用`authorization`参数发送将被注入到`jwtMiddleware`中的值：

    ```js
    const authenticated = jwtMiddleware(authorization)
    ```

    我们唯一缺少的是实际上将`authorization`值发送到`createServer`函数的能力。

1.  在`src/index.ts`中，将认证配置提取到一个变量中，以便我们可以重复使用：

    ```js
    import { AuthRepository, Algorithm } from "./deps.ts";
    …
    const authConfiguration = {
      algorithm: "HS512" as Algorithm,
      key: "my-insecure-key",
      tokenExpirationInSeconds: 120
    }
    const authRepository = new AuthRepository({
      configuration: authConfiguration
    });
    ```

1.  让我们重复使用那个相同的变量来发送发送到`createServer`所需参数：

    ```js
    createServer({
      configuration: {
        port: 8080,
        authorization: {
          key: authConfiguration.key,
          algorithm: authConfiguration.algorithm
        }
      },
      museum: museumController,
      user: userController
    })
    ```

    大功告成！让我们测试一下我们的应用程序，看看它是否按预期工作。

    请注意，期望的行为是只有认证用户才能访问博物馆路由并看到所有的博物馆。

1.  让我们通过运行以下命令来运行应用程序：

    ```js
    $ deno run --allow-net src/index.ts
    Application running at http://localhost:8080
    ```

1.  让我们注册一个用户，这样我们就可以登录了：

    ```js
    $ curl -X POST -d '{"username": "asantos00", "password": "testpw1" }' -H 'Content-Type: application/json' http://localhost:8080/api/users/register
    {"user":{"username":"asantos00","createdAt" :"2020-10-27T19:14:01.984Z"}}
    ```

1.  现在，让我们登录，这样我们就可以获得我们的令牌：

    ```js
    $ curl -X POST -d '{"username": "asantos00", "password": "testpw1" }' -H 'Content-Type: application/json' http://localhost:8080/api/login
    {"user":{"username":"asantos00","createdAt":"2020-10-27T19:14:01.984Z"},"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtdXNldW1zIiwiZXhwIjoxNjAzODI2NTEzLCJ1c2VyIjoi YXNhbnRvczAwIn0.XV1vaHDpTu2SnavFla5q8eIPKCRIfDw_Kk-j8gi1 mqcz5UN3sVnk61JWCapwlh0IJ46fJdc7cw2WoMMIh-ypcg"}
    ```

1.  最后，让我们尝试使用从前一个请求返回的令牌访问博物馆路由：

    ```js
    Authentication header with Bearer as a prefix, as specified by the JWT specification.
    ```

1.  为了确保它按预期工作，让我们尝试在不带`Authorization`头的相同请求中，期望一个`unauthorized`响应：

    ```js
    -i flag with curl so that it logs the request status code and headers.
    ```

就这些！现在我们已经成功创建了一个仅限认证用户访问的路由。这在任何包含用户的应用程序中都非常常见。

如果我们更深入地了解这个问题，我们可以探索 JWT `refreshToken`，或者甚至如何从 JWT 令牌中读取用户信息，但这些都超出了本书的范围。这是我要让您自己探索的东西。

在本节中，我们实现了我们的目标，并查看了 API 的许多不同部分。

不过还有一件事缺失：与真实持久化引擎的连接。这就是我们接下来要做的——将我们的应用程序连接到 NoSQL 数据库！

# 连接到 MongoDB

到目前为止，我们已经实现了一个列出博物馆的应用程序，并包含用户，允许他们进行认证。这些功能已经就位，但它们都有一个缺点：它们都在内存数据库上运行。

我们选择这种方式是为了简化问题。然而，由于我们的大部分实现都不依赖于交付机制，如果数据库发生变化，它应该不会有多大变化。

从这一节的标题中，您可能已经猜到，我们将学习如何将应用程序的一个实体移动到数据库。我们将利用我们已经创建的抽象来实现这一点。这个过程将与所有实体非常相似，因此我们决定学习如何连接数据库，只为了用户模块。

稍后，如果您好奇如果所有应用程序都连接到数据库，这会怎样工作，您将有机会检查这本书的 GitHub 仓库。

为了确保我们都对类似的数据库进行操作，我们将使用 MongoDB Atlas。Atlas 是一个提供免费 MongoDB 集群的产品，我们可以用来连接我们的应用程序。

如果你不熟悉 MongoDB，这里有一个来自他们网站的“一句话解释”（[`www.mongodb.com/`](https://www.mongodb.com/)）。请随意去那里了解更多：

"MongoDB 是一个通用目的、基于文档、分布式数据库，为现代应用程序开发人员和云时代而构建。"

准备好了吗？让我们开始吧！

## 创建一个用户 MongoDB 存储库

我们当前的`UserRepository`是负责将用户与数据库连接的模块。这就是我们想要更改的，以便我们的应用程序连接到一个 MongoDB 实例，而不是一个内存数据库。

我们将通过创建新的 MongoDB 存储库、将其暴露给世界、并将我们应用程序的其余部分连接到它的步骤。

首先，通过重新组织用户模块的内部文件结构，为新的用户存储库创建空间。

### 重新排列我们的用户模块

我们的用户模块最初设想只有一个存储库，因此它没有相应的文件夹；只是一个`repository.ts`文件。现在我们考虑将用户保存到数据库的更多方法，我们需要创建它。

记得我们第一次谈到架构时，提到了它将不断进化吗？这就是正在发生的事情。

让我们重新排列用户模块，以便它可以处理多个存储库并添加一个 MongoDB 存储库，遵循我们之前创建的`UserRepository`接口：

1.  在`src/users`内创建一个名为`repository`的文件夹，并将实际的`src/users/repository.ts`移动到那里，将其重命名为`inMemory.ts`：

    ```js
    └── src
        ├── museums
        ├── users
        │   ├── adapter.ts
        │   ├── controller.ts
        │   ├── index.ts
        │   ├── repository
    │ │   ├── inMemory.ts
        │   ├── types.ts
        │   └── util.ts
    ```

1.  记得修复`src/users/repository/inMemory.ts`内的模块导入：

    ```js
    import { User, UserRepository } from "../types.ts";
    import { generateSalt, hashWithSalt } from "../util.ts";
    ```

1.  为了保持应用程序的运行，让我们前往`src/users/index.ts`并导出正确的存储库：

    ```js
    export { Repository } from './repository/inMemory.ts'
    ```

1.  现在，让我们创建一个 MongoDB 存储库。将其命名为`mongoDb.ts`，并将其放入`src/users/respository`文件夹内：

    ```js
    import { UserRepository } from "../types.ts";
    export class Repository implements UserRepository {
      storage
      async create(username: string, password: string) {
      }
      async exists(username: string) {
      }
      async getByUsername(username: string) {
      }
    }
    ```

    确保它实现了我们之前定义的`UserRepository`接口。

这里就是所有乐趣开始的地方！现在我们有了 MongoDB 存储库，我们将开始编写它并将其连接到我们的应用程序。

## 安装 MongoDB 客户端库

我们已经有了一个我们存储库需要实现的方法列表。遵循接口，我们可以保证我们的应用程序会工作，不管实现方式如何。

有一件事我们可以肯定，因为我们不想一直重新发明轮子：我们将使用第三方包来处理与 MongoDB 的连接。

我们将使用`deno-mongo`包进行此操作（[`github.com/manyuanrong/deno_mongo`](https://github.com/manyuanrong/deno_mongo)）。

重要提示

Deno 的 MongoDB 驱动程序使用 Deno 插件 API，该 API 仍处于不稳定状态。这意味着我们将不得不以`--unstable`标志运行我们的应用程序。由于它目前正在使用尚未被认为是稳定的 API，因此暂时不应在生产环境中使用。

让我们看看文档中的示例，其中建立了与 MongoDB 数据库的连接：

```js
import { MongoClient } from
  "https://deno.land/x/mongo@v0.13.0/mod.ts";
const client = new MongoClient();
client.connectWithUri("mongodb://localhost:27017");
const db = client.database("test");
const users = db.collection<UserSchema>("users");
```

在这里，我们可以看到我们将需要创建一个 MongoDB 客户端并使用包含主机（可能包含主机的用户名和密码）的连接字符串连接到数据库。

之后，我们需要让客户端访问一个特定的数据库（在这个例子中是`test`）。只有这样，我们才能拥有允许我们与集合（在这个例子中是`users`）交互的处理程序。

首先，让我们将`deno-mongo`添加到我们的依赖列表中：

1.  前往你的`src/deps.ts`文件，并在那里添加`MongoClient`的导出：

    ```js
    export { MongoClient } from
      "https://deno.land/x/mongo@v0.13.0/mod.ts";
    ```

1.  现在，确保运行`cache`命令以安装模块。我们将不得不使用`--unstable`标志运行它，因为我们要安装的插件在安装时也需要不稳定的 API：

    ```js
    $ deno cache --lock=lock.json --lock-write --unstable src/deps.ts
    ```

有了这个，我们已经用我们刚刚安装的包更新了`deps.ts`文件！

让我们继续使用这个包来开发我们的仓库。

## 开发 MongoDB 仓库

从我们从文档中获得的示例中，我们学会了如何连接到数据库并创建我们想要的用户集合的处理程序。我们知道我们的仓库需要访问这个处理程序，以便它可以与集合交互。

再次，我们可以在仓库内部直接创建 MongoDB 客户端，但这将使我们无法在没有尝试连接到 MongoDB 的情况下测试该仓库。

由于我们尽可能希望将依赖项注入到模块中，我们将通过其构造函数将 MongoDB 客户端传递给我们的仓库，这在代码的其他部分非常类似于我们做的。

让我们回到我们的 MongoDB 仓库，并按照这些步骤进行操作：

1.  在 MongoDB 仓库内创建`constructor`方法。

    确保它接收一个具有名为`storage`的`Database`类型的属性的对象，该属性是由`deno-mongo`包导出的：

    ```js
    import { User, UserRepository } from "../types.ts";
    collection method on it, to get access to the users' collection. Once we've done that, we must set it to our storage class property. Both the method and the type require a generic to be passed in. This should represent the type of object present in that collection. In our case, it is the User type.
    ```

1.  现在，我们必须进入`src/deps.ts`文件，并从`deno-mongo`中导出`Database`和`Collection`类型：

    ```js
    export { MongoClient, Collection, Database } from
      "https://deno.land/x/mongo@v0.13.0/mod.ts";
    ```

现在，这只是开发满足`UserRepository`接口的方法的问题。

这些方法将非常类似于我们为内存数据库开发的那些方法，区别在于我们现在在与 MongoDB 集合交互，而不是我们之前使用的 JavaScript Map。

现在，我们只需要实现一些方法，这些方法将创建用户、验证用户是否存在，并通过用户名获取用户。这些方法在插件文档中可用，非常接近 MongoDB 的本地 API。

这是最终类的样子：

```js
import { CreateUser, User, UserRepository } from
 "../types.ts";
import { Collection, Database } from "../../deps.ts";
export class Repository implements UserRepository {
  storage: Collection<User>
  constructor({ storage }: RepositoryDependencies) {
    this.storage = storage.collection<User>("users");
  }
  async create(user: CreateUser) {
    const userWithCreatedAt = { ...user, createdAt: new Date() }
    this.storage.insertOne({ ...user })
    return userWithCreatedAt;
  }
  async exists(username: string) {
    return Boolean(await this.storage.count({ username }));
  }
  async getByUsername(username: string) {
    const user = await this.storage.findOne({ username });
    if (!user) {
      throw new Error("User not found");
    }
    return user;
  }
}  
```

我们突出了使用`deno-mongo`插件访问数据库的方法。注意逻辑与我们之前做的非常相似。我们在`create`方法中添加了创建日期，然后从 mongo 调用`create`方法。在`exists`方法中，我们调用`count`方法，并将其转换为`boolean`。对于`getByUsername`方法，我们使用 mongo 库中的`findOne`方法，发送用户名。

如果你对如何使用这些 API 有任何疑问，请查看 deno-mongo 的文档 ([`github.com/manyuanrong/deno_mongo`](https://github.com/manyuanrong/deno_mongo)).

## 将应用程序连接到 MongoDB

现在，为了暴露我们创建的 MongoDB 仓库，我们需要进入`src/users/index.ts`并将其作为`Repository`暴露（删除高亮显示的行）：

```js
export { Repository } from "./repository/mongoDb.ts";
export { Repository } from "./repository/inMemory.ts";
```

现在，我们应该在我们的编辑器和 typescript 编译器中看到抱怨，抱怨我们在`src/index.ts`中实例化`UserRepository`时没有发送正确的依赖关系，这是正确的。所以，让我们去那里修复它。

在将数据库客户端发送到`UserRepository`之前，它需要被实例化。通过查看`deno-mongo`的文档，我们可以看到以下示例：

```js
const client = new MongoClient();
client.connectWithUri("mongodb://localhost:27017");
```

我们没有连接到 localhost，所以我们需要稍后更改连接 URI。

让我们按照文档的示例，编写连接到 MongoDB 实例的代码。按照以下步骤操作：

1.  在将`MongoClient`的导出添加到`src/deps.ts`文件后，在`src/index.ts`中导入它：

    ```js
    import { MongoClient } from "./deps.ts";
    ```

1.  然后，调用`connectWithUri`：

    ```js
    const client = new MongoClient();
    client.connectWithUri("mongodb://localhost:27017");
    ```

1.  然后，通过在客户端上调用`database`方法来获取一个数据库处理器：

    ```js
    const db = client.database("getting-started-with-deno");
    ```

这应该是我们连接到 MongoDB 所需的所有内容。唯一缺少的是将数据库处理器发送到`UserRepository`的代码。所以，让我们添加这个：

```js
const client = new MongoClient();
client.connectWithUri("mongodb://localhost:27017");
const db = client.database("getting-started-with-deno");
...
const userRepository = new UserRepository({ storage: db });
```

不应该有任何警告出现，我们应该现在能够运行我们的应用程序了！

然而，我们仍然没有一个数据库可以连接。我们接下来会看看这个问题。

## 连接到 MongoDB 集群

现在，我们需要连接到一个真实的 MongoDB 实例。在这里，我们将使用一个名为 Atlas 的服务。Atlas 是 MongoDB 提供的一个云 MongoDB 数据库服务。他们的免费层非常慷慨，非常适合我们的应用程序。在那里创建一个账户。完成后，我们可以创建一个 MongoDB 集群。

重要提示

如果你有其他任何 MongoDB 实例，无论是本地的还是远程的，都可以跳过下一段，直接将数据库 URI 插入代码中。

以下链接包含创建一个集群所需的所有说明：[`docs.atlas.mongodb.com/tutorial/create-new-cluster/`](https://docs.atlas.mongodb.com/tutorial/create-new-cluster/)。

一旦集群被创建，我们还需要创建一个可以访问它的用户。前往[`docs.atlas.mongodb.com/tutorial/connect-to-your-cluster/index.html#connect-to-your-atlas-cluster`](https://docs.atlas.mongodb.com/tutorial/connect-to-your-cluster/index.html#connect-to-your-atlas-cluster)了解如何获取连接字符串。

它应该看起来像下面这样：

```js
mongodb+srv://<username>:<password>@clustername.mongodb.net/
  test?retryWrites=true&w=majority&useNewUrlParser=
    true&useUnifiedTopology=true
```

现在我们有了连接字符串，我们只需要将其传递给之前在`src/index.ts`中创建的代码：

```js
const client = new MongoClient();
client.connectWithUri("mongodb+srv://<username>:<password>
  @clustername.mongodb.net/test?retryWrites=true&w=
    majority&useNewUrlParser=true&useUnifiedTopology=true");
const db = client.database("getting-started-with-deno");
```

应该就是我们所需要的全部内容了，让我们开始吧！

记住，由于我们使用插件 API 连接到 MongoDB，而且它仍然不稳定，所以需要以下权限以及`--unstable`标志：

```js
$ deno run --allow-net --allow-write --allow-read --allow-plugin --allow-env --unstable src/index.ts
Application running at http://localhost:8080
```

现在，为了测试我们的`UserRepository`是否运行正常并且与数据库连接，让我们尝试注册并登录看看是否可行：

1.  向`/api/users/register`发送一个`POST`请求来注册我们的用户：

    ```js
    $ curl -X POST -d '{"username": "asantos00", "password": "testpw1" }' -H 'Content-Type: application/json' http://localhost:8080/api/users/register
    {"user":{"username":"asantos00","createdAt":"2020-11-01T23:21:58.442Z"}}
    ```

1.  现在，为了确保我们连接到永久存储，我们可以停止应用程序然后再次运行它，在尝试登录之前：

    ```js
    $ deno run --allow-net --allow-write --allow-read --allow-plugin --allow-env --unstable src/index.ts
    Application running at http://localhost:8080
    ```

1.  现在，让我们用刚才创建的同一个用户登录：

    ```js
    $ curl -X POST -d '{"username": "asantos00", "password": "testpw1" }' -H 'Content-Type: application/json' http://localhost:8080/api/login
    {"user":{"username":"asantos006"},"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtdXNl dW1zIiwiZXhwIjoxNjA0MjczMDQ1LCJ1c2VyIjoiYXNhbnRvczAwNi J9.elY48It-DHse5sSszCAWuE2PzNkKiPsMIvif4v5klY1URq0togK 84wsbSskGAfe5UQsJScr4_0yxqnrxEG8viw"}
    ```

我们得到了响应！我们成功地将之前连接到内存数据库的应用程序连接到了一个真实的 MongoDB 数据库。如果你使用了 MongoDB，你可以在 Atlas 界面的**集合**菜单中查看那里创建的用户。

你注意到我们为了更改持久性机制并没有触及到任何业务或网络逻辑了吗？这证明了我们最初创建的层和抽象现在正在发挥作用，通过允许应用程序不同部分之间的解耦。

有了这些，我们完成了这一章节并把我们的用户迁移到了一个真实的数据库。我们也可以对其他模块做同样的事情，但那将会是几乎相同的工作，并且不会为你的学习体验增加太多。我想挑战你编写其他模块的逻辑，使其能够连接到 MongoDB。

如果你想要跳过这部分但是好奇它会是怎样的，那么去看看这本书的 GitHub 仓库吧。

# 总结

这一章节基本上已经涵盖了我们在逻辑方面对应用程序的封装。我们稍后会在第八章 *测试 - 单元和集成* 中添加测试以及我们所缺少的一个特性——对博物馆进行评分的能力。然而，这部分大多数已经完成。在其当前状态下，我们有一个应用程序，它的领域被划分为可以独立使用且彼此不依赖的模块。我们相信我们已经实现了一些既易于在代码中导航又可扩展的东西。

这一过程结束了不断重构和精炼架构、管理依赖项以及调整逻辑以确保代码尽可能解耦，同时尽可能容易地在未来进行更改。在完成所有这些工作时，我们设法创建了一个具有几个功能的应用程序，同时尝试绕过行业标准。

我们通过学习中间件函数开始了这一章，这是我们之前使用过，尽管我们还没有学习过它们的东西。我们理解了它们是如何工作的，以及它们如何被利用来在应用程序和路线中添加逻辑。为了更具体一点，我们进入了具体的例子，并以在应用程序中实现几个为例结束。在这里，我们添加了诸如基本日志记录和请求计时等常见功能。

然后，我们继续完成认证的旅程。在上一章中添加了用户和注册功能后，我们开始实现认证功能。我们依赖一个外部包来管理我们的 JWT 令牌，我们稍后用于我们的授权机制。在向用户提供令牌后，我们必须确保令牌有效，然后才允许用户访问应用程序。我们在博物馆路线上添加了一个认证路线，确保它只能被认证用户访问。再次使用中间件来检查令牌的有效性并在错误情况下回答请求。

我们通过向应用程序添加一个新功能来结束这一章：连接到真实数据库。在我们这样做之前，我们所有的应用程序模块都依赖于内存中的数据库。在这里，我们将其中一个模块，“用户”，移动到 MongoDB 实例。为了做到这一点，我们利用了之前创建的层来将业务逻辑与我们的持久化和交付机制分离。在这里，我们创建并实现了我们所谓的 MongoDB 存储库，确保应用程序运行顺利，但具有真正的持久化机制。我们为此示例使用了 MongoDB Atlas。

在下一章中，我们将向我们的网络应用程序添加一些内容，具体包括管理代码之外的秘密和配置的能力，这是一个众所周知的好实践。我们还将探索 Deno 在运行浏览器代码等方面的可能性，等等。下一章将结束这本书的这一部分；也就是说，构建应用程序的功能。让我们开始吧！
