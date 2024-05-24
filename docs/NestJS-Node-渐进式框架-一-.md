# NestJS：Node 渐进式框架（一）

> 原文：[`zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240`](https://zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 什么是 Nest.js？

有很多可用的 Web 框架，随着 Node.js 的出现，发布的框架更是层出不穷。随着 Web 技术的变化和发展，JavaScript 框架很快就会进入和退出流行。Nest.js 对许多开发人员来说是一个很好的起点，因为它使用一种非常类似于迄今为止最常用的 Web 语言 JavaScript 的语言。许多开发人员是使用诸如 Java 或 C/C++之类的语言来学习编程的，这两种语言都是严格的语言，因此使用 JavaScript 可能会有点尴尬，并且由于缺乏类型安全性，容易出错。Nest.js 使用 TypeScript，这是一个很好的折衷方案。它是一种语言，提供了 JavaScript 的简单性和强大性，同时又具有您可能习惯的其他语言的类型安全性。Nest.js 中的类型安全性仅在编译时可用，因为 Nest.js 服务器被编译为运行 JavaScript 的 Node.js Express 服务器。然而，这仍然是一个重大优势，因为它允许您在运行时之前更好地设计无错误的程序。

Node.js 在 NPM（Node Package Manager）中拥有丰富的软件包生态系统。拥有超过 35 万个软件包，它是世界上最大的软件包注册表。使用 Express 的 Nest.js 在开发 Nest 应用程序时，您可以访问每一个这些软件包。许多软件包甚至为其软件包提供了类型定义，允许 IDE 读取软件包并提供建议/自动填充代码，这在跨 JavaScript 代码与 TypeScript 代码交叉时可能是不可能的。Node.js 最大的好处之一是可以从中提取模块的庞大存储库，而不必编写自己的模块。Nest.js 已经将其中一些模块包括在 Nest 平台的一部分中，比如`@nestjs/mongoose`，它使用 NPM 库`mongoose`。在 2009 年之前，JavaScript 主要是一种前端语言，但在 2009 年 Node.js 发布之后，它推动了许多 JavaScript 和 TypeScript 项目的开发，如：Angular、React 等。Angular 对 Nest.js 的开发产生了很大的启发，因为两者都使用了允许可重用的模块/组件系统。如果您不熟悉 Angular，它是一个基于 TypeScript 的前端框架，可用于跨平台开发响应式 Web 应用程序和原生应用程序，并且它的功能与 Nest 非常相似。两者在一起也非常搭配，Nest 提供了运行通用服务器的能力，以提供预渲染的 Angular 网页，以加快网站交付时间，使用了上面提到的服务器端渲染（SSR）。

# 关于示例

本书将引用一个托管在 GitHub 上的 Nest.js 项目的示例（https://github.com/backstopmedia/nest-book-example）。在整本书中，代码片段和章节将引用代码的部分，以便您可以看到您所学习的内容的一个工作示例。示例 Git 存储库可以在命令提示符中克隆。

```js
git clone https://github.com/backstopmedia/nest-book-example.git

```

这将在您的计算机上创建项目的本地副本，您可以通过使用 Docker 构建项目在本地运行：

```js
docker-compose up

```

一旦您的 Docker 容器在本地主机：3000 端口上运行起来，您将希望在做任何其他事情之前运行迁移。要做到这一点，请运行：

```js
docker ps

```

获取正在运行的 Docker 容器的 ID：

```js
docker exec -it [ID] npm run migrate up

```

这将运行数据库迁移，以便您的 Nest.js 应用程序可以使用正确的模式读取和写入数据库。

如果您不想使用 Docker，或者无法使用 Docker，您可以使用您选择的软件包管理器（如`npm`或`yarn`）构建项目：

```js
npm install

```

或

```js
yarn

```

这将在您的`node_modules`文件夹中安装依赖项。然后运行：

```js
npm start:dev

```

或以下内容启动您的 Nest.js 服务器：

```js
yarn start:dev

```

这些将运行`nodemon`，如果有任何更改，将导致您的 Nest.js 应用程序重新启动，使您无需停止、重建和重新启动应用程序。

# 关于作者

+   格雷格·马戈兰（Greg Magolan）是 Rangle.io 的高级架构师、全栈工程师和 Angular 顾问。他在 Agilent Technologies、Electronic Arts、Avigilon、Energy Transfer Partners、FunnelEnvy、Yodel 和 ACM Facility Safety 等公司工作了 15 年以上，开发企业软件解决方案。

+   杰伊·贝尔（Jay Bell）是 Trellis 的首席技术官。他是一名资深的 Angular 开发人员，使用 Nest.js 在生产中开发领先行业的软件，帮助加拿大的非营利组织和慈善机构。他是一位连续创业者，曾在许多行业开发软件，从利用无人机帮助打击森林大火到构建移动应用程序。

+   大卫·吉哈罗（David Guijarro）是 Car2go Group GmbH 的前端开发人员。他在 JavaScript 生态系统内有丰富的工作经验，成功建立并领导了多元文化、多功能团队。

+   阿德里安·德佩雷蒂（Adrien de Peretti）是一名全栈 JavaScript 开发人员。他对新技术充满热情，不断寻找新挑战，特别对人工智能和机器人领域感兴趣。当他不在电脑前时，阿德里安喜欢在大自然中玩各种运动。

+   帕特里克·豪斯利（Patrick Housley）是 VML 的首席技术专家。他是一名拥有超过六年技术行业经验的 IT 专业人士，能够分析涉及多种技术的复杂问题，并提供详细的解决方案和解释。他具有强大的前端开发技能，有领导开发团队进行维护和新项目开发的经验。


# 第一章：介绍

每个 Web 开发人员都严重依赖于一个或多个 Web 框架（有时如果他们的服务有不同的要求，会使用更多），而公司将依赖于许多框架，但每个框架都有其优缺点。这些框架正是为开发人员提供一个框架，提供基本功能，任何 Web 框架必须提供这些功能，才能被认为是开发人员或公司在其技术栈中使用的一个好选择。在本书中，我们将讨论您期望在像 Nest 这样的先进框架中看到的框架的许多部分。这些包括：

1.  依赖注入

1.  认证

1.  ORM

1.  REST API

1.  Websockets

1.  微服务

1.  路由

1.  Nest 特定工具的解释

1.  OpenApi（Swagger）文档

1.  命令查询责任分离（CQRS）

1.  测试

1.  使用 Universal 和 Angular 进行服务器端渲染。

Nest 提供了更多这些功能，因为它是建立在 Node.js Express 服务器之上的现代 Web 框架。通过利用现代 ES6 JavaScript 的弹性和 TypeScript 在编译时强制类型安全，Nest 在设计和构建服务器端应用程序时将可扩展的 Node.js 服务器提升到一个全新的水平。Nest 将三种不同的技术结合成一个成功的组合，允许高度可测试、可扩展、松散耦合和可维护的应用程序。这些技术包括：

1.  面向对象编程（OOP）：一个围绕对象而不是动作和可重用性而不是利基功能构建的模型。

1.  函数式编程（FP）：设计不依赖于全局状态的确定功能，即函数 f(x)对于一些不变的参数每次返回相同的结果。

1.  函数式响应式编程（FRP）：是上述 FP 和响应式编程的扩展。函数式响应式编程在其核心是考虑时间流的函数式编程。它在 UI、模拟、机器人和其他应用程序中非常有用，其中特定时间段的确切答案可能与另一个时间段的答案不同。

# 讨论的主题

以下每个主题将在接下来的章节中详细讨论。

# Nest CLI

在 Nest 的第 5 版中，有一个 CLI 可以允许通过命令行生成项目和文件。可以通过以下命令全局安装 CLI：

```js
npm install -g @nestjs/cli

```

或者通过 Docker：

```js
docker pull nestjs/cli:[version]

```

可以使用以下命令生成新的 Nest 项目：

```js
nest new [project-name]

```

此过程将从[typescript-starter](https://github.com/nestjs/typescript-starter)创建项目，并将要求输入`name`，`description`，`version`（默认为 0.0.0）和`author`（这将是您的名字）。完成此过程后，您将拥有一个完全设置好的 Nest 项目，并且依赖项已安装在您的`node_modules`文件夹中。`new`命令还将询问您想要使用哪种包管理器，就像`yarn`或`npm`一样。Nest 在创建过程中为您提供了这个选择。

CLI 中最常用的命令将是`generate`（g）命令，这将允许您创建 Nest 支持的新的`controllers`，`modules`，`servies`或任何其他组件。可用组件的列表如下：

1.  `class`（cl）

1.  `controller`（co）

1.  `decorator`（d）

1.  `exception`（e）

1.  `filter`（f）

1.  `gateway`（ga）

1.  `guard`（gu）

1.  `interceptor`（i）

1.  `middleware`（mi）

1.  `module`（mo）

1.  `pipe`（pi）

1.  `provider`（pr）

1.  `service`（s）

请注意，括号中的字符串是该特定命令的别名。这意味着您可以输入：

```js
nest generate service [service-name]

```

在控制台中，您可以输入：

```js
nest g s [service-name]

```

最后，Nest CLI 提供了`info`（i）命令来显示关于您的项目的信息。此命令将输出类似以下内容的信息：

```js
[System Information]
OS Version     : macOS High Sierra
NodeJS Version : v8.9.0
YARN Version    : 1.5.1
[Nest Information]
microservices version : 5.0.0
websockets version    : 5.0.0
testing version       : 5.0.0
common version        : 5.0.0
core version          : 5.0.0

```

# 依赖注入

依赖注入是一种技术，它通过将依赖对象（如服务）注入到组件的构造函数中，从而将依赖对象（如模块或组件）提供给依赖对象。下面是来自 sequelize 章节的一个示例。在这里，我们将`UserRespository`服务注入到`UserService`的构造函数中，从而在`UserService`组件内部提供对用户数据库存储库的访问。

```js
@Injectable()
export class UserService implements IUserService {
    constructor(@Inject('UserRepository') private readonly UserRepository: typeof User) { }
    ...
}

```

反过来，这个`UsersService`将被注入到`src/users/users.controller.ts`文件中的`UsersController`中，这将为指向该控制器的路由提供对`UsersService`的访问。更多关于路由和依赖注入的内容将在后面的章节中讨论。

# 认证

认证是开发中最重要的方面之一。作为开发人员，我们始终希望确保用户只能访问他们有权限访问的资源。认证可以采用多种形式，从展示您的驾驶执照或护照到为登录门户提供用户名和密码。近年来，这些认证方法已经扩展到变得更加复杂，但我们仍然需要相同的服务器端逻辑，以确保这些经过认证的用户始终是他们所说的那个人，并保持这种认证，这样他们就不需要为每次对 REST API 或 Websocket 的调用重新进行认证，因为那将提供非常糟糕的用户体验。选择的库恰好也被命名为 Passport，并且在 Node.js 生态系统中非常知名和使用。在 Nest 中集成时，它使用 JWT（JSON Web Token）策略。Passport 是一个中间件，HTTP 调用在到达控制器端点之前会经过它。这是为示例项目编写的`AuthenticationMiddleware`，它扩展了`NestMiddleware`，根据请求负载中的电子邮件对每个用户进行认证。

```js
@Injectable()  
export class AuthenticationMiddleware implements NestMiddleware {  
   constructor(private userService: UserService) { }  

   async resolve(strategy: string): Promise<ExpressMiddleware> {  
       return async (req, res, next) => {  
           return passport.authenticate(strategy, async (/*...*/args: any[]) => {  
               const [, payload, err] = args;  
                if (err) {  
                    return res.status(HttpStatus.BAD_REQUEST).send('Unable to authenticate the user.');  
                }  

               const user = await this.userService.findOne({
                    where: { email: payload.email }
               });  
                req.user = user;  
                return next();  
            })(req, res, next);  
        };  
    }  
}

```

Nest 还实现了守卫，它们与其他提供者一样使用`@Injectable()`进行装饰。守卫基于经过认证的用户所拥有的访问权限来限制某些端点。守卫将在认证章节中进一步讨论。

# ORM

ORM 是对象关系映射，是处理服务器和数据库之间通信时最重要的概念之一。ORM 提供了内存中对象（如`User`或`Comment`这样的定义类）与数据库中的关系表之间的映射。这使您可以创建一个数据传输对象，它知道如何将存储在内存中的对象写入数据库，并从 SQL 或其他查询语言中读取结果，再次存入内存。在本书中，我们将讨论三种不同的 ORM：两种关系型数据库和一种 NoSQL 数据库。TypeORM 是 Node.js 中最成熟和最流行的 ORM 之一，因此具有非常广泛和完善的功能集。它也是 Nest 提供自己的包之一：`@nestjs/typeorm`。它非常强大，并支持许多数据库，如 MySQL、PostgreSQL、MariaDB、SQLite、MS SQL Server、Oracle 和 WebSQL。除了 TypeORM，Sequelize 也是另一个用于关系数据的 ORM。

如果 TypeORM 是最受欢迎的 ORM 之一，那么 Sequelize 就是 Node.js 世界中最受欢迎的 ORM。它是用纯 JavaScript 编写的，但通过`sequelize-typescript`和`@types/sequelize`包具有 TypeScript 绑定。Sequelize 拥有强大的事务支持、关系、读取复制和许多其他功能。本书涵盖的最后一个 ORM 是处理非关系型或 NoSQL 数据库的 ORM。包`mongoose`处理了 MongoDB 和 JavaScript 之间的对象关系。实际的映射比与关系数据库更接近，因为 MongoDB 以 JSON 格式存储其数据，JSON 代表 JavaScript 对象表示法。Mongoose 也是具有`@nestjs/mongoose`包的包之一，并提供通过查询链接查询数据库的能力。

# REST API

REST 是创建 API 的主要设计范式之一。它代表着表现状态转移，并使用 JSON 作为传输格式，这与 Nest 存储对象的方式一致，因此它是用于消费和返回 HTTP 调用的自然选择。REST API 是本书讨论的许多技术的组合。它们以一定的方式组合在一起；客户端向服务器发起 HTTP 调用。服务器将根据 URL 和 HTTP 动词路由调用到正确的控制器，可选择性地通过一个或多个中间件传递到控制器之前。控制器然后将其交给服务进行处理，这可能包括通过 ORM 与数据库通信。如果一切顺利，服务器将向客户端返回一个 OK 响应，如果客户端请求资源（GET 请求），则可能包含一个可选的主体，或者如果是 POST/PUT/DELETE，则只返回一个 200/201 HTTP OK，而没有响应主体。

# WebSockets

WebSockets 是连接到服务器并发送/接收数据的另一种方式。使用 WebSockets，客户端将连接到服务器，然后订阅特定的频道。然后客户端可以将数据推送到已订阅的频道。服务器将接收这些数据，然后将其广播给订阅了特定频道的每个客户端。这允许多个客户端都实时接收更新，而无需手动进行 API 调用，可能会通过 GET 请求向服务器发送大量请求。大多数聊天应用程序使用 WebSockets 来实现实时通信，群组消息中的每个成员发送消息后，所有成员都会立即收到消息。Websockets 允许更多地以流式传输数据的方式来传输数据，而不是传统的请求-响应 API，因为 Websockets 会在接收到数据时广播数据。

# 微服务

微服务允许 Nest 应用程序以一组松散耦合的服务的形式进行结构化。在 Nest 中，微服务略有不同，因为它们是使用除 HTTP 之外的不同传输层的应用程序。这一层可以是 TCP 或 Redis pub/sub 等。Nest 支持 TCP 和 Redis，尽管如果您使用其他传输层，可以通过使用`CustomTransportStrategy`接口来实现。微服务很棒，因为它们允许团队在全局项目中独立于其他团队的微服务进行工作，并对服务进行更改，而不会影响项目的其他部分，因为它是松散耦合的。这允许持续交付和持续集成，而不受其他团队微服务的影响。

# GraphQL

正如我们在上面看到的，REST 是设计 API 时的一种范式，但现在有一种新的方式来考虑创建和使用 API：GraphQL。使用 GraphQL，每个资源都不再有自己指向它的 URL，而是 URL 将接受一个带有 JSON 对象的查询参数。这个 JSON 对象定义了要返回的数据的类型和格式。Nest 通过`@nestjs/graphql`包提供了这方面的功能。这将在项目中包括`GraphQLModule`，它是 Apollo 服务器的包装器。GraphQL 是一个可以写一整本书的主题，所以我们在本书中不再深入讨论它。

# 路由

路由是讨论 Web 框架的核心原则之一。客户端需要知道如何访问服务器的端点。这些端点中的每一个描述了如何检索/创建/操作存储在服务器上的数据。描述 API 端点的每个`Component`必须具有一个`@Controller('prefix')`装饰器，用于描述此组件端点集的 API 前缀。

```js
@Controller('hello')
export class HelloWorldController {
  @Get(‘world’)
  printHelloWorld() {
    return ‘Hello World’;
  }
}

```

上述控制器是`GET /hello/world`的 API 端点，将返回一个带有`Hello World`的`HTTP 200 OK`。这将在路由章节中进一步讨论，您将了解如何使用 URL 参数、查询参数和请求对象。

# Nest 特定工具

Nest 提供了一组特定于 Nest.js 的工具，可以在整个应用程序中使用，帮助编写可重用的代码并遵循 SOLID 原则。这些装饰器将在后续的每一章中使用，因为它们定义了特定的功能：

1.  @Module：项目中可重用代码的定义，它接受以下参数来定义其行为。⋅⋅ *导入：这些是包含在此模块中使用的组件的模块。⋅⋅*导出：这些是将在其他模块中使用的组件，导入此模块的模块。⋅⋅ *组件：这些组件将可供至少通过 Nest 注入器共享此模块。⋅⋅*控制器：在此模块中创建的控制器，这些控制器将根据定义的路由定义 API 端点。

1.  @Injectable：Nest 中几乎所有东西都是可以通过构造函数注入的提供者。提供者使用`@Injectable()`进行注释。.. *中间件：在请求传递到路由处理程序之前运行的函数。在本章中，我们将讨论中间件、异步中间件和功能中间件之间的区别。..*拦截器：类似于中间件，它们在方法执行前后绑定额外的逻辑，并且可以转换或完全覆盖函数。拦截器受面向方面的编程（AOP）的启发。.. *管道：类似于拦截器功能的一部分，管道将输入数据转换为所需的输出。..*守卫：更智能、更专业的中间件，守卫的唯一目的是确定请求是否应该由路由处理程序处理。..*Catch：告诉`ExceptionFilter`要查找的异常，然后将数据绑定到它。

1.  @Catch：将元数据绑定到异常过滤器，并告诉 Nest 过滤器仅寻找`@Catch`中列出的异常。

注意：在 Nest 版本 4 中，上面列出的`@Injectable()`下的不是所有东西都使用`@Injectable()`装饰器。组件、中间件、拦截器、管道和守卫各自都有自己的装饰器。在 Nest 版本 5 中，这些都已合并为`@Injectable()`，以减少 Nest 和 Angular 之间的差异。

# OpenAPI（Swagger）

在编写 Nest 服务器时，文档非常重要，特别是在创建将被其他人使用的 API 时，否则最终将使用 API 的客户端的开发人员不知道该发送什么或者他们会得到什么。其中最流行的文档引擎之一是 Swagger。与其他文档引擎一样，Nest 提供了专门用于 OpenAPI（Swagger）规范的模块`@nestjs/swagger`。该模块提供装饰器来描述 API 的输入/输出和端点。然后可以通过服务器上的端点访问此文档。

# 命令查询责任分离（CQRS）

命令查询责任分离（CQRS）是每个方法应该是执行操作（命令）或请求数据（查询）的想法，但不能两者兼而有之。在我们示例应用程序的上下文中，我们不会在端点的控制器中直接使用数据库访问代码，而是创建一个组件（数据库服务），该组件具有诸如`getAllUsers()`的方法，该方法将返回控制器服务可以调用的所有用户，从而将问题和答案分离到不同的组件中。

# 测试

测试您的 Nest 服务器将是至关重要的，以便一旦部署，就不会出现意外问题，并且一切都能顺利运行。在本书中，您将了解两种不同类型的测试：单元测试和 E2E 测试（端到端测试）。单元测试是测试小片段或代码块的艺术，这可能是测试单个函数或为`Controller`、`Interceptor`或任何其他`Injectable`编写测试。有许多流行的单元测试框架，`Jasmine`和`Jest`是其中两个流行的框架。Nest 提供了专门的包，特别是`@nestjs/testing`，用于在`*.spec.ts`和`*.test.ts`类中编写单元测试。

E2E 测试是常用的另一种测试形式，与单元测试不同之处在于它测试的是整个功能，而不是单个函数或组件，这就是所谓的端到端测试的由来。最终，应用程序会变得如此庞大，以至于很难测试每一行代码和端点。在这种情况下，您可以使用 E2E 测试来测试应用程序从开始到结束，以确保一切顺利进行。对于 E2E 测试，Nest 应用程序可以再次使用`Jest`库来模拟组件。除了`Jest`，您还可以使用`supertest`库来模拟 HTTP 请求。

测试是编写应用程序的非常重要的一部分，不应被忽视。无论您最终使用什么语言或框架，这都是一个相关的章节。大多数大型开发公司都有专门的团队负责为推送到生产应用程序的代码编写测试，这些团队被称为 QA 开发人员。

# 使用 Angular Universal 进行服务器端渲染

Angular 是一个客户端应用程序开发框架，而 Angular Universal 是一种技术，允许我们的 Nest 服务器预渲染网页并将其提供给客户端，这有许多好处，将在“使用 Angular Universal 进行服务器端渲染”章节中讨论。Nest 和 Angular 非常搭配，因为它们都使用 TypeScript 和 Node.js。许多可以在 Nest 服务器中使用的包也可以在 Angular 应用程序中使用，因为它们都编译为 JavaScript。

# 总结

在本书中，您将更详细地了解上述每个主题，不断构建在先前概念的基础上。Nest 提供了一个清晰、组织良好的框架，以简单而高效的方式实现每个概念，这是因为框架的模块化设计在所有模块中都是一致的。


# 第二章：概述

在本章中，我们将概述 Nest.js，并查看构建 Nest.js 应用程序所需的核心概念。

# 控制器

Nest 中的控制器负责处理传入的请求并向客户端返回响应。Nest 将传入的请求路由到控制器类中的处理程序函数。我们使用`@Controller()`装饰器来创建控制器类。

```js
import { Controller, Get } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Get()
    index(): Entry[] {
        const entries: Entry[] = this.entriesService.findAll();
        return entries;
    }

```

我们将在**路由和请求处理**章节中详细讨论路由和处理请求的细节。

# 提供者

Nest 中的提供者用于创建服务、工厂、助手等，这些可以被注入到控制器和其他提供者中，使用 Nest 内置的依赖注入。`@Injectable()`装饰器用于创建提供者类。

例如，我们博客应用程序中的`AuthenticationService`是一个提供者，它注入并使用`UsersService`组件。

```js
@Injectable()
export class AuthenticationService {
    constructor(private readonly userService: UserService) {}

    async validateUser(payload: {
        email: string;
        password: string;
    }): Promise<boolean> {
        const user = await this.userService.findOne({
            where: { email: payload.email }
        });
        return !!user;
    }
}

```

我们将在**依赖注入**章节中更多地讨论依赖注入。

# 模块

Nest.js 应用程序被组织成模块。如果您熟悉 Angular 中的模块，那么 Nest 使用的模块语法将看起来非常熟悉。

每个 Nest.js 应用程序都将有一个**根模块**。在一个小应用程序中，这可能是唯一的模块。在一个较大的应用程序中，将应用程序组织成多个模块是有意义的，这些模块将您的代码分割成功能和相关功能。

Nest.js 中的模块是带有`@Module()`装饰器的类。`@Module()`装饰器接受一个描述模块的单个对象，使用以下属性。

| 属性 | 描述 |
| --- | --- |
| `components` | 要实例化的组件，可以在此模块中共享，并导出以供其他模块使用 |
| `controllers` | 由此模块创建的控制器 |
| `imports` | 要导入的模块列表，这些模块导出了此模块中需要的组件 |
| `exports` | 从此模块导出的组件列表，可供其他模块使用 |

在我们的示例应用程序中，根模块名为`AppModule`，应用程序分为多个子模块，这些子模块处理应用程序的主要部分，如身份验证、评论、数据库访问、博客条目和用户。

```js
@Module({
    components: [],
    controllers: [],
    imports: [
        DatabaseModule,
        AuthenticationModule.forRoot('jwt'),
        UserModule,
        EntryModule,
        CommentModule,
        UserGatewayModule,
        CommentGatewayModule
    ],
    exports: [],
})
export class AppModule implements NestModule {}

```

AppModule 导入应用程序所需的模块。我们的应用程序中的根模块不需要有任何`exports`，因为没有其他模块导入它。

根模块也没有任何`components`或`controllers`，因为这些都是在它们相关的子模块中组织的。例如，`EntryModule`包括与博客条目相关的`components`和`controllers`。

```js
@Module({
    components: [entryProvider, EntryService],
    controllers: [EntryController],
    imports: [],
    exports: [EntryService],
})
export class EntryModule implements NestModule {}

```

在 Nest.js 中，模块默认是单例的。这意味着您可以在模块之间共享导出组件的相同实例，例如上面的`EntryService`，而无需任何努力。

# 引导

每个 Nest.js 应用程序都需要进行引导。这是通过使用`NestFactory`创建根模块并调用`listen()`方法来完成的。

在我们的示例应用程序中，入口点是`main.ts`，我们使用 async/await 模式创建`AppModule`并调用`listen()`：

```js
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();

```

# 中间件

Nest.js 中间件可以是一个函数，也可以是一个使用`@Injectable()`装饰器实现`NestMiddleware`接口的类。中间件在路由处理程序**之前**被调用。这些函数可以访问**请求**和**响应**对象，并且可以对请求和响应对象进行更改。

可以为路由配置一个或多个中间件函数，并且中间件函数可以选择将执行传递给堆栈上的下一个中间件函数，或者结束请求-响应周期。

如果中间件函数没有结束请求-响应周期，它必须调用`next()`将控制权传递给堆栈上的下一个中间件函数，或者如果它是堆栈上的最后一个函数，则传递给请求处理程序。未能这样做将使请求挂起。

例如，在我们的博客应用程序中，`AuthenticationMiddleware`负责对访问博客的用户进行身份验证。

```js
import {
    MiddlewareFunction,
    HttpStatus,
    Injectable,
    NestMiddleware
} from '@nestjs/common';
import * as passport from 'passport';
import { UserService } from '../../modules/user/user.service';

@Injectable()
export class AuthenticationMiddleware implements NestMiddleware {
    constructor(private userService: UserService) {}

    async resolve(strategy: string): Promise<MiddlewareFunction> {
        return async (req, res, next) => {
            return passport.authenticate(strategy, async (...args: any[]) => {
                const [, payload, err] = args;
                if (err) {
                    return res
                        .status(HttpStatus.BAD_REQUEST)
                        .send('Unable to authenticate the user.');
                }

                const user = await this.userService.findOne({
                    where: { email: payload.email }
                });
                req.user = user;
                return next();
            })(req, res, next);
        };
    }
}

```

如果身份验证失败，将向客户端发送 400 响应。如果身份验证成功，那么将调用`next()`，并且请求将继续通过中间件堆栈，直到到达请求处理程序。

中间件是在 Nest.js 模块的`configure()`函数中配置在路由上的。例如，上面的`AuthenticationMiddle`在`AppModule`中配置如下所示。

```js
@Module({
    imports: [
        DatabaseModule,
        AuthenticationModule.forRoot('jwt'),
        UserModule,
        EntryModule,
        CommentModule,
        UserGatewayModule,
        CommentGatewayModule,
        KeywordModule
    ],
    controllers: [],
    providers: []
})
export class AppModule implements NestModule {
    public configure(consumer: MiddlewareConsumer) {
        const userControllerAuthenticatedRoutes = [
            { path: '/users', method: RequestMethod.GET },
            { path: '/users/:id', method: RequestMethod.GET },
            { path: '/users/:id', method: RequestMethod.PUT },
            { path: '/users/:id', method: RequestMethod.DELETE }
        ];

        consumer
            .apply(AuthenticationMiddleware)
            .with(strategy)
            .forRoutes(
                ...userControllerAuthenticatedRoutes,
                EntryController,
                CommentController
            );
    }
}

```

您可以将中间件应用到控制器上的所有路由，就像`EntryController`和`CommentController`中所做的那样。您还可以根据路径将中间件应用到特定路由上，就像从`UserController`中的子集路由中所做的那样。

# 守卫

守卫是用`@Injectable()`装饰器修饰并实现`CanActivate`接口的类。守卫负责确定请求是否应该由路由处理程序或路由处理。守卫在每个中间件之后执行，但在管道之前执行。与中间件不同，守卫可以访问`ExecutionContext`对象，因此它们确切地知道将要评估的内容。

在我们的博客应用程序中，我们在`UserController`中使用`CheckLoggedInUserGuard`，只允许用户访问和访问自己的用户信息。

```js
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class CheckLoggedInUserGuard implements CanActivate {
    canActivate(
        context: ExecutionContext
    ): boolean | Promise<boolean> | Observable<boolean> {
        const req = context.switchToHttp().getRequest();
        return Number(req.params.userId) === req.user.id;
    }
}

```

`@UseGuards`装饰器用于将守卫应用到路由上。这个装饰器可以用在控制器类上，将守卫应用到该控制器的所有路由上，也可以用在控制器中的单个路由处理程序上，就像`UserController`中所示的那样：

```js
@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get(':userId')
    @UseGuards(CheckLoggedInUserGuard)
    show(@Param('userId') userId: number) {
        const user: User = this.userService.findById(userId);
        return user;
    }

```

# 总结

在本章中，我们介绍了 Nest.js 控制器、提供者、模块、引导和中间件。在下一章中，我们将介绍 Nest.js 身份验证。


# 第三章：Nest.js 认证

Nest.js，在版本 5 中，`@nestjs/passport` 软件包允许您实现所需的认证策略。当然，您也可以使用 `passport` 手动执行此操作。

在本章中，您将看到如何通过将其集成到 Nest.js 项目中来使用 passport。我们还将介绍策略是什么，以及如何配置策略以与 passport 一起使用。

我们还将使用认证中间件来管理限制访问，并查看守卫如何在用户访问处理程序之前检查数据。此外，我们将展示如何使用 Nest.js 提供的 passport 软件包，以涵盖两种可能性。

作为示例，我们将使用以下存储库文件：

+   `/src/authentication`

+   `/src/user`

+   `/shared/middlewares`

+   `/shared/guards`

# Passport

Passport 是一个众所周知的流行且灵活的库。事实上，passport 是一种灵活的中间件，可以完全自定义。Passport 允许不同的方式来验证用户，如以下方式：

+   `本地策略` 允许您仅使用自己的数据 `email` 和 `password` 来验证用户，在大多数情况下。

+   `jwt 策略` 允许您通过提供令牌并使用 `jsonwebtoken` 验证此令牌来验证用户。这种策略被广泛使用。

一些策略使用社交网络或 Google 来验证用户的配置文件，如 `googleOAuth`、`Facebook`，甚至 `Twitter`。

为了使用 passport，您必须安装以下软件包：`npm i passport`。在了解如何实现认证之前，您必须实现 `userService` 和 `userModel`。

# 手动实现

在本节中，我们将使用 passport 手动实现认证，而不使用 Nest.js 软件包。

## 实施

为了配置 passport，需要配置三件事：

+   认证策略

+   应用程序中间件

+   可选的会话

Passport 使用策略来验证请求，并且凭据的验证被委托给一些请求中的策略。

在使用 passport 之前，您必须配置策略，在这种情况下，我们将使用 `passport-jwt` 策略。

在任何其他操作之前，您必须安装适当的软件包：

+   `npm i passport-jwt @types/passport-jwt`

+   `npm i jsonwebtoken @types/jsonwebtoken`

### 认证模块

为了有一个可工作的示例，您必须实现一些模块，我们将从 `AuthenticationModule` 开始。`AuthenticationModule` 将使用 jwt 策略配置策略。为了配置策略，我们将扩展 `passport-jwt` 软件包提供的 `Strategy` 类。

#### 策略

这是一个扩展 `Strategy` 类以配置并在 passport 中使用的策略的示例。

```js
@Injectable()  
export default class JwtStrategy extends Strategy {  
   constructor(private readonly authenticationService: AuthenticationService) {  
       super({  
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),  
            passReqToCallback: true,  
            secretOrKey: 'secret'  
        }, async (req, payload, next) => {  
            return await this.verify(req, payload, next);  
        });  
        passport.use(this);  
    }  

   public async verify(req, payload, done) {  
       const isValid = await this.authenticationService.validateUser(payload);  
        if (!isValid) {  
           return done('Unauthorized', null);  
        } else {  
           return done(null, payload);  
        }  
   }  
}

```

构造函数允许您向扩展的 `Strategy` 类传递一些配置参数。在这种情况下，我们只使用了三个参数：

+   `jwtFromRequest` 选项接受一个函数，以从请求中提取令牌。在我们的情况下，我们使用 `passport-jwt` 软件包提供的 `ExtractJwt.fromAuthHeaderAsBearerToken()` 函数。此函数将从请求的标头中提取令牌，使用 `Authorization` 标头，并选择跟随 `bearer` 词的令牌。

+   `passReqToCallback` 参数接受一个布尔值，以便告诉您是否要在稍后看到的验证方法中获取 `req`。

+   `secretOrKey` 参数接受一个字符串或缓冲区，以验证令牌签名。

还有其他参数可用于配置策略，但为了实现我们的认证，我们不需要它们。

此外，在传递不同的先前参数之后，我们传递了一个名为`verify`的回调函数。这个函数是异步的，其目的是验证传递的令牌以及从令牌获得的载荷是否有效。此函数执行我们的`verify`方法，该方法调用`authenticationService`以验证具有载荷作为参数的用户。

如果用户有效，我们返回载荷，否则我们返回一个错误以指示载荷无效。

#### 身份验证服务

如前一节所示，为了验证从令牌中获取的载荷，调用`AuthenticationService`提供的`validateUser`方法。

事实上，该服务将实现另一种方法，以为已登录的用户生成令牌。该服务可以按照以下示例实现。

```js
@Injectable()  
export class AuthenticationService {  
   constructor(private readonly userService: UserService) { }  

   createToken(email: string, ttl?: number) {  
        const expiresIn = ttl || 60 * 60;  
        const secretOrKey = 'secret';  
        const user = { email };  
        const token = jwt.sign(user, secretOrKey, { expiresIn });  
        return {  
            expires_in: expiresIn,  
            access_token: token,  
        };  
   }  

   async validateUser(payload: { email: string; password: string }): Promise<boolean> {  
        const user = await this.userService.findOne({  
            where: { email: payload.email }  
        });  
        return !!user;  
   }  
}

```

服务注入了`UserService`，以便使用传递给`validateUser`方法的载荷来查找用户。如果载荷中的电子邮件允许您找到用户，并且该用户具有有效的令牌，她可以继续身份验证过程。

为了为尝试登录的用户提供令牌，实现`createToken`方法，该方法以`email`和可选的`ttl`作为参数。`ttl`（生存时间）将配置令牌在一段时间内有效。`ttl`的值以秒为单位表示，我们在`60 * 60`中定义了默认值，这意味着 1 小时。

#### 身份验证控制器

为了处理用户的身份验证，实现控制器并为登录端点提供处理程序。

```js
@Controller()  
export class AuthenticationController {  
   constructor(  
        private readonly authenticationService: AuthenticationService,  
        private readonly userService: UserService) {}  

   @Post('login')  
   @HttpCode(HttpStatus.OK)  
   public async login(@Body() body: any, @Res() res): Promise<any> {  
       if (!body.email || !body.password) {  
           return res.status(HttpStatus.BAD_REQUEST).send('Missing email or password.');  
       }  

       const user = await this.userService.findOne({  
           where: {  
               email: body.email,  
                password: crypto.createHmac('sha256', body.password).digest('hex')  
           }  
       });  
       if (!user) {  
           return res.status(HttpStatus.NOT_FOUND).send('No user found with this email and password.');  
       }  

       const result = this.authenticationService.createToken(user.email);  
       return res.json(result);  
    }  
}

```

控制器提供了登录处理程序，可通过在`POST /login`路由上调用来访问。该方法的目的是验证用户提供的凭据，以便在数据库中找到他。如果找到用户，则创建适当的令牌，并将其作为响应返回，其中`expiresIn`值对应于我们先前定义的`ttl`。否则，请求将被拒绝。

#### 模块

我们现在已经定义了我们的服务和策略，以配置 passport 并提供一些方法来创建令牌和验证载荷。让我们定义`AuthenticationModule`，它类似于以下示例。

```js
@Module({})  
export class AuthenticationModule {  
   static forRoot(strategy?: 'jwt' | 'OAuth' | 'Facebook'): DynamicModule {  
       strategy = strategy ? strategy : 'jwt';  
        const strategyProvider = {  
            provide: 'Strategy',  
            useFactory: async (authenticationService: AuthenticationService) => {  
                const Strategy = (await import (`./passports/${strategy}.strategy`)).default;  
                return new Strategy(authenticationService);  
            },  
            inject: [AuthenticationService]  
       };  
        return {  
            module: AuthenticationModule,  
            imports: [UserModule],  
            controllers: [AuthenticationController],  
            providers: [AuthenticationService, strategyProvider],  
            exports: [strategyProvider]  
        };  
    }  
}

```

如您所见，该模块不是作为普通模块定义的，因此在`@Module()`装饰器中没有定义组件或控制器。事实上，该模块是一个动态模块。为了提供多种策略，我们可以在类上实现一个静态方法，以便在另一个模块中导入时调用它。这个`forRoot`方法以您想要使用的策略的名称作为参数，并将创建一个`strategyProvider`，以便添加到返回模块的组件列表中。该提供程序将实例化策略并将`AuthenticationService`作为依赖项提供。

让我们继续创建一些需要保护的东西，比如`UserModule`。

### 用户模块

`UserModule`提供了一个服务、一个控制器和一个模型（请参阅 Sequelize 章节中的 User 模型）。我们在`UserService`中创建了一些方法，以便操作有关用户的数据。这些方法在`UserController`中使用，以向 API 的用户提供一些功能。

所有功能都不能被用户使用，或者在返回的数据中受到限制。

#### 用户服务

让我们来看一个`UserService`的例子和一些方法，以便访问和操作数据。本部分描述的所有方法将在控制器中使用，其中一些受身份验证限制。

```js
@Injectable()
export class UserService() {
    // The SequelizeInstance come from the DatabaseModule have a look to the Sequelize chapter
    constructor(@Inject('UserRepository') private readonly UserRepository: typeof User,
                @Inject('SequelizeInstance') private readonly sequelizeInstance) { }

    /* ... */
}

```

服务注入了我们在 Sequelize 章节中描述的`UserRepository`，以便访问模型和数据库中的数据存储。我们还注入了在 Sequelize 章节中描述的`SequelizeInstance`，以便使用事务。

`UserService`实现了`findOne`方法，以在`options`参数中传递条件查找用户。`options`参数可以如下所示：

```js
{
    where: {
        email: 'some@email.test',
        firstName: 'someFirstName'
    }
}

```

使用这些条件，我们可以找到相应的用户。该方法将只返回一个结果。

```js
@Injectable()
export class UserService() {
    /* ... */

    public async findOne(options?: object): Promise<User | null> {  
        return await this.UserRepository.findOne<User>(options);  
    }

    /* ... */
}

```

让我们实现`findById`方法，该方法以 ID 作为参数，以查找唯一的用户。

```js
@Injectable()
export class UserService() {
    /* ... */

    public async findById(id: number): Promise<User | null> {  
        return await this.UserRepository.findById<User>(id);  
    }  

    /* ... */
}

```

然后我们需要一种方法，在数据库中创建一个新用户，传递符合`IUser`接口的用户。正如您所看到的，该方法使用`this.sequelizeInstance.transaction`事务，以避免在一切完成之前读取数据。该方法将参数传递给`create`函数，该函数是`returning`，以获取已创建的用户实例。

```js
@Injectable()
export class UserService() {
    /* ... */

    public async create(user: IUser): Promise<User> {  
        return await this.sequelizeInstance.transaction(async transaction => {  
            return await this.UserRepository.create<User>(user, {  
                returning: true,  
                transaction,  
            });  
        });  
    }  

    /* ... */
}

```

当然，如果您可以创建用户，您也需要通过以下方法更新用户，遵循`IUser`接口。这个方法也将返回已更新的用户实例。

```js
@Injectable()
export class UserService() {
    /* ... */

    public async update(id: number, newValue: IUser): Promise<User | null> {  
        return await this.sequelizeInstance.transaction(async transaction => {  
            let user = await this.UserRepository.findById<User>(id, { transaction });  
            if (!user) throw new Error('The user was not found.');  

            user = this._assign(user, newValue);  
            return await user.save({  
                returning: true,  
                transaction,  
            });  
        });  
    }  

    /* ... */
}

```

为了在所有方法中进行一轮，我们将实现`delete`方法，从数据库中完全删除用户。

```js
@Injectable()
export class UserService() {
    /* ... */

    public async delete(id: number): Promise<void> {  
        return await this.sequelizeInstance.transaction(async transaction => {  
            return await this.UserRepository.destroy({  
                where: { id },  
                transaction,  
            });  
        });  
    }

    /* ... */
}

```

在所有先前的示例中，我们定义了一个完整的`UserService`，允许我们操作数据。我们有可能创建、读取、更新和删除用户。

#### 用户模型

如果您想查看用户模型的实现，可以参考 Sequelize 章节。

#### 用户控制器

现在我们已经创建了我们的服务和模型，我们需要实现控制器来处理来自客户端的所有请求。该控制器至少提供了一个创建、读取、更新和删除处理程序，应该像以下示例一样实现。

```js
@Controller()  
export class UserController {  
   constructor(private readonly userService: UserService) { }

   /* ... */
}

```

控制器注入了`UserService`，以使用`UserService`中实现的方法。

提供一个`GET users`路由，允许访问数据库中的所有用户，您将看到我们不希望用户访问所有用户的数据，只希望用户访问自己的数据。这就是为什么我们使用了一个守卫，只允许用户访问自己的数据。

```js
@Controller()  
export class UserController {  
    /* ... */

    @Get('users')  
    @UseGuards(CheckLoggedInUserGuard)
    public async index(@Res() res) {  
        const users = await this.userService.findAll();  
        return res.status(HttpStatus.OK).json(users);  
    }

    /* ... */
}

```

用户可以访问一个允许您创建新用户的路由。当然，如果您愿意，用户可以注册到已登录的应用程序中，我们必须允许那些没有限制的用户。

```js
@Controller()  
export class UserController {  
    /* ... */

    @Post('users')  
    public async create(@Body() body: any, @Res() res) {  
       if (!body || (body && Object.keys(body).length === 0)) throw new Error('Missing some information.');  

        await this.userService.create(body);  
        return res.status(HttpStatus.CREATED).send();  
    }  

    /* ... */
}

```

我们还提供了一个`GET users/:id`路由，允许您通过 ID 获取用户。当然，已登录用户不应该能够访问另一个用户的数据，即使通过这个路由。该路由也受到守卫的保护，以允许用户访问自己而不是其他用户。

```js
@Controller()  
export class UserController {  
    /* ... */

    @Get('users/:id')  
    @UseGuards(CheckLoggedInUserGuard)
    public async show(@Param() id: number, @Res() res) {  
       if (!id) throw new Error('Missing id.');  

        const user = await this.userService.findById(id);  
        return res.status(HttpStatus.OK).json(user);  
    }   

    /* ... */
}

```

用户可能想要更新自己的一些信息，这就是为什么我们通过以下`PUT users/:id`路由提供了一种更新用户的方式。这个路由也受到守卫的保护，以避免用户更新其他用户。

```js
@Controller()  
export class UserController {  
    /* ... */
    @Put('users/:id')  
    @UseGuards(CheckLoggedInUserGuard)
    public async update(@Param() id: number, @Body() body: any, @Res() res) {  
       if (!id) throw new Error('Missing id.');  

        await this.userService.update(id, body);  
        return res.status(HttpStatus.OK).send();  
    }

```

使用删除来完成最后一个处理程序。这个路由也必须受到守卫的保护，以避免用户删除另一个用户。唯一能够被用户删除的用户是他自己。

```js
    @Delete('users/:id')  
    @UseGuards(CheckLoggedInUserGuard)
    public async delete(@Param() id: number, @Res() res) {  
       if (!id) throw new Error('Missing id.');  

        await this.userService.delete(id);  
        return res.status(HttpStatus.OK).send();  
    }  
}

```

我们已经在这个控制器中实现了所有需要的方法。其中一些受到守卫的限制，以应用一些安全性，并防止用户操纵另一个用户的数据。

#### 模块

为了完成`UserModule`的实现，我们当然需要设置模块。该模块包含一个服务、一个控制器和一个提供者，允许您注入用户模型并提供一种操作存储数据的方式。

```js
@Module({  
    imports: [],  
    controllers: [UserController],  
    providers: [userProvider, UserService],
    exports: [UserService]  
})  
export class UserModule {}

```

该模块被导入到主`AppModule`中，就像`AuthenticationModule`一样，以便在应用程序中使用并可访问。

### 应用程序模块

`AppModule`导入了三个示例模块。

+   `DatabaseModule`访问 sequelize 实例并访问数据库。

+   `AuthenticationModule`允许您登录用户并使用适当的策略。

+   `UserModule`公开了一些可以由客户端请求的端点。

最后，该模块应该如以下示例所示。

```js
@Module({  
   imports: [  
        DatabaseModule,  
        // Here we specify the strategy
        AuthenticationModule.forRoot('jwt'),  
        UserModule  
    ]
})  
export class AppModule implements NestModule {  
   public configure(consumer: MiddlewaresConsumer) {  
       consumer  
           .apply(AuthenticationMiddleware)  
           .with(strategy)  
           .forRoutes(  
               { path: '/users', method: RequestMethod.GET },  
                { path: '/users/:id', method: RequestMethod.GET },  
                { path: '/users/:id', method: RequestMethod.PUT },  
                { path: '/users/:id', method: RequestMethod.DELETE }  
           );  
    }  
}

```

如你在这个例子中所看到的，我们已经将`AuthenticationMiddleware`应用到了我们想要保护不被未登录用户访问的路由上。

这个中间件的目的是应用 passport 中间件`passport.authenticate`，它验证用户提供的令牌，并将请求存储在头部作为`Authorization`值。这个中间件将使用策略参数来对应应该应用的策略，对我们来说是`strategy = 'jwt'`。

这个中间件应用于`UserController`的几乎所有路由，除了允许你创建新用户的`POST /users`。

## 身份验证中间件

如前一节所示，我们已经应用了`AuthenticationMiddleware`，并且我们已经看到 passport 是用于验证用户的中间件。这个中间件将使用策略`jwt`执行`passport.authenticate`方法，使用一个回调函数来返回验证方法的结果。因此，我们可以接收对应于令牌的有效负载，或者在验证不起作用的情况下收到错误。

```js
@Injectable()
export class AuthenticationMiddleware implements NestMiddleware {
    constructor(private userService: UserService) { }

    async resolve(strategy: string): Promise<ExpressMiddleware> {
        return async (req, res, next) => {
            return passport.authenticate(strategy, async (...args: any[]) => {
                const [,  payload, err] = args;
                if (err) {
                    return res.status(HttpStatus.BAD_REQUEST).send('Unable to authenticate the user.');
                }

                const user = await this.userService.findOne({ where: { email: payload.email }});
                req.user = user;
                return next();
            })(req, res, next);
        };
    }
}

```

如果身份验证成功，我们将能够将用户存储在请求`req`中，以便控制器或守卫使用。中间件实现了`NestMiddleware`接口，以实现解析函数。它还注入了`UserService`，以便找到已验证的用户。

## 使用守卫管理限制

Nest.js 带有一个守卫概念。这个可注入的守卫有一个单一的责任，就是确定请求是否需要由路由处理程序处理。

守卫用于实现`canActivate`接口的类，以实现`canActivate`方法。

守卫在每个中间件之后和任何管道之前执行。这样做的目的是将中间件的限制逻辑与守卫分开，并重新组织这个限制。

想象一下使用守卫来管理对特定路由的访问，并且你希望这个路由只能被已登录的用户访问。为此，我们实现了一个新的守卫，如果访问路由的用户与想要访问资源的用户相同，它必须返回`true`。使用这种类型的守卫，可以避免用户访问其他用户。

```js
@Injectable()
export class CheckLoggedInUserGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const request = context.switchToHttp().getRequest();
        return Number(req.params.userId) === req.user.id;
    }
}

```

正如你所看到的，你可以从上下文中获取处理程序，该上下文对应于应用守卫的控制器上的路由处理程序。你还可以从请求参数中获取`userId`，并将其与请求中注册的已登录用户进行比较。如果想要访问数据的用户是相同的，那么他可以访问请求参数中的引用，否则他将收到`403 Forbidden`。

要将守卫应用到路由处理程序，请参见以下示例。

```js
@Controller()
@UseGuards(CheckLoggedInUserGuard)  
export class UserController {/*...*/}

```

现在我们已经保护了所有的用户控制器的路由处理程序，它们都是可访问的，除了`delete`，因为用户必须是`admin`才能访问。如果用户没有适当的角色，他们将收到`403 Forbidden`的响应。

# Nest.js passport 包

`@nestjs/passport`包是一个可扩展的包，允许你在 Nest.js 中使用 passport 的任何策略。如前一节所示，可以手动实现身份验证，但如果想要更快地实现并包装策略，那么就使用这个好的包。

在本节中，你将看到使用`jwt`的包的用法，就像前一节所示的那样。要使用它，你必须安装以下包：

`npm install --save @nestjs/passport passport passport-jwt jsonwebtoken`

要使用这个包，你将有可能使用与前一节中实现的完全相同的`AuthenticationService`，但记得遵循下面的代码示例。

```js
@Injectable()  
export class AuthenticationService {  
   constructor(private readonly userService: UserService) { }  

   createToken(email: string, ttl?: number) {  
        const expiresIn = ttl || 60 * 60;  
        const secretOrKey = 'secret';  
        const user = { email };  
        const token = jwt.sign(user, secretOrKey, { expiresIn });  
        return {  
            expires_in: expiresIn,  
            access_token: token,  
        };  
   }  

   async validateUser(payload: { email: string; password: string }): Promise<boolean> {  
        const user = await this.userService.findOne({  
            where: { email: payload.email }  
        });  
        return !!user;  
   }  
}

```

要实例化 jwt 策略，你还需要实现 `JwtStrategy`，但现在你只需要传递选项，因为 passport 被包装在这个包中，并且会在幕后自动将策略应用于 passport。

```js
@Injectable()
export default class JwtStrategy extends PassportStrategy(Strategy) {  
   constructor(private readonly authenticationService: AuthenticationService) {  
       super({  
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),  
            passReqToCallback: true,  
            secretOrKey: 'secret'  
        });
    }  

   public async validate(req, payload, done) {  
       const isValid = await this.authenticationService.validateUser(payload);  
        if (!isValid) {  
           return done('Unauthorized', null);  
        } else {  
           return done(null, payload);  
        }  
   }  
}

```

正如你所看到的，在这个新的 `JwtStrategy` 实现中，你不再需要实现回调。这是因为现在你扩展了 `PassportStrategy(Strategy)`，其中 `Strategy` 是从 `passport-jwt` 库中导入的成员。此外，`PassportStrategy` 是一个混合类，将调用我们实现并根据这个混合类的抽象成员命名的 `validate` 方法。该方法将被策略调用作为有效载荷的验证方法。

该包提供的另一个功能是 `AuthGuard`，它可以与 `@UseGuards(AuthGuard('jwt'))` 一起使用，以在特定控制器方法上启用身份验证，而不是使用我们在上一节中实现的中间件。

`AuthGuard` 接受策略名称作为参数，我们的示例中是 `jwt`，还可以接受遵循 `AuthGuardOptions` 接口的其他一些参数。该接口定义了三个可用的选项：

+   - `callback` 作为允许你实现自己逻辑的函数

+   - `property` 作为一个字符串，用于定义要添加到请求中并附加到经过身份验证的用户的属性的名称

+   你还看到了新的 `@nestjs/passport` 包，它允许你以更快的方式实现一些类，如 `AuthenticationService` 和 `JwtStrategy`，并能够使用该包提供的 `AuthGuard` 在任何控制器方法上验证任何用户。

默认情况下，`session` 被设置为 false，`property` 被设置为 user。默认情况下，回调将返回 `user` 或 `UnauthorizedException`。就是这样，现在你可以在任何控制器方法上验证用户并从请求中获取用户。

你唯一需要做的就是创建以下示例中的 `AuthModule`：

```js
@Module({
  imports: [UserModule],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}

```

正如你所看到的，现在不需要创建提供者来实例化策略，因为它现在被包装在这个包中。

# 摘要

在本章中，你已经学会了什么是 passport 以及配置 passport 不同部分的策略，以便验证用户并将其存储到请求中。你还学会了如何实现不同的模块，`AuthenticationModule` 和 `UserModule`，以便用户登录并提供一些用户可访问的端点。当然，我们已经通过 `AuthenticationMiddleware` 和 `CheckLoggedInUserGuard` 限制了对一些数据的访问，以提供更多安全性。

在下一章中，你将学习关于依赖注入模式的内容。

- `session` 作为布尔值


# 第四章：Nest.js 的依赖注入系统

本章概述了依赖注入（DI）模式，这是今天最大的框架经常使用的一种方式。这是一种保持代码清晰且易于使用的方法。通过使用此模式，您最终会得到更少耦合的组件和更多可重用的组件，这有助于加快开发过程时间。

在这里，我们将研究在模式存在之前使用注入的方法，以及注入如何随着时间的推移而改变，以使用 TypeScript 和装饰器的现代方法进行 Nest.js 注入。您还将看到显示此类模式优势的代码片段，以及框架提供的模块。

Nest.js 在架构上基于 Angular，并用于创建可测试、可扩展、松耦合和易于维护的应用程序。与 Angular 一样，Nest.js 有自己的依赖注入系统，这是框架的`core`的一部分，这意味着 Nest.js 不太依赖第三方库。

# 依赖注入概述

自`Typescript 1.5`引入装饰器的概念以来，您可以使用装饰器在不同对象或属性上提供的添加元数据进行`元编程`，例如`class`，`function`，`function parameters`或`class property`。元编程是使用描述对象的元数据编写一些代码或程序的能力。这种类型的程序允许您使用其自身的元数据修改程序的功能。在我们的情况下，这些元数据对我们很有兴趣，因为它有助于将某些对象注入到另一个对象中，其名称为依赖注入。

通过使用装饰器，您可以在与这些装饰器相关联的任何对象或属性上添加元数据。例如，这将定义接受装饰器的对象的类型，但它还可以定义函数所需的所有参数，这些参数在其元数据中描述。要获取或定义任何对象上的元数据，您还可以使用`reflect-metadata`库来操纵它们。

## 为什么使用依赖注入

使用依赖注入的真正好处在于，依赖对象与其依赖项之间的耦合度更低。通过提供注入器系统的框架，您可以管理对象而无需考虑它们的实例化，因为这由注入器来管理，后者旨在解决每个依赖对象的依赖关系。

这意味着更容易编写测试和模拟依赖项，这些测试更清晰和更易读。

## 没有依赖注入的情况下如何运作

让我们想象一个需要注入`UserService`的`AuthenticationService`。

这里是`UserService`：

```js
export class UserService() {
    private users: Array<User> = [{
        id: 1,
        email: 'userService1@email.com',
        password: 'pass'
    ]};

    public findOne({ where }: any): Promise<User> {
        return this.users
        .filter(u => {
            return u.email === where.email &&
            u.password === where.password;
        });
    }
}

```

还有`AuthenticationService`，它实例化所需的`UserService`：

```js
export class AuthenticationService {
    public userService: UserService;

    constructor() {
        this.userService = new UserService();
    }

    async validateAUser(payload: { email: string; password: string }): Promise<boolean> {
        const user = await this.userService.findOne({
            where: payload
        });
        return !!user;
    }
}

```

```js
const authenticationService = new AuthenticationService();

```

正如您所看到的，您必须在类本身中管理所有相关的依赖项，以便在`AuthenticationService`内部使用。

这种方法的缺点主要是`AuthenticationService`的不灵活性。如果要测试此服务，您必须考虑其自身的隐藏依赖项，当然，您不能在不同的类之间共享任何服务。

## 使用手动依赖注入的工作原理

现在让我们看看如何使用先前的`UserService`通过构造函数传递依赖项。

```js
// Rewritted AuthenticationService
export class AuthenticationService {
    /* 
 Declare at the same time the public 
 properties belongs to the class
 */
    constructor(public userService: UserService) { }
}

```

```js
// Now you can instanciate the AutheticationService like that
const userService = new UserService();
const authenticationService = new AuthenticationService(userService);

```

您可以轻松地通过所有对象共享`userService`实例，而不再是`AuthenticationService`必须创建`UserService`实例。

这使生活变得更容易，因为注入器系统将允许您执行所有这些操作，而无需实例化依赖项。让我们在下一节中使用前面的类来看看这一点。

## 依赖注入模式今天

今天，要使用依赖注入，你只需要使用 Typescript 提供的装饰器系统，并由你想要使用的框架实现。在我们的案例中，正如你将在工具章节中看到的那样，Nest.js 提供了一些装饰器，它们几乎什么都不做，只是在它们将被使用的对象或属性上添加一些元数据。

这些元数据将帮助框架意识到这些对象可以被操作，注入所需的依赖关系。

以下是`@Injectable()`装饰器的使用示例：

```js
@Injectable()
export class UserService { /*...*/ }

@Injectable()
export class AuthenticationService {
    constructor(private userService: UserService) { }
}

```

这个装饰器将被转译，并且将向其添加一些元数据。这意味着在类上使用装饰器后，你可以访问`design:paramtypes`，这允许注入器知道依赖于`AuthenticationService`的参数的类型。

通常，如果你想创建自己的类装饰器，这个装饰器将以`target`作为参数，表示你的类的`type`。在前面的例子中，`AuthenticationService`的类型就是`AuthenticationService`本身。这个自定义类装饰器的目的将是将目标注册到服务的`Map`中。

```js
export Component = () => {
    return (target: Type<object>) => {
        CustomInjector.set(target);
    };
}

```

当然，你已经看到了如何将服务注册到服务的 Map 中，那么让我们看看这可能是一个自定义注入器。这个注入器的目的将是将所有服务注册到 Map 中，并解决对象的所有依赖关系。

```js
export const CustomInjector = new class {
  protected services: Map<string, Type<any>> = new Map<string, Type<any>>();

  resolve<T>(target: Type<any>): T {
    const tokens = Reflect.getMetadata('design:paramtypes', target) || [];
    const injections = tokens.map(token => CustomInjector.resolve<any>(token));
    return new target(/*...*/injections);
  }

  set(target: Type<any>) {
    this.services.set(target.name, target);
  }
};

```

因此，如果你想实例化我们的`AuthenticationService`，它依赖于超级`UserService`类，你应该调用注入器来解决依赖关系，并返回所需对象的实例。

在下面的例子中，我们将通过注入器解决`UserService`，并将其传递到`AuthenticationService`的构造函数中，以便能够实例化它。

```js
const authenticationService = CustomInjector.resolve<AuthenticationService>(AuthenticationService);
const isValid = authenticationService.validateUser(/* payload */);

```

# Nest.js 依赖注入

从`@nestjs/common`中，你可以访问框架提供的装饰器，其中之一就是`@Module()`装饰器。这个装饰器是构建所有模块并在它们之间使用 Nest.js 依赖注入系统的主要装饰器。

你的应用程序将至少有一个模块，即主模块。在小型应用程序的情况下，应用程序可以只使用一个模块（主模块）。然而，随着应用程序的增长，你将不得不创建多个模块来为主模块安排应用程序。

从主模块中，Nest 将知道你已经导入的所有相关模块，然后创建应用程序树来管理所有的依赖注入和模块的范围。

为了做到这一点，`@Module()`装饰器遵循`ModuleMetadata`接口，该接口定义了允许配置模块的属性。

```js
export interface ModuleMetadata {  
    imports?: any[];  
    providers?: any[];  
    controllers?: any[];  
    exports?: any[];
    modules?: any[]; // this one is deprecated.
}

```

要定义一个模块，你必须注册所有存储在`providers`中的服务，这些服务将由 Nest.js 的`injector`实例化，以及可以注入提供者的`controllers`，这些提供者是通过`exports`属性注册到模块中的服务，或者由其他模块导出的服务。在这种情况下，这些服务必须在`imports`中注册。

如果一个模块没有导出可注入的内容，并且导出模块没有被导入到使用外部服务的相关模块中，那么就无法访问另一个模块中的可注入内容。

***Nest.js 如何创建依赖注入树？***

在前一节中，我们谈到了主模块，通常称为`AppModule`，它用于从`NestFactory.create`创建应用程序。从这里，Nest.js 将不得不注册模块本身，并且还将遍历导入到主模块的每个模块。

Nest.js 然后会为整个应用程序创建一个`container`，其中包含整个应用程序的`module`，`globalModule`和`dynamicModuleMetadata`。

在创建了容器之后，它将初始化应用程序，并在初始化期间实例化一个 `InstanceLoader` 和一个 `DependenciesScanner -> scanner.ts`，通过它，Nest.js 将有可能扫描与每个模块和元数据相关的所有模块。它这样做是为了解决所有的依赖关系，并生成所有模块和服务的实例及其自己的注入。

如果你想了解引擎的细节，我们建议你深入了解两个类：`InstanceLoader` 和 `DependenciesScanner`。

为了更好地理解这是如何工作的，看一个例子。

想象一下，你有三个模块：

+   `ApplicationModule`

+   `AuthenticationModule`

+   `UserModule`

应用程序将从 `ApplicationModule` 创建：

```js
@Module({
    imports: [UserModule, AuthenticationModule]
})
export class ApplicationModule {/*...*/}

```

这导入了 `AuthenticationModule`：

```js
@Module({
    imports: [UserModule],
    providers: [AuthenticationService]
})
export class AuthenticationModule {/*...*/}

@Injectable()
export class AuthenticationService {
    constructor(private userService: UserService) {}
}

```

以及 `UserModule`：

```js
@Module({
    providers: [UserService],
    exports: [UserService]
})
export class UserModule {/*...*/}

@Injectable()
export class UserService {/*...*/}

```

在这种情况下，`AuthenticationModule` 必须导入 `UserModule`，后者导出 `UserService`。

我们现在已经构建了应用程序的架构模块，并且需要创建应用程序，它将允许解决所有的依赖关系。

```js
const app = await NestFactory.create(ApplicationModule);

```

基本上，当你创建应用程序时，Nest.js 将：

+   扫描模块。

+   存储模块和一个空的作用域数组（用于主模块）。然后将作用域填充为导入此扫描模块的模块。

+   查看通过 `modules` 元数据相关的模块。

+   扫描模块的依赖项作为服务、控制器、相关模块和导出项，将它们存储在模块中。

+   将所有全局模块绑定到每个模块中的相关模块。

+   通过解析原型创建所有的依赖项，为每个依赖项创建一个实例。对于具有自己依赖项的依赖项，Nest.js 将以相同的方式解析它们，并将其包含在前一级中。

***全局模块呢？***

Nest.js 还提供了一个 `@Global()` 装饰器，允许 Nest 将它们存储在全局模块的 `Set` 中，并将其添加到相关模块的 `Set` 中。

这种类型的模块将使用 `__globalModule__` 元数据键进行注册，并添加到容器的 globalModule 集合中。然后它们将被添加到相关模块的 `Set` 中。有了全局模块，你可以允许将模块中的组件注入到另一个模块中，而无需将其导入到目标模块中。这避免了将一个可能被所有模块使用的模块导入到所有模块中。

这是一个例子：

```js
@Module({
    imports: [DatabaseModule, UserModule]
})
export class ApplicationModule {/*...*/}

```

```js
@Global()
@Module({
    providers: [databaseProvider],
    exports: [databaseProvider]
})
export class DatabaseModule {/*...*/}

```

```js
@Module({
    providers: [UserService],
    exports: [UserService]
})
export class UserModule {/*...*/}

@Injectable()
export class UserService {
    // SequelizeInstance is provided by the DatabaseModule store as a global module
    constructor(@Inject('SequelizeInstance') private readonly sequelizeInstance) {}
}

```

有了之前的所有信息，你现在应该对 Nest.js 依赖注入的机制很熟悉，并且对它们如何一起工作有了更好的理解。

# Nest.js 和 Angular DI 之间的区别

即使 Nest.js 在很大程度上基于 Angular，它们之间存在一个重大区别。在 Angular 中，每个服务都是单例，这与 Nest.js 相同，但是可以要求 Angular 提供服务的新实例。在 Angular 中，你可以使用 `@Injectable()` 装饰器的 `providers` 属性来注册模块中的提供者的新实例，并且仅对该组件可用。这对于避免通过不同组件覆盖某些属性非常有用。

# 总结

因此，总结一下，我们在本章中看到了如何在不使用依赖注入的情况下，对象是多么不灵活和难以测试。此外，我们还了解了如何实现依赖项注入的方法的演变，首先是通过将依赖项实现到依赖项中，然后通过手动将它们传递到构造函数来改变方法，最终到达注入器系统。然后通过解析树自动在构造函数中解析依赖项，这就是 Nest.js 如何使用这种模式。

在下一章中，我们将看到 Nest.js 如何使用 TypeORM，这是一个与多种不同关系数据库一起工作的对象关系映射（ORM）。


# 第五章：TypeORM

几乎每次在现实世界中使用 Nest.js 时，您都需要某种持久性来保存数据。也就是说，您需要将 Nest.js 应用程序接收到的数据保存在某个地方，并且您需要从某个地方读取数据，以便随后将该数据作为响应传递给 Nest.js 应用程序接收到的请求。

大多数情况下，“某个地方”将是一个数据库。

TypeORM 是一个与多种不同关系数据库一起工作的对象关系映射（ORM）。对象关系映射是一个工具，用于在对象（例如“Entry”或“Comment”，因为我们正在构建一个博客）和数据库中的表之间进行转换。

这种转换的结果是一个实体（称为数据传输对象），它知道如何从数据库中读取数据到内存（这样您就可以将数据作为请求的响应使用），以及如何从内存写入数据库（这样您就能够存储数据以备后用）。

TypeORM 在概念上类似于 Sequelize。TypeORM 也是用 TypeScript 编写的，并且广泛使用装饰器，因此它非常适合 Nest.js 项目。

我们显然将专注于将 TypeORM 与 Nest.js 一起使用，但 TypeORM 也可以在浏览器和服务器端使用，使用传统的 JavaScript 以及 TypeScript。

TypeORM 允许您同时使用数据映射器模式和活动记录模式。我们将专注于活动记录模式，因为它大大减少了在典型 Nest.js 架构上使用所需的样板代码量，就像本书中所解释的那样。

TypeORM 也可以与 MongoDB 一起工作，不过在这种情况下，使用专门的 NoSQL ORM，如 Mongoose，是更常见的方法。

# 使用哪种数据库

TypeORM 支持以下数据库：

+   MySQL

+   MariaDB

+   PostgreSQL

+   MS SQL Server

+   sql.js

+   MongoDB

+   Oracle（实验性）

考虑到在本书中我们已经使用 Sequelize 和 Mongoose 分别使用 PostgreSQL 和 MongoDB，我们决定使用 TypeORM 与 MariaDB。 

## 关于 MariaDB

MariaDB 是一个由 MySQL 的一些原始开发人员领导的开源、社区驱动的项目。它是从 Oracle 收购后保持其自由和开放性的 GNU 通用公共许可证下的 MySQL 分支。

该项目的最初想法是作为 MySQL 的一个可替代品。这在 5.5 版本之前基本上是正确的，而 MariaDB 保持了与 MySQL 相同的版本号。

尽管如此，从 10.0 版本开始，较新的版本略微偏离了这种方法。不过，MariaDB 仍然专注于与 MySQL 高度兼容，并共享相同的 API。

# 入门

当然，TypeORM 作为一个 npm 包进行分发。您需要运行`npm install typeorm @nestjs/typeorm`。

您还需要一个 TypeORM 数据库驱动程序；在这种情况下，我们将使用`npm install mysql`安装 MySQL/MariaDB。

TypeORM 还依赖于`reflect-metadata`，但幸运的是，我们之前已经安装了它，因为 Nest.js 也依赖于它，所以我们无需做其他事情。请记住，如果您在 Nest.js 上下文之外使用 TypeORM，您还需要安装这个依赖。

**注意：** 如果您还没有安装 Node.js，现在安装是一个好主意：`npm install --save-dev @types/node`。

## 启动数据库

为了连接到数据库，我们将使用 Docker Compose，使用官方的 MariaDB Docker 镜像来设置我们的本地开发环境。我们将指向`latest` Docker 镜像标签，这在撰写本文时对应于版本 10.2.14。

```js
version: '3'

volumes:
  # for persistence between restarts
  mariadb_data:

services:
  mariadb:
    image: mariadb:latest
    restart: always
    ports:
      - "3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: secret
      MYSQL_DATABASE: nestbook
      MYSQL_USER: nest
      MYSQL_PASSWORD: nest
    volumes:
        - mariadb_data:/var/lib/mysql

  api:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - NODE_ENV=development
    depends_on:
      - mariadb
    links:
      - mariadb
    environment:
      PORT: 3000
    ports:
      - "3000:3000"
    volumes:
      - .:/app
      - /app/node_modules
    command: >
      npm run start:dev

```

## 连接到数据库

现在我们有了一个连接 TypeORM 的数据库，让我们配置连接。

我们有几种配置 TypeORM 的方式。最直接的一种是在项目根文件夹中创建一个`ormconfig.json`文件，这对于入门非常有用。这个文件将在启动时被 TypeORM 自动抓取。

这是一个适合我们用例的示例配置文件（即使用 Docker Compose 与之前提出的配置）。

**ormconfig.json**

```js
{
  "type": "mariadb",
  "host": "mariadb",
  "port": 3306,
  "username": "nest",
  "password": "nest",
  "database": "nestbook",
  "synchronize": true,
  "entities": ["src/**/*.entity.ts"]
}

```

关于配置文件的一些说明：

+   属性`host`、`port`、`username`、`password`和`database`需要与`docker-compose.yml`文件中之前指定的属性匹配；否则，TypeORM 将无法连接到 MariaDB Docker 镜像。

+   `synchronize`属性告诉 TypeORM 在应用程序启动时是否创建或更新数据库模式，以便模式与代码中声明的实体匹配。将此属性设置为`true`很容易导致数据丢失，所以**在启用此属性之前，请确保你知道你在做什么**。

## 初始化 TypeORM

现在数据库正在运行，并且你能够成功地建立起它与我们的 Nest.js 应用之间的连接，我们需要指示 Nest.js 使用 TypeORM 作为一个模块。

由于我们之前安装的`@nest/typeorm`包，所以在我们的 Nest.js 应用程序中使用 TypeORM 就像在主应用程序模块（可能是`app.module.ts`文件）中导入`TypeOrmModule`一样简单。

```js
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    TypeOrmModule.forRoot(),
    ...
  ]
})

export class AppModule {}

```

# 建模我们的数据

使用 ORM 最好的一点可能是，你可以利用它们提供的建模抽象：基本上，它们允许我们思考我们的数据，并用属性（包括类型和关系）来塑造它，生成我们可以直接使用和操作的“对象类型”（并将它们连接到数据库表）。

这个抽象层可以让你摆脱编写特定于数据库的代码，比如查询、连接等。很多人喜欢不必为选择和类似的事情而苦苦挣扎；所以这个抽象层非常方便。

## 我们的第一个实体

在使用 TypeORM 时，这些对象抽象被称为*实体*。

实体基本上是映射到数据库表的类。

说到这里，让我们创建我们的第一个实体，我们将其命名为`Entry`。我们将使用这个实体来存储博客的条目（帖子）。我们将在`src/entries/entry.entity.ts`创建一个新文件；这样 TypeORM 就能够找到这个实体文件，因为在我们的配置中我们指定了实体文件将遵循`src/**/*.entity.ts`文件命名约定。

```js
import { Entity } from 'typeorm';

@Entity()
export class Entry {}

```

`@Entity()`装饰器来自`typeorm` npm 包，用于标记`Entry`类为一个实体。这样，TypeORM 就会知道它需要在我们的数据库中为这种对象创建一个表。

`Entry`实体还有点太简单了：我们还没有为它定义一个属性。我们可能需要像标题、正文、图片和日期这样的东西来记录博客条目，对吧？让我们来做吧！

```js
import { Entity, Column } from 'typeorm';

@Entity()
export class Entry {
  @Column() title: string;

  @Column() body: string;

  @Column() image: string;

  @Column() created_at: Date;
}

```

不错！我们为实体定义的每个属性都标有`@Column`装饰器。再次，这个装饰器告诉 TypeORM 如何处理属性：在这种情况下，我们要求每个属性都存储在数据库的一列中。

遗憾的是，这个实体将无法使用这段代码。这是因为每个实体都需要至少一个主列，而我们没有将任何列标记为主列。

我们最好为每个条目创建一个`id`属性，并将其存储在主列上。

```js
import { Entity, Column, PrimaryColumn } from 'typeorm';

@Entity()
export class Entry {
  @PrimaryColumn() id: number;

  @Column() title: string;

  @Column() body: string;

  @Column() image: string;

  @Column() created_at: Date;
}

```

啊，好多了！我们的第一个实体现在可以工作了。让我们来使用它！

# 使用我们的模型

当需要将请求连接到数据模型时，在 Nest.js 中的典型方法是构建专门的服务，这些服务作为与每个模型的“接触点”，并构建控制器，将服务与到达 API 的请求连接起来。让我们在以下步骤中遵循`模型 -> 服务 -> 控制器`的方法。

## 服务

在典型的 Nest.js 架构中，应用程序的重要工作是由服务完成的。为了遵循这种模式，创建一个新的`EntriesService`，用它来与`Entry`实体交互。

所以，让我们在这里创建一个新文件：**`src/entries/entries.service.ts`**

```js
import { Component } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { Entry } from './entry.entity';

@Injectable()
export class EntriesService {
  constructor(
    // we create a repository for the Entry entity
    // and then we inject it as a dependency in the service
    @InjectRepository(Entry) private readonly entry: Repository<Entry>
  ) {}

  // this method retrieves all entries
  findAll() {
    return this.entry.find();
  }

  // this method retrieves only one entry, by entry ID
  findOneById(id: number) {
    return this.entry.findOneById(id);
  }

  // this method saves an entry in the database
  create(newEntry: Entry) {
    this.entry.save(newEntry);
  }
}

```

服务的最重要部分是使用`Repository<Entry>`创建 TypeORM 存储库，然后在构造函数中使用`@InjectRepository(Entry)`进行注入。

顺便说一句，如果你在想，当处理 ORM 时，存储库可能是最常用的设计模式，因为它允许你将数据库操作抽象为对象集合。

回到最新的服务代码，一旦你创建并注入了 Entry 存储库，就可以使用它从数据库中`.find()`和`.save()`条目，以及其他操作。当我们为实体创建存储库时，这些有用的方法会被添加进来。

既然我们已经处理了数据模型和服务，现在让我们为最后一个链接编写代码：控制器。

## 控制器

让我们为 Entry 模型创建一个控制器，通过 RESTful API 将其暴露给外部世界。代码非常简单，你可以看到。

继续，在以下位置创建一个新文件：**`src/entries/entries.controller.ts`**

```js
import { Controller, Get, Post, Body, Param } from '@nestjs/common';

import { EntriesService } from './entry.service';

@Controller('entries')
export class EntriesController {
  constructor(private readonly entriesSrv: EntriesService) {}

  @Get()
  findAll() {
    return this.entriesSrv.findAll();
  }

  @Get(':entryId')
  findOneById(@Param('entryId') entryId) {
    return this.entriesSrv.findOneById(entryId);
  }

  @Post()
  create(@Body() entry) {
    return this.entriesSrv.create(entry);
  }
}

```

和往常一样，我们使用 Nest.js 依赖注入使`EntryService`在`EntryController`中可用。

## 构建一个新的模块

我们新实体端点工作的最后一步是在应用模块中包含实体、服务和控制器。我们不会直接这样做，而是遵循“分离模块”的方法，为我们的条目创建一个新模块，在那里导入所有必要的部分，然后在应用模块中导入整个模块。

因此，让我们创建一个名为：**`src/entries/entries.module.ts`**的新文件。

```js
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { Entry } from './entry.entity';
import { EntriesController } from './entry.controller';
import { EntriesService } from './entry.service';

@Module({
  imports: [TypeOrmModule.forFeature([Entry])],
  controllers: [EntriesController],
  components: [EntriesService],
})
export class EntriesModule {}

```

还记得当我们在本章的最初步骤中在`AppModule`中包含了`TypeOrmModule`吗？我们在那里使用了`TypeOrmModule.forRoot()`公式。然而，在这里我们使用了不同的公式：`TypeOrmModule.forFeature()`。

Nest.js TypeORM 实现中的这种区别允许我们在不同的模块中分离不同的功能（“特性”）。这样你就可以根据本书的架构章节中提出的一些想法和最佳实践来调整你的代码。

无论如何，让我们将新的`EntriesModule`导入到`AppModule`中。如果忽略了这一步，你的主应用模块将不会意识到`EntriesModule`的存在，你的应用将无法正常工作。

**`src/app.module.ts`**

```js
import { TypeOrmModule } from '@nestjs/typeorm';
import { EntriesModule } from './entries/entries.module';

@Module({
  imports: [
    TypeOrmModule.forRoot(),
    EntriesModule,
    ...
  ]
})

export class AppModule {}

```

就是这样！现在你可以向`/entities`发送请求，端点将调用数据库的写入和读取操作。

是时候让我们的数据库试试了！我们将向之前链接到数据库的端点发送一些请求，看看是否一切都按预期工作。

我们将从向`/entries`端点发送 GET 请求开始。显然，由于我们还没有创建任何条目，我们应该收到一个空数组作为响应。

```js
> GET /entries HTTP/1.1
> Host: localhost:3000
< HTTP/1.1 200 OK

[]

```

让我们创建一个新的条目。

```js
> GET /entries HTTP/1.1
> Host: localhost:3000
| {
|   "id": 1,
|   "title": "This is our first post",
|   "body": "Bla bla bla bla bla",
|   "image": "http://lorempixel.com/400",
|   "created_at": "2018-04-15T17:42:13.911Z"
| }

< HTTP/1.1 201 Created

```

成功！让我们通过 ID 检索新条目。

```js
> GET /entries/1 HTTP/1.1
> Host: localhost:3000
< HTTP/1.1 200 OK

{
  "id": 1,
  "title": "This is our first post",
  "body": "Bla bla bla bla bla",
  "image": "http://lorempixel.com/400",
  "created_at": "2018-04-15T17:42:13.911Z"
}

```

是的！我们之前的 POST 请求触发了数据库中的写入，现在这个最后的 GET 请求触发了对数据库的读取，并返回先前保存的数据！

现在让我们再次尝试检索所有条目。

```js
> GET /entries HTTP/1.1
> Host: localhost:3000
< HTTP/1.1 200 OK

[{
  "id": 1,
  "title": "This is our first post",
  "body": "Bla bla bla bla bla",
  "image": "http://lorempixel.com/400",
  "created_at": "2018-04-15T17:42:13.911Z"
}]

```

我们刚刚确认，对`/entries`端点的请求成功执行了数据库的读写操作。这意味着我们的 Nest.js 应用现在可以使用，因为几乎任何服务器应用程序的基本功能（即存储数据并根据需要检索数据）都正常工作。

# 改进我们的模型

尽管我们现在通过实体从数据库中读取和写入数据，但我们只编写了一个基本的初始实现；我们应该审查我们的代码，看看有什么可以改进的地方。

现在让我们回到实体文件`src/entries/entry.entity.ts`，看看我们可以做出什么样的改进。

## 自动生成的 ID

所有的数据库条目都需要有一个唯一的 ID。目前，我们只是依赖于客户端在创建实体时（发送 POST 请求时）发送的 ID，但这并不理想。

任何服务器端应用程序都将连接到多个客户端，所有这些客户端都无法知道哪些 ID 已经在使用，因此他们无法生成并发送每个 POST 请求的唯一 ID。

TypeORM 提供了几种为实体生成唯一 ID 的方法。第一种是使用`@PrimaryGeneratedColumn()`装饰器。通过使用它，您不再需要在 POST 请求的主体中包含 ID，也不需要在保存条目之前手动生成 ID。相反，每当您要求将新条目保存到数据库时，TypeORM 会自动为其生成 ID。

我们的代码看起来像下面这样：

```js
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn() id: number;

  @Column() title: string;

  @Column() body: string;

  @Column() image: string;

  @Column() created_at: Date;
}

```

值得一提的是，这些唯一的 ID 将以顺序方式生成，这意味着每个 ID 将比数据库中已有的最高 ID 高一个数字（生成新 ID 的确切方法将取决于数据库类型）。

TypeORM 还可以更进一步：如果将`"uuid"`参数传递给`@PrimaryGeneratedColumn()`装饰器，生成的值将看起来像一串随机的字母和数字，带有一些破折号，确保它们是唯一的（至少*相对*唯一）。

```js
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column() body: string;

  @Column() image: string;

  @Column() created_at: Date;
}

```

还要记得将`id`的类型从`number`更改为`string`！

## 条目是何时创建的？

在原始实体定义中，还预期从客户端接收`created_at`字段。然而，我们可以通过一些更多的 TypeORM 魔术装饰器轻松改进这一点。

让我们使用`@CreateDateColumn()`装饰器为每个条目动态生成插入日期。换句话说，您不需要在保存条目之前从客户端设置日期或手动创建日期。

让我们更新实体：

```js
import {
  Entity,
  Column,
  CreateDateColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column() body: string;

  @Column() image: string;

  @CreateDateColumn() created_at: Date;
}

```

不错，是吗？还想知道条目上次修改是什么时候，以及对其进行了多少次修订？同样，TypeORM 使这两者都很容易实现，并且不需要我们额外的代码。

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
} from 'typeorm';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column() body: string;

  @Column() image: string;

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

我们的实体现在将自动为我们处理修改日期，以及每次保存操作时的修订号。您可以跟踪对实体的每个实例所做的更改，而无需实现一行代码！

## 列类型

在我们的实体中使用装饰器定义列时，如上所述，TypeORM 将从使用的属性类型推断数据库列的类型。这基本上意味着当 TypeORM 找到以下行时

```js
@Column() title: string;

```

这将`string`属性类型映射到`varchar`数据库列类型。

这通常会很好地工作，但在某些情况下，我们可能需要更明确地指定要在数据库中创建的列的类型。幸运的是，TypeORM 允许使用非常少的开销来实现这种自定义行为。

要自定义列类型，请将所需类型作为字符串参数传递给`@Column()`装饰器。一个具体的例子是：

```js
@Column('text') body: string;

```

可以使用的确切列类型取决于您使用的数据库类型。

### `mysql` / `mariadb`的列类型

`int`、`tinyint`、`smallint`、`mediumint`、`bigint`、`float`、`double`、`dec`、`decimal`、`numeric`、`date`、`datetime`、`timestamp`、`time`、`year`、`char`、`varchar`、`nvarchar`、`text`、`tinytext`、`mediumtext`、`blob`、`longtext`、`tinyblob`、`mediumblob`、`longblob`、`enum`、`json`、`binary`、`geometry`、`point`、`linestring`、`polygon`、`multipoint`、`multilinestring`、`multipolygon`、`geometrycollection`

### `postgres`的列类型

`int`、`int2`、`int4`、`int8`、`smallint`、`integer`、`bigint`、`decimal`、`numeric`、`real`、`float`、`float4`、`float8`、`double precision`、`money`、`character varying`、`varchar`、`character`、`char`、`text`、`citext`、`hstore`、`bytea`、`bit`、`varbit`、`bit varying`、`timetz`、`timestamptz`、`timestamp`、`timestamp without time zone`、`timestamp with time zone`、`date`、`time`、`time without time zone`、`time with time zone`、`interval`、`bool`、`boolean`、`enum`、`point`、`line`、`lseg`、`box`、`path`、`polygon`、`circle`、`cidr`、`inet`、`macaddr`、`tsvector`、`tsquery`、`uuid`、`xml`、`json`、`jsonb`、`int4range`、`int8range`、`numrange`、`tsrange`、`tstzrange`、`daterange`

### `sqlite` / `cordova` / `react-native`的列类型

`int`、`int2`、`int8`、`integer`、`tinyint`、`smallint`、`mediumint`、`bigint`、`decimal`、`numeric`、`float`、`double`、`real`、`double precision`、`datetime`、`varying character`、`character`、`native character`、`varchar`、`nchar`、`nvarchar2`、`unsigned big int`、`boolean`、`blob`、`text`、`clob`、`date`

### `mssql`的列类型

`int`、`bigint`、`bit`、`decimal`、`money`、`numeric`、`smallint`、`smallmoney`、`tinyint`、`float`、`real`、`date`、`datetime2`、`datetime`、`datetimeoffset`、`smalldatetime`、`time`、`char`、`varchar`、`text`、`nchar`、`nvarchar`、`ntext`、`binary`、`image`、`varbinary`、`hierarchyid`、`sql_variant`、`timestamp`、`uniqueidentifier`、`xml`、`geometry`、`geography`

### `oracle`的列类型

`char`、`nchar`、`nvarchar2`、`varchar2`、`long`、`raw`、`long raw`、`number`、`numeric`、`float`、`dec`、`decimal`、`integer`、`int`、`smallint`、`real`、`double precision`、`date`、`timestamp`、`timestamp with time zone`、`timestamp with local time zone`、`interval year to month`、`interval day to second`、`bfile`、`blob`、`clob`、`nclob`、`rowid`、`urowid`

如果你还没有准备好承诺使用特定的数据库类型，并且希望为将来保持选择的开放性，那么使用不是每个数据库都可用的类型可能不是最好的主意。

## SQL 中的 NoSQL

TypeORM 还有一个最后的绝招：`simple-json`列类型，可以在每个支持的数据库中使用。使用它，你可以直接在关系数据库列中保存普通的 JavaScript 对象。是的，令人惊叹！

让我们在实体中使用一个新的`author`属性。

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
} from 'typeorm';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column('text') body: string;

  @Column() image: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

`simple-json`列类型允许您直接存储甚至复杂的 JSON 树，而无需首先定义一个模型。在您欣赏比传统的关系数据库结构更灵活的情况下，这可能会派上用场。

# 数据模型之间的关系

如果您一直跟着本章节，那么您将有一种通过 API 将新的博客条目保存到数据库中，然后再读取它们的方法。

接下来是创建第二个实体来处理每个博客条目中的评论，然后以这样的方式创建条目和评论之间的关系，以便一个博客条目可以有属于它的多个评论。

然后创建`Comments`实体。

**`src/comments/comment.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
} from 'typeorm';

@Entity()
export class Comment {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column('text') body: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

您可能已经注意到`Comment`实体与`Entry`实体非常相似。

接下来的步骤将是在条目和评论之间创建一个“一对多”的关系。为此，在`Entry`实体中包含一个新的属性，使用`@OneToMany()`装饰器。

**`src/entries/entry.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
  OneToMany,
} from 'typeorm';

import { Comment } from '../comments/comment.entity';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column('text') body: string;

  @Column() image: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @OneToMany(type => Comment, comment => comment.id)
  comments: Comment[];

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

“一对多”关系必须是双向的，因此您需要在`Comment`实体中添加一个反向关系“多对一”。这样，两者都将得到适当的“绑定”。

**`src/comments/comment.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
  ManyToOne,
} from 'typeorm';

import { Entry } from '../entries/entry.entity';

@Entity()
export class Comment {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column('text') body: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @ManyToOne(type => Entry, entry => entry.comments)
  entry: Entry;

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

我们传递给`@OneToMany()`和`@ManyToOne()`装饰器的第二个参数用于指定我们在另一个相关实体上创建的逆关系。换句话说，在`Entry`中，我们将相关的`Comment`实体保存在名为`comments`的属性中。这就是为什么在`Comment`实体定义中，我们将`entry => entry.comments`作为第二个参数传递给装饰器的原因，直到在`Entry`中存储评论。

**注意：**并非所有关系*需要*是双向的。“一对一”关系可以是单向的或双向的。在单向“一对一”关系的情况下，关系的所有者是声明它的一方，而另一个实体不需要知道关于第一个实体的任何信息。

就是这样！现在我们的每个条目都可以有多条评论。

## 如何存储相关实体

如果我们谈论代码，保存属于条目的评论的最直接的方法将是保存评论，然后保存包含新评论的条目。创建一个新的`Comments`服务来与实体交互，然后修改`Entry`控制器以调用该新的`Comments`服务。

让我们看看。这并不像听起来那么难！

这将是我们的新服务：

**`src/comments/comments.service.ts`**

```js
import { Component } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { Comment } from './comment.entity';

@Injectable()
export class CommentsService {
  constructor(
    @InjectRepository(Comment) private readonly comment: Repository<Comment>
  ) {}

  findAll() {
    return this.comment.find();
  }

  findOneById(id: number) {
    return this.comment.findOneById(id);
  }

  create(comment: Comment) {
    return this.comment.save(comment);
  }
}

```

代码看起来确实很熟悉，不是吗？这与我们已经拥有的`EntriesService`非常相似，因为我们为评论和条目提供了相同的功能。

这将是修改后的`Entries`控制器：

**`src/entries/entries.controller.ts`**

```js
import { Controller, Get, Post, Body, Param } from '@nestjs/common';

import { EntriesService } from './entries.service';
import { CommentsService } from '../comments/comments.service';

import { Entry } from './entry.entity';
import { Comment } from '../comments/comment.entity';

@Controller('entries')
export class EntriesController {
  constructor(
    private readonly entriesSrv: EntriesService,
    private readonly commentsSrv: CommentsService
  ) {}

  @Get()
  findAll() {
    return this.entriesSrv.findAll();
  }

  @Get(':entryId')
  findOneById(@Param('entryId') entryId) {
    return this.entriesSrv.findOneById(entryId);
  }

  @Post()
  async create(@Body() input: { entry: Entry; comments: Comment[] }) {
    const { entry, comments } = input;
    entry.comments: Comment[] = [];
    await comments.forEach(async comment => {
      await this.commentsSrv.create(comment);
      entry.comments.push(comment);
    });
    return this.entriesSrv.create(entry);
  }
}

```

简而言之，新的`create()`方法：

+   接收一个博客条目和属于该条目的评论数组。

+   在博客条目对象内创建一个新的空数组属性（名为`comments`）。

+   遍历接收到的评论，保存每一条评论，然后逐一将它们推送到`entry`的新`comments`属性中。

+   最后，保存了现在包含每条评论链接的`entry`。

### 以更简单的方式保存相关实体

我们上次编写的代码有效，但不太方便。

幸运的是，TypeORM 为我们提供了一种更简单的方法来保存相关实体：启用“级联”。

在实体中将`cascade`设置为`true`将意味着我们将不再需要单独保存每个相关实体；相反，将关系的所有者保存到数据库将同时保存这些相关实体。这样，我们以前的代码可以简化。

首先，让我们修改我们的`Entry`实体（它是关系的所有者）以启用级联。

**`src/entries/entry.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
  OneToMany,
} from 'typeorm';

import { Comment } from '../comments/comment.entity';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column('text') body: string;

  @Column() image: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @OneToMany(type => Comment, comment => comment.id, {
    cascade: true,
  })
  comments: Comment[];

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

这真的很简单：我们只需为`@OneToMany()`装饰器的第三个参数添加一个`{cascade: true}`对象。

现在，我们将重构`Entries`控制器上的`create()`方法。

**`src/entries/entries.controller.ts`**

```js
import { Controller, Get, Post, Body, Param } from '@nestjs/common';

import { EntriesService } from './entries.service';

import { Entry } from './entry.entity';
import { Comment } from '../comments/comment.entity';

@Controller('entries')
export class EntriesController {
  constructor(private readonly entriesSrv: EntriesService) {}

  @Get()
  findAll() {
    return this.entriesSrv.findAll();
  }

  @Get(':entryId')
  findAll(@Param('entryId') entryId) {
    return this.entriesSrv.findOneById(entryId);
  }

  @Post()
  async create(@Body() input: { entry: Entry; comments: Comment[] }) {
    const { entry, comments } = input;
    entry.comments = comments;
    return this.entriesSrv.create(entry);
  }
}

```

请将新控制器与我们以前的实现进行比较；我们已经摆脱了对`Comments`服务的依赖，以及对`create()`方法的迭代器。这使我们的代码更短，更清晰，这总是好的，因为它减少了引入错误的风险。

在这一部分，我们发现了如何保存彼此相关的实体，同时保存它们的关系。这对于我们相关实体的成功至关重要。干得好！

## 批量检索相关实体

现在我们知道如何保存一个实体并包含它的关系，我们将看看如何从数据库中读取一个实体以及它们的所有相关实体。

在这种情况下的想法是，当我们从数据库请求博客条目（只有一个）时，我们还会得到属于它的评论。

当然，由于你对博客一般情况比较熟悉（它们已经存在一段时间了，对吧？），你会意识到并不是所有的博客都会同时加载博客文章和评论；很多博客只有在你滚动到页面底部时才加载评论。

为了演示功能，我们将假设我们的博客平台将同时检索博客文章和评论。

我们需要修改`Entries`服务来实现这一点。再次强调，这将非常容易！

**`src/entries/entries.service.ts`**

```js
import { Component } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { Entry } from './entry.entity';

@Injectable()
export class EntriesService {
  constructor(
    @InjectRepository(Entry) private readonly entry: Repository<Entry>
  ) {}

  findAll() {
    return this.entry.find();
  }

  findOneById(id: number) {
    return this.entry.findOneById(id, { relations: ['comments'] });
  }

  create(newEntry: Entry) {
    this.entry.save(newEntry);
  }
}

```

我们只在`Entry`存储库的`findOneById()`方法的第二个参数中添加了`{ relations: ['comments'] }`。选项对象的`relations`属性是一个数组，因此我们可以检索出我们需要的任意多个关系。它也可以与任何`find()`相关方法一起使用（即`find()`、`findByIds()`、`findOne()`等等）。

## 懒惰关系

在使用 TypeORM 时，常规关系（就像我们迄今为止写的那样）是*急切*关系。这意味着当我们从数据库中读取实体时，`find*()`方法将返回相关的实体，而无需我们编写连接或手动读取它们。

我们还可以配置我们的实体将关系视为*懒惰*，这样相关的实体在我们说之前不会从数据库中检索出来。

这是通过将保存相关实体的字段类型声明为`Promise`而不是直接类型来实现的。让我们看看代码上的区别：

```js
// This relationship will be treated as eager
@OneToMany(type => Comment, comment => comment.id)
comments: Comment[];

// This relationship will be treated as lazy
@OneToMany(type => Comment, comment => comment.id)
comments: Promise<Comment[]>;

```

当然，使用懒惰关系意味着我们需要改变保存实体到数据库的方式。下一个代码块演示了如何保存懒惰关系。请注意`create()`方法。

**`src/entries/entries.controller.ts`**

```js
import { Controller, Get, Post, Body, Param } from '@nestjs/common';

import { EntriesService } from './entries.service';
import { CommentsService } from '../comments/comments.service';

import { Entry } from './entry.entity';
import { Comment } from '../comments/comment.entity';

@Controller('entries')
export class EntriesController {
  constructor(
    private readonly entriesSrv: EntriesService,
    private readonly commentsSrv: CommentsService
  ) {}

  @Get()
  findAll() {
    return this.entriesSrv.findAll();
  }

  @Get(':entryId')
  findAll(@Param('entryId') entryId) {
    return this.entriesSrv.findOneById(entryId);
  }

  @Post()
  async create(@Body() input: { entry: Entry; comments: Comment[] }) {
    const { entry, comments } = input;
    const resolvedComments = [];
    await comments.forEach(async comment => {
      await this.commentsSrv.create(comment);
      resolvedComments.push(comment);
    });
    entry.comments = Promise.resolve(resolvedComments);
    return this.entriesSrv.create(entry);
  }
}

```

通过以下方式使`create()`方法变为“懒惰”：

1.  初始化一个新的`resolvedComments`空数组。

1.  遍历请求中收到的所有评论，保存每一条评论，然后将其添加到`resolvedComments`数组中。

1.  当所有评论都被保存时，我们将一个 promise 分配给`entry`的`comments`属性，然后立即用第 2 步中构建的评论数组解决它。

1.  将带有相关评论的`entry`保存为已解决的 promise。

在保存之前将一个立即解决的 promise 分配为实体的值的概念并不容易理解。但是，由于 JavaScript 的异步性质，我们仍然需要诉诸于这一点。

话虽如此，请注意 TypeORM 对懒惰关系的支持仍处于实验阶段，因此请谨慎使用。

# 其他类型的关系

到目前为止，我们已经探讨了“一对多”的关系。显然，TypeORM 也支持“一对一”和“多对多”的关系。

## 一对一

以防你不熟悉这种关系，其背后的想法是一个实体的一个实例，只属于另一个实体的一个实例，而且只属于一个。

举个更具体的例子，假设我们要创建一个新的`EntryMetadata`实体来存储我们想要跟踪的新事物，比如，假设博客文章从读者那里得到的喜欢数量和每篇博客文章的短链接。

让我们从创建一个名为`EntryMetadata`的新实体开始。我们将把文件放在`/entry`文件夹中，与`entry.entity.ts`文件相邻。

**`src/entries/entry_metadata.entity.ts`**

```js
import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity()
export class EntryMetadata {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() likes: number;

  @Column() shortlink: string;
}

```

我们刚刚创建的实体非常简单：它只有常规的`uuid`属性，以及用于存储条目的`likes`和`shortlink`的两个其他属性。

现在让我们告诉 TypeORM 在每个`Entry`实例中包含一个`EntryMetadata`实体的实例。

**`src/entries/entry.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
  OneToMany,
  OneToOne,
  JoinColumn,
} from 'typeorm';

import { EntryMetadata } from './entry-metadata.entity';
import { Comment } from '../comments/comment.entity';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column('text') body: string;

  @Column() image: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @OneToOne(type => EntryMetadata)
  @JoinColumn()
  metadata: EntryMetadata;

  @OneToMany(type => Comment, comment => comment.id, {
    cascade: true,
  })
  comments: Comment[];

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

您可能已经注意到了`@JoinColumn()`装饰器。在“一对一”关系中使用这个装饰器是 TypeORM 所要求的。

### 双向一对一关系

此时，`Entry`和`EntryMetadata`之间的关系是单向的。在这种情况下，这可能已经足够了。

然而，假设我们想直接访问`EntryMetadata`实例，然后获取它所属的`Entry`实例的可能性。好吧，现在我们还不能做到；直到我们使关系双向为止。

因此，仅出于演示目的，我们将在`EntryMetadata`实例中包含到`Entry`实例的反向关系，以便你知道它是如何工作的。

**`src/entries/entry_metadata.entity.ts`**

```js
import { Entity, PrimaryGeneratedColumn, Column, OneToOne } from 'typeorm';

import { Entry } from './entry.entity';

@Entity()
export class EntryMetadata {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() likes: number;

  @Column() shortlink: string;

  @OneToOne(type => Entry, entry => entry.metadata)
  entry: Entry;
}

```

确保不要在第二个条目中包含`@JoinColumn()`装饰器。该装饰器应该只用在拥有者实体中；在我们的情况下，就是`Entry`中。

我们需要做的第二个调整是指向原始`@OneToOne()`装饰器中相关实体的位置。记住，我们刚刚看到这需要通过向装饰器传递第二个参数来完成，就像这样：

**`src/entries/entry.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  VersionColumn,
  OneToMany,
  OneToOne,
  JoinColumn,
} from 'typeorm';

import { EntryMetadata } from './entry-metadata.entity';
import { Comment } from '../comments/comment.entity';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column('text') body: string;

  @Column() image: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @OneToOne(type => EntryMetadata, entryMetadata => entryMetadata.entry)
  @JoinColumn()
  metadata: EntryMetadata;

  @OneToMany(type => Comment, comment => comment.id, {
    cascade: true,
  })
  comments: Comment[];

  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

就是这样！现在我们有了一个美丽的、工作正常的`Entry`和`EntryMetadata`实体之间的双向一对一关系。

顺便说一句，如果你想知道我们如何保存然后检索这两个相关的实体，我有好消息告诉你：它的工作方式与我们在本章前面看到的一对多关系相同。因此，要么像在本章前面介绍的那样手动操作，要么（我个人的最爱）使用“级联”来保存它们，并使用`find*()`来检索它们！

## 多对多

我们可以为我们的实体建立的最后一种关系类型被称为“多对多”。这意味着拥有实体的多个实例可以包含拥有实体的多个实例。

一个很好的例子可能是我们想要为我们的博客条目添加“标签”。一个条目可能有几个标签，一个标签可以用在几个博客条目中，对吧。这使得关系属于“多对多”类型。

我们将节省一些代码，因为这些关系的声明方式与“一对一”关系完全相同，只需将`@OneToOne()`装饰器更改为`@ManyToMany()`。

# 高级 TypeORM

让我们来看看安全。

## 首先是安全

如果你在本书的 Sequelize 章节中阅读过，你可能对生命周期钩子的概念很熟悉。在那一章中，我们使用`beforeCreate`钩子在将用户密码保存到数据库之前对其进行加密。

如果你想知道 TypeORM 中是否也存在这样的东西，答案是肯定的！尽管 TypeORM 文档将它们称为“监听器”。

因此，为了演示其功能，让我们编写一个非常简单的`User`实体，其中包含用户名和密码，并且在将其保存到数据库之前，我们将确保加密密码。我们将在 TypeORM 中使用的特定监听器称为`beforeInsert`。

```js
@Entity
export class User {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() username: string;

  @Column() password: string;

  @BeforeInsert()
  encryptPassword() {
    this.password = crypto.createHmac('sha256', this.password).digest('hex');
  }
}

```

## 其他监听器

一般来说，监听器是在 TypeORM 中特定事件发生时触发的方法，无论是与写相关还是与读相关。我们刚刚了解了`@BeforeInsert()`监听器，但我们还有其他一些可以利用的监听器：

+   `@AfterLoad()`

+   `@BeforeInsert()`

+   `@AfterInsert()`

+   `@BeforeUpdate()`

+   `@AfterUpdate()`

+   `@BeforeRemove()`

+   `@AfterRemove()`

## 组合和扩展实体

TypeORM 提供了两种不同的方式来减少实体之间的代码重复。其中一种遵循组合模式，而另一种遵循继承模式。

尽管很多作者都支持组合优于继承，但我们将在这里介绍这两种可能性，并让读者决定哪种更适合他/她自己的特定需求。

### 嵌入式实体

在 TypeORM 中组合实体的方式是使用一种称为嵌入式实体的工件。

嵌入式实体基本上是具有一些声明的表列（属性）的实体，可以包含在其他更大的实体中。

让我们以一个例子开始：在审查我们之前为`Entry`和`Comment`实体编写的代码之后，我们很容易看到（除其他外）有三个重复的属性：`created_at`，`modified_at`和`revision`。

创建一个“可嵌入”实体来保存这三个属性然后将它们嵌入到我们的原始实体中会是一个很好的主意。让我们看看如何做。

我们首先将创建一个`Versioning`实体（名称不太好，我知道，但应该能让您看到这个想法）带有这三个重复的属性。

**`src/common/versioning.entity.ts`**

```js
import { CreateDateColumn, UpdateDateColumn, VersionColumn } from 'typeorm';

export class Versioning {
  @CreateDateColumn() created_at: Date;

  @UpdateDateColumn() modified_at: Date;

  @VersionColumn() revision: number;
}

```

请注意，我们在这个实体中没有使用@Entity 装饰器。这是因为它不是一个“真正”的实体。把它想象成一个“抽象”实体，即一个我们永远不会直接实例化的实体，而是我们将用它来嵌入到其他可实例化的实体中，以便为它们提供一些可重用的功能。换句话说，从较小的部分组合实体。

因此，现在我们将把这个新的“可嵌入”实体嵌入到我们的两个原始实体中。

**`src/entries/entry.entity.ts`**

```js
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  OneToMany,
  OneToOne,
  JoinColumn,
} from 'typeorm';

import { EntryMetadata } from './entry-metadata.entity';
import { Comment } from '../comments/comment.entity';
import { Versioning } from '../common/versioning.entity';

@Entity()
export class Entry {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column() title: string;

  @Column('text') body: string;

  @Column() image: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @OneToOne(type => EntryMetadata, entryMetadata => entryMetadata.entry)
  @JoinColumn()
  metadata: EntryMetadata;

  @OneToMany(type => Comment, comment => comment.id, {
    cascade: true,
  })
  comments: Comment[];

  @Column(type => Versioning)
  versioning: Versioning;
}

```

**`src/comments/comment.entity.ts`**

```js
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

import { Versioning } from '../common/versioning.entity';

@Entity()
export class Comment {
  @PrimaryGeneratedColumn('uuid') id: string;

  @Column('text') body: string;

  @Column('simple-json') author: { first_name: string; last_name: string };

  @Column(type => Versioning)
  versioning: Versioning;
}

```

即使在这个非常简单的例子中，我们已经将两个原始实体从三个不同的属性减少到了一个！在`Entry`实体和`Comment`实体中，当我们调用它们的读取或写入方法时，`versioning`列将被`Versioning`嵌入实体内的属性实际替换。

### 实体继承

TypeORM 为在我们的实体之间重用代码提供了第二种选择，即使用实体继承。

如果您已经熟悉 TypeScript，那么当您考虑到实体只是带有一些装饰器的常规 TS 类时，实体继承就很容易理解（和实现）。

对于这个特定的例子，让我们假设我们基于 Nest.js 的博客已经在线上一段时间了，并且它已经相当成功。现在我们想要引入赞助博客条目，这样我们就可以赚一些钱并将它们投资到更多的书籍中。

问题是，赞助条目将与常规条目非常相似，但会有一些新属性：赞助商名称和赞助商网址。

在这种情况下，经过一番思考后，我们可能决定扩展我们的原始`Entry`实体并创建一个`SponsoredEntry`。

**`src/entries/sponsored-entry.entity.ts`**

```js
import { Entity, Column } from 'typeorm';

import { Entry } from './entry.entity';

@Entity()
export class SponsoredEntry extends Entry {
  @Column() sponsorName: string;

  @Column() sponsorUrl: string;
}

```

就是这样。我们从`SponsoredEntry`实体创建的任何新实例都将具有来自扩展的`Entry`实体的相同列，以及我们为`SponsoredEntry`定义的两个新列。

## 缓存

TypeORM 默认提供了一个缓存层。我们可以利用它，只需稍微增加一点开销。如果您正在设计一个预期会有大量流量和/或您需要尽可能获得最佳性能的 API，这一层将特别有用。

这两种情况都会因为使用更复杂的数据检索场景（例如复杂的`find*()`选项，大量相关实体等）而越来越受益于缓存。

在连接到数据库时，缓存需要显式激活。到目前为止，在我们的情况下，这将是我们在本章开头创建的`ormconfig.json`文件。

**ormconfig.json**

```js
{
  "type": "mariadb",
  "host": "db",
  "port": 3306,
  "username": "nest",
  "password": "nest",
  "database": "nestbook",
  "synchronize": true,
  "entities": ["src/**/*.entity.ts"],
  "cache": true
}

```

在连接上激活缓存层之后，我们需要将`cache`选项传递给我们的`find*()`方法，就像下面的例子中那样：

```js
this.entry.find({ cache: true });

```

上面的代码将使`.find()`方法在缓存值存在且未过期时返回缓存值，否则返回相应数据库表中的值。因此，即使在过期时间窗口内调用该方法三千次，实际上只会执行一次数据库查询。

TypeORM 在处理缓存时使用了一些默认值：

1.  默认的缓存生命周期是 1,000 毫秒（即 1 秒）。如果我们需要自定义过期时间，我们只需要将所需的生命周期作为值传递给选项对象的`cache`属性。在上面的例子中，`this.entry.find({ cache: 60000 })`将设置 60 秒的缓存 TTL。

1.  TypeORM 将在您已经使用的同一数据库中为缓存创建一个专用表。该表将被命名为`query-result-cache`。这并不是坏事，但如果我们有一个可用的 Redis 实例，它可以得到很大的改进。在缓存中，我们需要在`ormconfig.json`文件中包含我们的 Redis 连接详细信息：

**ormconfig.json**

```js
{
  "type": "mariadb",
  ...
  "cache": {
    "type": "redis",
    "options": {
      "host": "localhost",
      "port": 6379
    }
  }
}

```

这样我们可以在高负载下轻松提高 API 的性能。

## 构建查询

TypeORM 的存储库方法极大地隔离了我们查询的复杂性。它们提供了一个非常有用的抽象，使我们不需要关心实际的数据库查询。

然而，除了使用这些不同的`.find*()`方法之外，TypeORM 还提供了手动执行查询的方法。这在访问我们的数据时极大地提高了灵活性，但代价是需要我们编写更多的代码。

TypeORM 执行查询的工具是`QueryBuilder`。一个非常基本的例子可能涉及重构我们旧有的`findOneById()`方法，使其使用`QueryBuilder`。

**`src/entries/entries.service.ts`**

```js
import {getRepository} from "typeorm";
...

findOneById(id: number) {
  return getRepository(Entry)
    .createQueryBuilder('entry')
    .where('entry.id = :id', { id })
    .getOne();
}

...

```

另一个稍微复杂一些的情景是构建一个连接，以便还检索相关的实体。我们将再次回到我们刚刚修改以包括相关评论的`findOneById()`方法。

**`src/entries/entries.service.ts`**

```js
import {getRepository} from "typeorm";
...

findOneById(id: number) {
  return getRepository(Entry)
    .createQueryBuilder('entry')
    .where('entry.id = :id', { id })
    .leftJoinAndSelect('entry.comments', 'comment')
    .getOne();
}

...

```

## 从现有数据库构建我们的模型

直到这一点，我们从一个“干净”的数据库开始，然后创建我们的模型，将模型转换为数据库列的任务交给了 TypeORM。

这是“理想”的情况，但是...如果我们发现自己处于相反的情况下怎么办？如果我们已经有一个填充了表和列的数据库呢？

有一个很好的开源项目可以用于这个：[typeorm-model-generator](https://github.com/Kononnable/typeorm-model-generator)。它被打包为一个命令行工具，可以使用`npx`运行。

**注意：**如果您对此不熟悉，`npx`是一个随`npm` > 5.2 一起提供的命令，它允许我们在命令行中运行 npm 模块，而无需先安装它们。要使用它，您只需要在工具的常规命令之前加上`npx`。例如，如果我们想要使用 Angular CLI 在命令行中创建一个新项目，我们将使用`npx ng new PROJECT-NAME`。

当它被执行时，typeorm-model-generator 将连接到指定的数据库（它支持大致与 TypeORM 相同的数据库），并将根据我们作为命令行参数传递的设置生成实体。

由于这是一个仅适用于一些非常特定用例的有用工具，我们将在本书中略去配置细节。但是，如果您发现自己在使用这个工具，请前往[其 GitHub 存储库](https://github.com/Kononnable/typeorm-model-generator)查看。

# 总结

TypeORM 是一个非常有用的工具，使我们能够在处理数据库时进行大量的繁重工作，同时大大抽象了数据建模、查询和复杂的连接，从而简化了我们的代码。

由于 Nest.js 通过`@nest/typeorm`包提供了很好的支持，因此它也非常适合用于 Nest.js 项目。

本章涵盖的一些内容包括：

+   TypeORM 支持的数据库类型以及如何选择其中一种的一些建议。

+   如何将 TypeORM 连接到您的数据库。

+   什么是实体以及如何创建您的第一个实体。

+   从您的数据库中存储和检索数据。

+   利用 TypeORM 使处理元数据（ID、创建和修改日期等）更容易。

+   自定义数据库中列的类型以匹配您的需求。

+   建立不同实体之间的关系以及在从数据库读取和写入时如何处理它们。

+   更高级的程序，如通过组合或继承重用代码；连接到生命周期事件；缓存；以及手动构建查询。

总的来说，我们真的认为你对 Nest.js 越熟悉，就越有可能开始感觉写 TypeORM 代码更舒适，因为它们在一些方面看起来很相似，比如它们广泛使用 TypeScript 装饰器。

在下一章中，我们将介绍 Sequelize，这是一个基于 Promise 的 ORM。
