# NestJS：Node 渐进式框架（四）

> 原文：[`zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240`](https://zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：架构

现在您知道，Nest.js 基于与 Angular 相同的原则，因此将其结构与 Angular 类似是一个好主意。

在进入文件结构之前，我们将看到一些关于命名和如何结构化不同目录和文件的指南，以便使项目更易读和可维护。

我们将看一下两种不同类型项目的架构：

+   服务器应用程序

+   使用 `Angular universal` 与 Nest.js 和 Angular 6 创建更完整的应用程序

在本章结束时，您应该知道如何为服务器应用程序或具有客户端前端的完整应用程序结构化您的应用程序。 

# 命名约定的样式指南

在这部分，我们将看到可以使用的命名约定，以便具有更好的可维护性和可读性。对于每个装饰器，您应该使用带连字符的名称，后跟一个点和对应的装饰器或对象的名称。

## 控制器

控制器的命名应遵循以下原则：

***user.controller.ts***

```js
@Controller()
export class UserController { /* ... */ }

```

## 服务

服务的命名应遵循以下原则：

***user.service.ts***

```js
@Injectable()
export class UserService { /* ... */ }

```

## 模块

模块的命名应遵循以下原则：

***user.module.ts***

```js
@Module()
export class UserModule { /* ... */ }

```

## 中间件

中间件的命名应遵循以下原则：

***authentication.middleware.ts***

```js
@Injectable()
export class AuthenticationMiddleware { /* ... */ }

```

## 异常过滤器

异常过滤器的命名应遵循以下原则：

***forbidden.exception.ts***

```js
export class ForbiddenException { /* ... */ }

```

## 管道

管道的命名应遵循以下原则：

***validation.pipe.ts***

```js
@Injectable()
export class ValidationPipe { /* ... */ }

```

## 守卫

守卫的命名应遵循以下原则：

***roles.guard.ts***

```js
@Injectable()
export class RolesGuard { /* ... */ }

```

## 拦截器

拦截器的命名应遵循以下原则：

***logging.interceptor.ts***

```js
@Injectable()
export class LoggingInterceptor { /* ... */ }

```

## 自定义装饰器

自定义装饰器的命名应遵循以下原则：

***comment.decorator.ts***

```js
export const Comment: (data?: any, ...pipes: Array<PipeTransform<any>>) => {
    ParameterDecorator = createParamDecorator((data, req) => {
        return req.comment;
    }
};

```

## 网关

网关的命名应遵循以下原则：

***comment.gateway.ts***

```js
@WebSocketGateway()
export class CommentGateway {

```

## 适配器

适配器的命名应遵循以下原则：

***ws.adapter.ts***

```js
export class WsAdapter {

```

## 单元测试

单元测试的命名应遵循以下原则：

***user.service.spec.ts***

## 端到端测试

端到端测试的命名应遵循以下原则：

***user.e2e-spec.ts***

现在我们已经概述了 Nest.js 提供的工具，并制定了一些命名指南。我们现在可以进入下一部分了。

# 目录结构

拥有良好结构化的目录文件的项目非常重要，因为这样更易读、易懂且易于使用。

因此，让我们看看如何结构化我们的目录，以便更清晰。您将在以下示例中看到用于存储库的目录文件架构，该架构是使用前一节中描述的命名约定创建的。

## 服务器架构

对于服务器架构，您将看到一个用于存储库的建议架构，以便有清晰的目录。

### 完整概述

查看基本文件结构，不要深入细节：

```js
.
├── artillery/
├── scripts/
├── migrations/
├── src/
├── Dockerfile
├── README.md
├── docker-compose.yml
├── migrate.ts
├── nodemon.json
├── package-lock.json
├── package.json
├── tsconfig.json
├── tslint.json
└── yarn.lock

```

我们有四个文件夹用于存放服务器所需的所有文件：

+   `artillery` 目录，如果需要，可以包含所有用于测试 API 端点的场景。

+   `scripts` 目录将包含您在应用程序中需要使用的所有脚本。在我们的情况下，等待 `RabbitMQ` 使用的端口打开的脚本，以便 Nest.js 应用程序在启动之前等待。

+   `migrations` 目录存在是因为我们使用了 `sequelize`，并且编写了一些迁移文件，这些文件存储在该目录中。

+   `src` 目录，其中包含我们服务器应用的所有代码。

在存储库中，我们还有一个 `client` 目录。但在这种情况下，它仅用作 WebSocket 使用的示例。

### `src` 目录

`src`目录将包含所有应用程序模块、配置、网关等。让我们来看看这个目录：

```js
src
├── app.module.ts
├── main.cluster.ts
├── main.ts
├── gateways
│   ├── comment
│   └── user
├── modules
│   ├── authentication
│   ├── comment
│   ├── database
│   ├── entry
│   ├── keyword
│   └── user
└── shared
    ├── adapters
    ├── config
    ├── decorators
    ├── exceptions
    ├── filters
    ├── guards
    ├── interceptors
    ├── interfaces
    ├── middlewares
    ├── pipes
    └── transports

```

这个目录也必须被良好地构建。为此，我们创建了三个子目录，对应于所有放在`gateways`目录中的 Web 套接字网关。`modules`将包含应用程序所需的所有模块。最后，`shared`将包含所有共享内容，如其名称所示，与所有`adapters`、`config`文件和自定义装饰器的元素对应，这些元素可以在任何模块中使用而不属于特定的模块。

现在我们将深入研究模块目录。

#### 模块

您的应用程序的主要部分将被构建为一个模块。这个模块将包含许多不同的文件。让我们看看一个模块可以如何构建：

```js
src/modules
├── authentication
│   ├── authentication.controller.ts
│   ├── authentication.module.ts
│   ├── authentication.service.ts
│   ├── passports
│   │   └── jwt.strategy.ts
│   └── tests
│       ├── e2e
│       │   └── authentication.controller.e2e-spec.ts
│       └── unit
│           └── authentication.service.spec.ts
├── comment
│   ├── comment.controller.ts
│   ├── comment.entity.ts
│   ├── comment.module.ts
│   ├── comment.provider.ts
│   ├── comment.service.ts
│   ├── interfaces
│   │   ├── IComment.ts
│   │   ├── ICommentService.ts
│   │   └── index.ts
│   └── tests
│       ├── unit
│       │   └── comment.service.spec.ts
│       └── utilities.ts
├── database
│   ├── database-utilities.service.ts
│   ├── database.module.ts
│   └── database.provider.ts
├── entry
│   ├── commands
│   │   ├── handlers
│   │   │   ├── createEntry.handler.ts
│   │   │   ├── deleteEntry.handler.ts
│   │   │   ├── index.ts
│   │   │   └── updateEntry.handler.ts
│   │   └── impl
│   │       ├── createEntry.command.ts
│   │       ├── deleteEntry.command.ts
│   │       └── updateEntry.command.ts
│   ├── entry.controller.ts
│   ├── entry.entity.ts
│   ├── entry.model.ts
│   ├── entry.module.ts
│   ├── entry.provider.ts
│   ├── entry.service.ts
│   ├── interfaces
│   │   ├── IEntry.ts
│   │   ├── IEntryService.ts
│   │   └── index.ts
│   └── tests
│       ├── unit
│       │   └── entry.service.spec.ts
│       └── utilities.ts
├── keyword
│   ├── commands
│   │   ├── handlers
│   │   │   ├── index.ts
│   │   │   ├── linkKeywordEntry.handler.ts
│   │   │   └── unlinkKeywordEntry.handler.ts
│   │   └── impl
│   │       ├── linkKeywordEntry.command.ts
│   │       └── unlinkKeywordEntry.command.ts
│   ├── events
│   │   ├── handlers
│   │   │   ├── index.ts
│   │   │   └── updateKeywordLinks.handler.ts
│   │   └── impl
│   │       └── updateKeywordLinks.event.ts
│   ├── interfaces
│   │   ├── IKeyword.ts
│   │   ├── IKeywordService.ts
│   │   └── index.ts
│   ├── keyword.controller.ts
│   ├── keyword.entity.ts
│   ├── keyword.module.ts
│   ├── keyword.provider.ts
│   ├── keyword.sagas.ts
│   ├── keyword.service.ts
│   └── keywordEntry.entity.ts
└── user
    ├── interfaces
    │   ├── IUser.ts
    │   ├── IUserService.ts
    │   └── index.ts
    ├── requests
    │   └── create-user.request.ts
    ├── tests
    │   ├── e2e
    │   │   └── user.controller.e2e-spec.ts
    │   ├── unit
    │   │   └── user.service.spec.ts
    │   └── utilities.ts
    ├── user.controller.ts
    ├── user.entity.ts
    ├── user.module.ts
    ├── user.provider.ts
    └── user.service.ts

```

在我们的存储库中，有许多模块。其中一些还实现了`cqrs`，它与模块位于同一个目录，因为它涉及到模块并且是其一部分。`cqrs`部分分为`commands`和`events`目录。模块还可以定义一些接口，这些接口放在单独的`interfaces`目录中。单独的目录使我们能够更清晰地阅读和理解，而不必将许多不同的文件混在一起。当然，所有涉及模块的测试也包括在它们自己的`tests`目录中，并分为`unit`和`e2e`。

最后，定义模块本身的主要文件，包括可注入对象、控制器和实体，都在模块的根目录中。

在本节中，我们已经看到了如何以更清晰和更易读的方式构建我们的服务器应用程序的结构。现在您知道应该把所有模块放在哪里，以及如何构建一个模块，以及如果使用它们，应该把网关或共享文件放在哪里。

## Angular Universal 架构

存储库的 Angular Universal 部分是一个独立的应用程序，使用 Nest.js 服务器和 Angular 6。它将由两个主要目录组成：`e2e`用于端到端测试，以及包含服务器和客户端的`src`。

让我们首先看一下这个架构的概述：

```js
├── e2e/
├── src/
├── License
├── README.md
├── angular.json
├── package.json
├── tsconfig.json
├── tslint.json
├── udk.container.js
└── yarn.lock

```

### `src`目录

这个目录将包含`app`目录，以便使用模块化的 Angular 架构放置我们的客户端内容。此外，我们还将找到`environments`，它定义了我们是否处于生产模式，并导出常量。这个环境将被生产环境配置替换为生产模式，然后是`server`和`shared`目录。共享目录允许我们共享一些文件，例如接口，而服务器目录将包含所有服务器应用程序，就像我们在前一节中看到的那样。

但在这种情况下，服务器有些变化，现在看起来是这样的：

```js
├── main.ts
├── app.module.ts
├── environments
│   ├── environment.common.ts
│   ├── environment.prod.ts
│   └── environment.ts
└── modules
    ├── client
    │   ├── client.constants.ts
    │   ├── client.controller.ts
    │   ├── client.module.ts
    │   ├── client.providers.ts
    │   ├── interfaces
    │   │   └── angular-universal-options.interface.ts
    │   └── utils
    │       └── setup-universal.utils.ts
    └── heroes
        ├── heroes.controller.ts
        ├── heroes.module.ts
        ├── heroes.service.ts
        └── mock-heroes.ts

```

modules 目录将包含所有的 Nest.js 模块，就像我们在前一节中看到的那样。其中一个模块是`client`模块，将为 Universal 应用程序提供所有必需的资产，并设置初始化程序以设置引擎并提供一些 Angular 配置。

关于`environments`，这个目录将包含与 Angular 应用程序相关的所有配置路径。这个配置引用了在前一节项目的基础中看到的`angular.json`文件中配置的项目。

# 总结

这一章让您以更易理解、易读和易于处理的方式设置应用程序的架构。我们已经看到了如何为服务器应用程序定义架构目录，以及如何使用 Angular Universal 构建完整应用程序。通过这两个示例，您应该能够以更清晰的方式构建自己的项目。

下一章将展示如何在 Nest.js 中使用测试。


# 第十四章：测试

自动化测试是软件开发的关键部分。尽管它不能（也不打算）取代手动测试和其他质量保证方法。当正确使用时，自动化测试是一个非常有价值的工具，可以避免回归、错误或不正确的功能。

软件开发是一门棘手的学科：尽管许多开发人员试图隔离软件的不同部分，但往往不可避免地，一些拼图的部分会对其他部分产生影响，无论是有意还是无意。

使用自动化测试的主要目标之一是检测新代码可能破坏先前工作功能的错误类型。这些测试被称为*回归测试*，当作为合并或部署过程的一部分触发时，它们是最有意义的。这意味着，如果自动化测试失败，合并或部署将被中断，从而避免向主代码库或生产环境引入新错误。

自动化测试还可以实现一种被称为*测试驱动开发（TDD）*的开发工作流程。在遵循 TDD 方法时，自动化测试是事先编写的，作为反映需求的非常具体的案例。新测试编写完成后，开发人员运行*所有测试*；新测试应该失败，因为尚未编写新代码。在这一点上，新代码必须被编写，以便新测试通过，同时不破坏旧测试。

如果正确执行测试驱动开发方法，可以提高对代码质量和需求符合的信心。它们还可以使重构甚至完整的代码迁移变得不那么冒险。

在本书中，我们将涵盖两种主要类型的自动化测试：单元测试和端到端测试。

# 单元测试

顾名思义，每个单元测试覆盖一个特定的功能。处理单元测试时最重要的原则是：

+   **隔离；**每个组件必须在没有任何其他相关组件的情况下进行测试；它不能受到副作用的影响，同样，它也不能产生任何副作用。

+   **可预测性；**每个测试必须产生相同的结果，只要输入不改变。

在许多情况下，遵守这两个原则意味着*模拟*（即模拟组件依赖的功能）。

## 工具

与 Angular 不同，Nest.js 没有用于运行测试的“官方”工具集；这意味着我们可以自由设置我们自己的工具，用于在 Nest.js 项目中运行自动化测试。

JavaScript 生态系统中有多个专注于编写和运行自动化单元测试的工具。典型的解决方案涉及使用多个不同的包进行设置，因为这些包在范围上受限（一个用于测试运行，第二个用于断言，第三个用于模拟，甚至可能还有一个用于代码覆盖报告）。

然而，我们将使用[ Jest ](https://facebook.github.io/jest/)，这是来自 Facebook 的“一体化”，“零配置”测试解决方案，大大减少了运行自动化测试所需的配置工作量。它还官方支持 TypeScript，因此非常适合 Nest.js 项目！

## 准备

正如您所期望的，Jest 被分发为一个 npm 包。让我们在我们的项目中安装它。从命令行或终端运行以下命令：

```js
npm install --save-dev jest ts-jest @types/jest

```

我们正在安装三个不同的 npm 包作为开发依赖项：Jest 本身；`ts-jest`，它允许我们在 TypeScript 代码中使用 Jest；以及 Jest 的类型定义，对于我们的 IDE 体验做出了宝贵的贡献！

还记得我们提到 Jest 是一个“零配置”测试解决方案吗？这是他们主页上宣称的。不幸的是，这并不完全正确：在我们能够运行测试之前，我们仍然需要定义一些配置。在我们的情况下，这主要是因为我们使用了 TypeScript。另一方面，我们需要编写的配置实际上并不多，所以我们可以将其编写为一个普通的 JSON 对象。

所以，让我们在项目的根文件夹中创建一个名为 `nest.json` 的新的 JSON 文件。

**`/nest.json`**

```js
{
  "moduleFileExtensions": ["js", "ts", "json"],
  "transform": {
    "^.+\\.ts": "<rootDir>/node_modules/ts-jest/preprocessor.js"
  },
  "testRegex": "/src/.*\\.(test|spec).ts",
  "collectCoverageFrom": [
    "src/**/*.ts",
    "!**/node_modules/**",
    "!**/vendor/**"
  ],
  "coverageReporters": ["json", "lcov", "text"]
}

```

这个小的 JSON 文件设置了以下配置：

1.  将 `.js`、`.ts` 和 `.json` 文件作为我们应用程序的模块（即代码）进行了配置。你可能会认为我们不需要 `.js` 文件，但事实上，由于 Jest 自身的一些依赖关系，我们的代码没有这个扩展名就无法运行。

1.  告诉 Jest 使用 `ts-jest` 包处理扩展名为 `.ts` 的文件（这个包在之前已经从命令行安装过）。

1.  指定我们的测试文件将位于 `/src` 文件夹中，并且将具有 `.test.ts` 或 `.spec.ts` 文件扩展名。

1.  指示 Jest 从 `/src` 文件夹中的任何 `.ts` 文件生成代码覆盖报告，同时忽略 `node_modules` 和 `vendor` 文件夹中的内容。此外，生成的覆盖报告格式为 `JSON` 和 `LCOV`。

最后，在我们开始编写测试之前的最后一步是向你的 `package.json` 文件中添加一些新的脚本：

```js
{
  ...
  "scripts": {
    ...
    "test": "jest --config=jest.json",
    "test:watch": "jest --watch --config=jest.json",
    ...
  }
}

```

这三个新的脚本将分别：运行一次测试，以观察模式运行测试（它们将在每次文件保存后运行），以及运行测试并生成代码覆盖报告（将输出到一个 `coverage` 文件夹中）。

**注意：** Jest 将其配置作为 `package.json` 文件中的 `jest` 属性接收。如果你决定以这种方式做事情，你将需要在你的 npm 脚本中省略 `--config=jest.json` 参数。

我们的测试环境已经准备好了。如果我们现在在项目文件夹中运行 `npm test`，我们很可能会看到以下内容：

```js
No tests found
In /nest-book-example
  54 files checked.
  testMatch:  - 54 matches
  testPathIgnorePatterns: /node_modules/ - 54 matches
  testRegex: /src/.*\.(test|spec).ts - 0 matches
Pattern:  - 0 matches
npm ERR! Test failed.  See above for more details.

```

测试失败了！好吧，其实并没有失败；我们只是还没有写任何测试！现在让我们来写一些测试。

## 编写我们的第一个测试

如果你已经阅读了本书的更多章节，你可能还记得我们的博客条目以及我们为它们编写的代码。让我们回顾一下 `EntryController`。根据章节的不同，代码看起来可能是这样的：

**`/src/modules/entry/entry.controller.ts`**

```js
import { Controller, Get, Post, Param } from '@nestjs/common';

import { EntriesService } from './entry.service';

@Controller('entries')
export class EntriesController {
  constructor(private readonly entriesSrv: EntriesService) {}

  @Get()
  findAll() {
    return this.entriesSrv.findAll();
  }
  ...
}

```

请注意，这个控制器是 `EntriesService` 的一个依赖项。由于我们提到每个组件都必须在*隔离*中进行测试，我们需要模拟它可能具有的任何依赖项；在这种情况下，是 `EntriesService`。

让我们为控制器的 `findAll()` 方法编写一个单元测试。我们将使用一个名为 `@nestjs/testing` 的特殊 Nest.js 包，它将允许我们为测试专门包装我们的服务在一个 Nest.js 模块中。

此外，遵循约定并将测试文件命名为 `entry.controller.spec.ts`，并将其放在 `entry.controller.ts` 文件旁边，这样当我们触发测试运行时 Jest 就能正确地检测到它。

**`/src/modules/entry/entry.controller.spec.ts`**

```js
import { Test } from '@nestjs/testing';
import { EntriesController } from './entry.controller';
import { EntriesService } from './entry.service';

describe('EntriesController', () => {
  let entriesController: EntriesController;
  let entriesSrv: EntriesService;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      controllers: [EntriesController],
    })
      .overrideComponent(EntriesService)
      .useValue({ findAll: () => null })
      .compile();

    entriesSrv = module.get<EntriesService>(EntriesService);
    entriesController = module.get<EntriesController>(EntriesController);
  });
});

```

现在让我们仔细看一下测试代码实现了什么。

首先，我们在 `describe('EntriesController', () => {` 上声明了一个测试套件。我们还声明了一些变量，`entriesController` 和 `entriesSrv`，分别用来保存被测试的控制器本身以及控制器所依赖的服务。

接下来是 `beforeEach` 方法。该方法中的代码将在每个测试运行之前执行。在这段代码中，我们为每个测试实例化了一个 Nest.js 模块。请注意，这是一种特殊类型的模块，因为我们使用了来自 `@nestjs/testing` 包的 `Test` 类的 `.createTestingModule()` 方法。因此，让我们把这个模块看作是一个“模拟模块”，它只用于测试目的。

现在是有趣的部分：我们在测试模块中将`EntriesController`作为控制器包含进来。然后我们继续使用：

```js
.overrideComponent(EntriesService)
.useValue({ findAll: () => null })

```

这替换了原始的`EntryService`，它是我们测试的控制器的一个依赖项。这是服务的模拟版本，甚至不是一个类，因为我们不需要它是一个类，而是一个没有参数并返回 null 的`findAll`方法的对象。

您可以将上述两行代码的结果视为一个空的、愚蠢的服务，它只重复我们以后需要使用的方法，而没有任何实现内部。

最后，`.compile()`方法是实际实例化模块的方法，因此它绑定到`module`常量。

一旦模块正确实例化，我们就可以将先前的`entriesController`和`entriesSrv`变量绑定到模块内控制器和服务的实例上。这是通过调用`module.get`方法实现的。

一旦所有这些初始设置都完成了，我们就可以开始编写一些实际的测试了。让我们实现一个检查我们的控制器中的`findAll()`方法是否正确返回条目数组的测试，即使我们只有一个条目：

```js
import { Test } from '@nestjs/testing';
import { EntriesController } from './entry.controller';
import { EntriesService } from './entry.service';

describe('EntriesController', () => {
  let entriesController: EntriesController;
  let entriesSrv: EntriesService;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      controllers: [EntriesController],
    })
      .overrideComponent(EntriesService)
      .useValue({ findAll: () => null })
      .compile();

    entriesSrv = module.get<EntriesService>(EntriesService);
    entriesController = module.get<EntriesController>(EntriesController);
  });

  describe('findAll', () => {
    it('should return an array of entries', async () => {
      expect(Array.isArray(await entriesController.findAll())).toBe(true);
    });
  });
});

```

`describe('findAll', () => {`行是开始实际测试套件的行。我们期望`entriesController.findAll()`的解析值是一个数组。这基本上是我们最初编写代码的方式，所以应该可以工作，对吧？让我们用`npm test`运行测试并检查测试输出。

```js
FAIL  src/modules/entry/entry.controller.spec.ts
  EntriesController
    findAll
      ✕ should return an array of entries (4ms)

  ● EntriesController › findAll › should return an array of entries

    expect(received).toBe(expected) // Object.is equality

    Expected value to be:
      true
    Received:
      false

      30 |       ];
      31 |       // jest.spyOn(entriesSrv, 'findAll').mockImplementation(() => result);
    > 32 |       expect(Array.isArray(await entriesController.findAll())).toBe(true);
      33 |     });
      34 |
      35 |     // it('should return the entries retrieved from the service', async () => {

      at src/modules/entry/entry.controller.spec.ts:32:64
      at fulfilled (src/modules/entry/entry.controller.spec.ts:3:50)

Test Suites: 1 failed, 1 total
Tests:       1 failed, 1 total
Snapshots:   0 total
Time:        1.112s, estimated 2s
Ran all test suites related to changed files.

```

它失败了... 好吧，当然失败了！记得`beforeEach()`方法吗？

```js
...
.overrideComponent(EntriesService)
.useValue({ findAll: () => null })
.compile();
...

```

我们告诉 Nest.js 将服务中的原始`findAll()`方法替换为另一个只返回`null`的方法。我们需要告诉 Jest 用返回数组的东西来模拟该方法，以便检查当`EntriesService`返回一个数组时，控制器实际上也将该结果作为数组返回。

```js
...
describe('findAll', () => {
  it('should return an array of entries', async () => {
    jest.spyOn(entriesSrv, 'findAll').mockImplementationOnce(() => [{}]);
    expect(Array.isArray(await entriesController.findAll())).toBe(true);
  });
});
...

```

为了模拟服务中的`findAll()`方法，我们使用了两个 Jest 方法。`spyOn()`接受一个对象和一个方法作为参数，并开始监视该方法的执行（换句话说，设置一个*spy*）。`mockImplementationOnce()`，顾名思义，当下一次调用该方法时改变方法的实现（在这种情况下，我们将其更改为返回一个空对象的数组）。

让我们尝试再次用`npm test`运行测试：

```js
 PASS  src/modules/entry/entry.controller.spec.ts
  EntriesController
    findAll
      ✓ should return an array of entries (3ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
Snapshots:   0 total
Time:        1.134s, estimated 2s
Ran all test suites related to changed files.

```

测试现在通过了，因此您可以确信控制器上的`findAll()`方法将始终表现自如，并返回一个数组，以便依赖于该输出为数组的其他代码组件不会自己破坏。

如果这个测试在将来的某个时刻开始失败，那将意味着我们在代码库中引入了一个回归。自动化测试的一个很大的好处是，在为时已晚之前，我们将收到有关此回归的通知。

## 测试相等性

直到这一点，我们可以确定`EntriesController.findAll()`返回一个数组。我们无法确定它不是一个空对象数组，或者一个布尔值数组，或者只是一个空数组。换句话说，我们可以将该方法重写为`findAll() { return []; }`，测试仍然会通过。

因此，让我们改进我们的测试，以检查该方法是否真的返回了来自服务的输出，而不会搞乱事情。

```js
import { Test } from '@nestjs/testing';
import { EntriesController } from './entry.controller';
import { EntriesService } from './entry.service';

describe('EntriesController', () => {
  let entriesController: EntriesController;
  let entriesSrv: EntriesService;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      controllers: [EntriesController],
    })
      .overrideComponent(EntriesService)
      .useValue({ findAll: () => null })
      .compile();

    entriesSrv = module.get<EntriesService>(EntriesService);
    entriesController = module.get<EntriesController>(EntriesController);
  });

  describe('findAll', () => {
    it('should return an array of entries', async () => {
      jest.spyOn(entriesSrv, 'findAll').mockImplementationOnce(() => [{}]);
      expect(Array.isArray(await entriesController.findAll())).toBe(true);
    });

    it('should return the entries retrieved from the service', async () => {
      const result = [
        {
          uuid: '1234567abcdefg',
          title: 'Test title',
          body:
            'This is the test body and will serve to check whether the controller is properly doing its job or not.',
        },
      ];
      jest.spyOn(entriesSrv, 'findAll').mockImplementationOnce(() => result);

      expect(await entriesController.findAll()).toEqual(result);
    });
  });
});

```

我们保留了大部分测试文件之前的内容，尽管我们添加了一个新的测试，最后一个测试，在其中：

+   我们设置了一个包含一个*非空*对象（`result`常量）的数组。

+   我们再次模拟服务的`findAll()`方法的实现，以返回该`result`。

+   我们检查控制器在调用时是否确实像原始的那样返回`result`对象。请注意，我们使用了 Jest 的`.toEqual()`方法，它与`.toBe()`不同，它对两个对象的所有属性进行深度相等比较。

这是我们再次运行`npm test`时得到的结果：

```js
 PASS  src/modules/entry/entry.controller.spec.ts
  EntriesController
    findAll
      ✓ should return an array of entries (2ms)
      ✓ should return the entries retrieved from the service (1ms)

Test Suites: 1 passed, 1 total
Tests:       2 passed, 2 total
Snapshots:   0 total
Time:        0.935s, estimated 2s
Ran all test suites related to changed files.

```

我们的两个测试都通过了。我们已经取得了相当大的成就。现在我们有了一个坚实的基础，将测试扩展到尽可能多的测试用例将是一项容易的任务。

当然，我们只为一个控制器编写了一个测试。但测试服务和我们的 Nest.js 应用程序的其余部分的工作方式是相同的。

## 在测试中覆盖我们的代码

代码自动化中的一个关键方面是代码覆盖报告。因为，你怎么知道你的测试实际上覆盖了尽可能多的测试用例？嗯，答案就是检查代码覆盖率。

如果您希望对您的测试作为回归检测系统有真正的信心，确保它们尽可能多地覆盖功能。让我们想象一下，我们有一个有五个方法的类，我们只为其中两个编写了测试。我们大约覆盖了五分之二的代码，这意味着我们对另外三分之二没有任何了解，也不知道随着代码库的不断增长它们是否仍然有效。

代码覆盖引擎分析我们的代码和测试，并检查测试套件中运行的测试覆盖的行数、语句和分支的数量，返回一个百分比值。

如前几节所述，Jest 已经默认包含代码覆盖报告，您只需要通过向`jest`命令传递`--coverage`参数来激活它。

让我们在`package.json`文件中添加一个脚本，当执行时将生成覆盖报告：

```js
{
  ...
  "scripts": {
    ...
    "test:coverage":"jest --config=jest.json --coverage --coverageDirectory=coverage",
    ...
  }
}

```

在之前编写的控制器上运行`npm run test:coverage`，您将看到以下输出：

```js
 PASS  src/modules/entry/entry.controller.spec.ts
  EntriesController
    findAll
      ✓ should return an array of entries (9ms)
      ✓ should return the entries retrieved from the service (2ms)

---------------------|----------|----------|----------|----------|-------------------|
File                 |  % Stmts | % Branch |  % Funcs |  % Lines | Uncovered Line #s |
---------------------|----------|----------|----------|----------|-------------------|
All files            |      100 |    66.67 |      100 |      100 |                   |
 entry.controller.ts |      100 |    66.67 |      100 |      100 |                 6 |
---------------------|----------|----------|----------|----------|-------------------|
Test Suites: 1 passed, 1 total
Tests:       2 passed, 2 total
Snapshots:   0 total
Time:        4.62s
Ran all test suites.

```

为了更好地了解本书中的控制台输出，我们将把控制台输出转换成一个合适的表格。

| 文件 | % 语句 | % 分支 | % 函数 | % 行 | 未覆盖的行号 |
| --- | --- | --- | --- | --- | --- |
| 所有文件 | 100 | 66.67 | 100 | 100 |  |
| entry.controller.ts | 100 | 66.67 | 100 | 100 | 6 |

我们可以很容易地看到，我们在测试中覆盖了 100%的代码行。这是有道理的，因为我们为控制器中唯一的方法编写了两个测试。

### 覆盖率低的失败测试

现在想象一下，我们在一个复杂的项目中与几个开发人员同时在同一个基础上工作。还要想象我们的工作流程包括一个持续集成/持续交付流水线，运行在像 Travis CI、CircleCI 甚至 Jenkins 之类的东西上。我们的流水线可能包括一个在合并或部署之前运行我们的自动化测试的步骤，这样如果测试失败，流水线就会中断。

在这个想象中的项目中工作的所有虚构开发人员将会添加（以及重构和删除，但这些情况并不适用于这个例子）新功能（即*新代码*），但他们可能会忘记对该代码进行适当的测试。那么会发生什么？项目的覆盖百分比值会下降。

为了确保我们仍然可以依赖我们的测试作为回归检测机制，我们需要确保覆盖率永远不会*太低*。什么是太低？这实际上取决于多个因素：项目和其使用的技术栈、团队等。然而，通常一个很好的经验法则是在每个编码过程迭代中不要让覆盖率值下降。

无论如何，Jest 允许您为测试指定覆盖率阈值：如果值低于该阈值，测试将返回失败*即使它们都通过了*。这样，我们的 CI/CD 流水线将拒绝合并或部署我们的代码。

覆盖率阈值必须包含在 Jest 配置对象中；在我们的情况下，它位于项目根文件夹中的`jest.json`文件中。

```js
{
  ...
  "coverageThreshold": {
    "global": {
      "branches": 80,
      "functions": 80,
      "lines": 80,
      "statements": 80
    }
  }
}

```

传递给对象的每个属性的数字都是百分比值；如果低于这个值，测试将失败。

为了演示，让我们以以上设置运行我们的控制器测试。`npm run test:coverage`返回如下结果：

```js
 PASS  src/modules/entry/entry.controller.spec.ts
  EntriesController
    findAll
      ✓ should return an array of entries (9ms)
      ✓ should return the entries retrieved from the service (1ms)

---------------------|----------|----------|----------|----------|-------------------|
File                 |  % Stmts | % Branch |  % Funcs |  % Lines | Uncovered Line #s |
---------------------|----------|----------|----------|----------|-------------------|
All files            |      100 |    66.67 |      100 |      100 |                   |
 entry.controller.ts |      100 |    66.67 |      100 |      100 |                 6 |
---------------------|----------|----------|----------|----------|-------------------|
Jest: "global" coverage threshold for branches (80%) not met: 66.67%
Test Suites: 1 passed, 1 total
Tests:       2 passed, 2 total
Snapshots:   0 total
Time:        2.282s, estimated 4s
Ran all test suites.
npm ERR! code ELIFECYCLE
npm ERR! errno 1
npm ERR! nest-book-example@1.0.0 test:coverage: `jest --config=jest.json --coverage --coverageDirectory=coverage`
npm ERR! Exit status 1
npm ERR!
npm ERR! Failed at the nest-book-example@1.0.0 test:coverage script.
npm ERR! This is probably not a problem with npm. There is likely additional logging output above.

```

正如你所看到的，测试通过了，但是进程以状态 1 失败并返回错误。此外，Jest 报告说`"全局"分支覆盖率阈值（80%）未达到：66.67%`。我们已成功将不可接受的代码覆盖率远离了我们的主分支或生产环境。

接下来的步骤可能是实现一些端到端测试，以及我们的单元测试，以改进我们的系统。

# 端到端测试

尽管单元测试根据定义是孤立和独立的，端到端（或 E2E）测试在某种程度上具有相反的功能：它们旨在检查系统作为一个整体的健康状况，并尝试包括尽可能多的解决方案组件。因此，在 E2E 测试中，我们将专注于测试完整的模块，而不是孤立的组件或控制器。

## 准备工作

幸运的是，我们可以像对单元测试一样使用 Jest 进行 E2E 测试。我们只需要安装`supertest` npm 包来执行 API 请求并断言它们的结果。通过在控制台中运行`npm install --save-dev supertest`来安装它。

另外，我们将在项目的根目录下创建一个名为`e2e`的文件夹。这个文件夹将保存所有的 E2E 测试文件，以及它们的配置文件。

这将带我们到下一步：在`e2e`文件夹内创建一个名为`jest-e2e.json`的新文件，内容如下：

```js
{
  "moduleFileExtensions": ["js", "ts", "json"],
  "transform": {
    "^.+\\.tsx?$": "<rootDir>/node_modules/ts-jest/preprocessor.js"
  },
  "testRegex": "/e2e/.*\\.(e2e-test|e2e-spec).ts|tsx|js)$",
  "coverageReporters": ["json", "lcov", "text"]
}

```

正如你所看到的，新的 E2E 配置对象与单元测试的对象非常相似；主要区别在于`testRegex`属性，它现在指向`/e2e/`文件夹中具有`.e2e-test`或`e2e.spec`文件扩展名的文件。

准备的最后一步将是在我们的`package.json`文件中包含一个 npm 脚本来运行端到端测试：

```js
{
  ...
  "scripts": {
    ...
    "e2e": "jest --config=e2e/jest-e2e.json --forceExit"
  }
  ...
}

```

## 编写端到端测试

使用 Jest 和 Nest.js 编写端到端测试的方式也与我们用于单元测试的方式非常相似：我们使用`@nestjs/testing`包创建一个测试模块，我们覆盖`EntriesService`的实现以避免需要数据库，然后我们准备运行我们的测试。

让我们来编写测试的代码。在`e2e`文件夹内创建一个名为`entries`的新文件夹，然后在其中创建一个名为`entries.e2e-spec.ts`的新文件，内容如下：

```js
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';

import { EntriesModule } from '../../src/modules/entry/entry.module';
import { EntriesService } from '../../src/modules/entry/entry.service';

describe('Entries', () => {
  let app: INestApplication;
  const mockEntriesService = { findAll: () => ['test'] };

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [EntriesModule],
    })
      .overrideComponent(EntriesService)
      .useValue(mockEntriesService)
      .compile();

    app = module.createNestApplication();
    await app.init();
  });

  it(`/GET entries`, () => {
    return request(app.getHttpServer())
      .get('/entries')
      .expect(200)
      .expect({
        data: mockEntriesService.findAll(),
      });
  });

  afterAll(async () => {
    await app.close();
  });
});

```

让我们回顾一下代码的功能：

1.  `beforeAll`方法创建一个新的测试模块，在其中导入`EntriesModule`（我们将要测试的模块），并用非常简单的`mockEntriesService`常量覆盖`EntriesService`的实现。一旦完成，它使用`.createNestApplication()`方法创建一个实际运行的应用程序来进行请求，然后等待其初始化。

1.  `'/GET entries'`测试使用 supertest 执行对`/entries`端点的 GET 请求，然后断言该请求的响应状态码是否为`200`，并且接收到的响应体是否与`mockEntriesService`常量的值匹配。如果测试通过，这意味着我们的 API 正确地响应了收到的请求。

1.  `afterAll`方法在所有测试运行完毕时结束了我们创建的 Nest.js 应用程序。这很重要，以避免在下次运行测试时产生副作用。

# 总结

在本章中，我们探讨了向我们的项目添加自动化测试的重要性以及它带来的好处。

另外，我们开始使用 Jest 测试框架，并学习了如何配置它，以便与 TypeScript 和 Nest.js 无缝使用。

最后，我们回顾了 Nest.js 为我们提供的测试工具，并学习了如何编写测试，包括单元测试和端到端测试，以及如何检查我们的测试覆盖了多少代码的百分比。

在下一章中，我们将介绍使用 Angular Universal 进行服务器端渲染。


# 第十五章：使用 Angular Universal 进行服务器端渲染

如果您对用于客户端应用程序开发的 Angular 平台不熟悉，值得一看。Nest.js 与 Angular 有着独特的共生关系，因为它们都是用 TypeScript 编写的。这允许在 Nest.js 服务器和 Angular 应用程序之间进行一些有趣的代码共享，因为 Angular 和 Nest.js 都使用 TypeScript，可以在两者之间创建一个共享的包中的类。然后可以将这些类包含在任一应用程序中，并帮助保持在客户端和服务器之间通过 HTTP 请求发送和接收的对象一致。当我们引入 Angular Universal 时，这种关系被提升到另一个层次。Angular Universal 是一种技术，允许在服务器上预渲染您的 Angular 应用程序。这有许多好处，比如：

1.  为了便于 SEO 目的的网络爬虫。

1.  提高网站的加载性能。

1.  提高低性能设备和移动设备上网站的性能。

这种技术称为服务器端渲染，可以非常有帮助，但需要对项目进行一些重构，因为 Nest.js 服务器和 Angular 应用程序是按顺序构建的，当请求获取网页时，Nest.js 服务器实际上会运行 Angular 应用程序本身。这本质上模拟了浏览器中的 Angular 应用程序，包括 API 调用和加载任何动态元素。这个在服务器上构建的页面现在作为静态网页提供给客户端，动态的 Angular 应用程序在后台静默加载。

如果您现在刚开始阅读本书，并希望跟随示例存储库进行操作，可以使用以下命令进行克隆：

```js
git clone https://github.com/backstopmedia/nest-book-example

```

Angular 是另一个可以写一整本书的主题。我们将使用一个已经由作者之一改编用于本书的 Angular 6 应用程序。原始存储库可以在这里找到。

```js
https://github.com/patrickhousley/nest-angular-universal.git

```

这个存储库使用了 Nest 5 和 Angular 6，所以进行了一些更改，因为这本书是基于 Nest 4 的。不过不用担心，我们在本章开头展示的主要存储库中包含了一个 Angular Universal 项目。它可以在项目的根目录下的`universal`文件夹中找到。这是一个独立的 Nest + Angular 项目，而不是将主要存储库适应这本书的 Angular 应用，我们将其隔离出来，以提供一个清晰简洁的示例。

# 使用 Nest.js 为 Angular Universal 应用提供服务

现在我们将使用 Nest.js 服务器来提供 Angular 应用程序，我们需要将它们编译在一起，这样当我们运行 Nest.js 服务器时，它就知道在哪里查找 Universal 应用程序。在我们的`server/src/main.ts`文件中，有一些关键的东西需要在那里。在这里我们创建一个`bootstrap()`函数，然后从下面调用它。

```js
async function bootstrap() {
  if (environment.production) {
    enableProdMode();
  }

  const app = await NestFactory.create(ApplicationModule.moduleFactory());

  if (module.hot) {
    module.hot.accept();
    module.hot.dispose(() => app.close());
  }

  await app.listen(environment.port);
}

bootstrap()
  .then(() => console.log(`Server started on port ${environment.port}`))
  .catch(err => console.error(`Server startup failed`, err));

```

让我们逐行分析这个函数。

```js
if (environment.production) {
    enableProdMode();
  }

```

这告诉应用程序为应用程序启用生产模式。在编写 Web 服务器时，生产模式和开发模式之间有许多不同之处，但如果您想在生产环境中运行 Web 服务器，这是必需的。

```js
const app = await NestFactory.create(ApplicationModule.moduleFactory());

```

这将创建类型为`INestApplication`的 Nest 应用程序变量，并将在`app.module.ts`文件中使用`ApplicationModule`运行。`app`将是在`environment.port`端口上运行的 Nest 应用程序的实例，可以在`src/server/environment/environment.ts`中找到。这里有三个不同的环境文件：

1.  `environment.common.ts`-正如其名称所示，这个文件在生产和开发构建之间是共用的。它提供了关于在服务器和客户端应用程序中找到打包构建文件的信息和路径。

1.  `environment.ts`-这是在开发过程中使用的默认环境，并包括`environment.common.ts`文件中的设置，以及将`production: false`和上面提到的端口设置为 3000。

1.  `environment.prod.ts`-这个文件与#2 相似，只是它设置了`production: true`，并且没有定义端口，而是默认使用默认端口，通常是 8888。

如果我们在本地开发并且想要进行热重载，即如果我们更改文件，则服务器将重新启动，那么我们需要在我们的`main.ts`文件中包含以下内容。

```js
if (module.hot) {
  module.hot.accept();
  module.hot.dispose(() => app.close());
}

```

这是在`webpack.server.config.ts`文件中设置的，基于我们的`NODE_ENV`环境变量。

最后，要实际启动服务器，调用我们的`INestApplication`变量上的`.listen()`函数，并传递一个端口来运行。

```js
await app.listen(environment.port);

```

然后我们调用`bootstrap()`，这将运行上面描述的函数。在这个阶段，我们现在有了我们的 Nest 服务器正在运行，并且能够提供 Angular 应用程序并监听 API 请求。

在上面的`bootstrap()`函数中，当创建`INestApplication`对象时，我们提供了`ApplicationModule`。这是应用程序的入口点，处理 Nest 和 Angular Universal 应用程序。在`app.module.ts`中我们有：

```js
@Module({
  imports: [
    HeroesModule,
    ClientModule.forRoot()
  ],
})
export class ApplicationModule {}

```

在这里，我们导入了两个 Nest 模块，`HeroesModule`，它将为*英雄之旅*应用程序提供 API 端点，以及`ClientModule`，它是处理 Universal 的模块。`ClientModule`有很多内容，但我们将重点介绍处理设置 Universal 的主要内容，这是这个模块的代码。

```js
@Module({
  controllers: [ClientController],
  components: [...clientProviders],
})
export class ClientModule implements NestModule {
  constructor(
    @Inject(ANGULAR_UNIVERSAL_OPTIONS)
    private readonly ngOptions: AngularUniversalOptions,
    @Inject(HTTP_SERVER_REF) private readonly app: NestApplication
  ) {}

  static forRoot(): DynamicModule {
    const requireFn = typeof __webpack_require__ === "function" ? __non_webpack_require__ : require;
    const options: AngularUniversalOptions = {
      viewsPath: environment.clientPaths.app,
      bundle: requireFn(join(environment.clientPaths.server, 'main.js'))
    };

    return {
      module: ClientModule,
      components: [
        {
          provide: ANGULAR_UNIVERSAL_OPTIONS,
          useValue: options,
        }
      ]
    };
  }

  configure(consumer: MiddlewareConsumer): void {
    this.app.useStaticAssets(this.ngOptions.viewsPath);
  }
}

```

我们将从文件顶部的`@Module`装饰器开始。与常规的 Nest.js 模块（还有 Angular，记得 Nest.js 是受 Angular 启发的吗？）一样，有`controllers`（用于端点）属性和`components`（用于服务、提供者和其他我们想要作为此模块一部分的组件）属性。在这里，我们在`controllers`数组中包括`ClientController`，在`components`中包括`...clientProviders`。这里的三个点（`...`）本质上意味着“将数组中的每个元素插入到这个数组中”。让我们更详细地解释一下这些。

`ClientController`

```js
@Controller()
export class ClientController {
  constructor(
    @Inject(ANGULAR_UNIVERSAL_OPTIONS) private readonly ngOptions: AngularUniversalOptions,
  ) { }

  @Get('*')
  render(@Res() res: Response, @Req() req: Request) {
    res.render(join(this.ngOptions.viewsPath, 'index.html'), { req });
  }
}

```

这与我们学到的任何其他控制器都是一样的，但有一个小小的不同。在 URL 路径`/*`上，Nest.js 服务器不是提供 API 端点，而是从之前在环境文件中看到的相同的`viewsPath`中呈现一个 HTML 页面，即`index.html`。

至于`clientProoviders`数组：

```js
export const clientProviders = [
  {
    provide: 'UNIVERSAL_INITIALIZER',
    useFactory: async (
      app: NestApplication,
      options: AngularUniversalOptions
    ) => await setupUniversal(app, options),
    inject: [HTTP_SERVER_REF, ANGULAR_UNIVERSAL_OPTIONS]
  }
];

```

这类似于我们在`ClientModule`的返回语句中定义自己的提供者，但是我们使用`useFactory`而不是`useValue`，这将 Nest 应用程序和我们之前定义的`AngularUniversalOptions`传递给`setupUniversal(app, options)`函数。我们花了一段时间，但这就是实际创建 Angular Universal 服务器的地方。

`setupUniversal(app, options)`

```js
export function setupUniversal(
  app: NestApplication,
  ngOptions: AngularUniversalOptions
) {
  const { AppServerModuleNgFactory, LAZY_MODULE_MAP } = ngOptions.bundle;

  app.setViewEngine('html');
  app.setBaseViewsDir(ngOptions.viewsPath);
  app.engine(
    'html',
    ngExpressEngine({
      bootstrap: AppServerModuleNgFactory,
      providers: [
        provideModuleMap(LAZY_MODULE_MAP),
        {
          provide: APP_BASE_HREF,
          useValue: `http://localhost:${environment.port}`
        }
      ]
    })
  );
}

```

这里调用了三个主要函数：`app.setViewEngine()`，`app.setBaseViewDir()`和`app.engine`。第一个`.setViewEngine()`将视图引擎设置为 HTML，以便引擎呈现视图时知道我们正在处理 HTML。第二个`.setBaseViewDir()`告诉 Nest.js 在哪里找到 HTML 视图，这同样是之前在`environment.common.ts`文件中定义的。最后一个非常重要，`.engine()`定义了要使用的 HTML 引擎，在这种情况下，因为我们使用的是 Angular，它是`ngExpressEngine`，这是 Angular Universal 引擎。在这里阅读更多关于 Universal express-engine 的信息：[`github.com/angular/universal/tree/master/modules/express-engine`](https://github.com/angular/universal/tree/master/modules/express-engine)。这将`bootstrap`设置为`AppServerModuleNgFactory`对象，这将在下一节中讨论。

在`ClientModule`中，我们可以看到在我们在`AppliationModule`（服务器入口点）中导入`ClientModule`时调用的`.forRoot()`函数。基本上，`forRoot()`定义了一个要返回的模块，以取代最初导入的`ClientModule`，也称为`ClientModule`。返回的这个模块有一个单一组件，提供了`ANGULAR_UNIVERSAL_OPTIONS`，这是一个定义将传递到组件的`useValue`属性中的对象类型的接口。

`ANGULAR_UNIVERSAL_OPTIONS`的结构是：

```js
export interface AngularUniversalOptions {
  viewsPath: string;
  bundle: {
    AppServerModuleNgFactory: any,
    LAZY_MODULE_MAP: any
  };
}

```

由此可见，`useValue`的值是在`forRoot()`顶部定义的`options`的内容。

```js
const options: AngularUniversalOptions = {
  viewsPath: environment.clientPaths.app,
  bundle: requireFn(join(environment.clientPaths.server, 'main.js'))
};

```

`environment.clientPaths.app`的值可以在我们之前讨论过的`environment.common.ts`文件中找到。作为提醒，它指向编译后的客户端代码的位置。也许你会想为什么`bundle`的值是一个 require 语句，而接口明确表示它应该是这样的结构：

```js
bundle: {
    AppServerModuleNgFactory: any,
    LAZY_MODULE_MAP: any
  };

```

好吧，如果你追溯这个 require 语句（`..`表示向上一级目录），那么你会看到我们将`bundle`属性设置为另一个模块`AppServerModule`。稍后会讨论这个，但是 Angular 应用程序最终将被提供。

`ClientModule`中的最后一部分是`configure()`函数，它将告诉服务器在哪里找到静态资产。

```js
configure(consumer: MiddlewareConsumer): void {
    this.app.useStaticAssets(this.ngOptions.viewsPath);
  }

```

# 构建和运行 Universal App

现在你已经设置好了 Nest.js 和 Angular 文件，几乎可以运行项目了。有一些需要你注意的配置文件，可以在示例项目中找到：[`github.com/backstopmedia/nest-book-example`](https://github.com/backstopmedia/nest-book-example)。到目前为止，我们一直在使用`nodemon`运行项目，这样我们的更改就会在保存项目时反映出来，但是，现在我们正在打包它以提供一个 Angular 应用程序，我们需要使用不同的包来构建服务器。为此，我们选择了`udk`，这是一个`webpack`扩展。它既可以构建我们的生产包，也可以启动一个开发服务器，就像`nodemon`为我们的普通 Nest.js 应用程序所做的那样。熟悉以下配置文件是个好主意：

1.  `angular.json`-我们的 Angular 配置文件，处理诸如使用哪个环境文件、可以与`ng`一起使用的命令以及 Angular CLI 命令等事项。

1.  `package.json`-项目全局依赖和命令文件。该文件定义了生产和开发所需的依赖项，以及命令行工具（如`yarn`或`npm`）可用的命令。

1.  `tsconfig.server.json`-这是全局`tsconfig.json`文件的扩展，它提供了一些 Angular 编译器选项，比如在哪里找到 Universal 入口点。

# 总结

就是这样！我们有一个可以玩耍的 Angular Universal 项目。Angular 是一个很棒的客户端框架，最近一直在蓬勃发展。在这一章中只是浅尝辄止，特别是在 Angular 本身方面，还有很多工作可以做。

这是本书的最后一章。我们希望你会兴奋地使用 Nest.js 来创建各种应用程序。
