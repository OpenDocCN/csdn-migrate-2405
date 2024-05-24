# NestJS：Node 渐进式框架（三）

> 原文：[`zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240`](https://zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：Nest.js 中的路由和请求处理

Nest.js 中的路由和请求处理由控制器层处理。Nest.js 将请求路由到定义在控制器类内部的处理程序方法。在控制器的方法中添加路由装饰器，如`@Get()`，告诉 Nest.js 为此路由路径创建一个端点，并将每个相应的请求路由到此处理程序。

在本章中，我们将使用我们的博客应用程序中的 EntryController 作为一些示例的基础，来介绍 Nest.js 中路由和请求处理的各个方面。我们将看看您可以使用的不同方法来编写请求处理程序，因此并非所有示例都与我们的博客应用程序中的代码匹配。

# 请求处理程序

在 EntryController 中注册的`/entries`路由的基本 GET 请求处理程序可能如下所示：

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

`@Controller('entries')`装饰器告诉 Nest.js 在类中注册的所有路由添加一个`entries`前缀。此前缀是可选的。设置此路由的等效方式如下：

```js
import { Controller, Get } from '@nestjs/common';

@Controller()
export class EntryController {
    @Get('entries')
    index(): Entry[] {
        const entries: Entry[] = this.entriesService.findAll();
        return entries;
    }

```

在这里，我们不在`@Controller()`装饰器中指定前缀，而是在`@Get('entries')`装饰器中使用完整的路由路径。

在这两种情况下，Nest.js 将所有 GET 请求路由到此控制器中的`index()`方法。从处理程序返回的条目数组将**自动**序列化为 JSON 并作为响应主体发送，并且响应状态码将为 200。这是 Nest.js 中生成响应的标准方法。

Nest.js 还提供了`@Put()`、`@Delete()`、`@Patch()`、`@Options()`和`@Head()`装饰器，用于创建其他 HTTP 方法的处理程序。`@All()`装饰器告诉 Nest.js 将给定路由路径的所有 HTTP 方法路由到处理程序。

# 生成响应

Nest.js 提供了两种生成响应的方法。

## 标准方法

使用自 Nest.js 4 以来可用的标准和推荐方法，Nest.js 将**自动**将从处理程序方法返回的 JavaScript 对象或数组序列化为 JSON 并将其发送到响应主体中。如果返回一个字符串，Nest.js 将只发送该字符串，而不将其序列化为 JSON。

默认的响应状态码为 200，除了 POST 请求使用 201。可以通过使用`@HttpCode(...)`装饰器轻松地更改处理程序方法的响应代码。例如：

```js
@HttpCode(204)
@Post()
create() {
  // This handler will return a 204 status response
}

```

## Express 方法

在 Nest.js 中生成响应的另一种方法是直接使用响应对象。您可以要求 Nest.js 将响应对象注入到处理程序方法中，使用`@Res()`装饰器。Nest.js 使用[express 响应对象](http://expressjs.com/en/api.html#res)。

您可以使用响应对象重写先前看到的响应处理程序，如下所示。

```js
import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller('entries')
export class EntryController {
    @Get()
    index(@Res() res: Response) {
        const entries: Entry[] = this.entriesService.findAll();
        return res.status(HttpStatus.OK).json(entries);
    }
}

```

直接使用 express 响应对象将条目数组序列化为 JSON 并发送 200 状态码响应。

`Response`对象的类型来自 express。在`package.json`中的`devDependencies`中添加`@types/express`包以使用这些类型。

# 路由参数

Nest.js 使得从路由路径接受参数变得容易。为此，您只需在路由的路径中指定路由参数，如下所示。

```js
import { Controller, Get, Param } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Get(':entryId')
    show(@Param() params) {
        const entry: Entry = this.entriesService.find(params.entryId);
        return entry;
    }
}

```

上述处理程序方法的路由路径为`/entries/:entryId`，其中`entries`部分来自控制器路由前缀，而由冒号表示的`:entryId`参数。使用`@Param()`装饰器注入 params 对象，其中包含参数值。

或者，您可以使用`@Param()`装饰器注入单个参数值，如下所示指定参数名称。

```js
import { Controller, Get, Param } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Get(':entryId')
    show(@Param('entryId') entryId) {
        const entry: Entry = this.entriesService.findOne(entryId);
        return entry;
    }
}

```

# 请求体

要访问请求的主体，请使用`@Body()`装饰器。

```js
import { Body, Controller, Post } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Post()
    create(@Body() body: Entry) {
        this.entryService.create(body);
    }
}

```

# 请求对象

要访问客户端请求的详细信息，您可以要求 Nest.js 使用`@Req()`装饰器将请求对象注入到处理程序中。Nest.js 使用[express 请求对象](http://expressjs.com/en/api.html#req)。

例如，

```js
import { Controller, Get, Req } from '@nestjs/common';
import { Request } from 'express';

@Controller('entries')
export class EntryController {
    @Get()
    index(@Req() req: Request): Entry[] {
        const entries: Entry[] = this.entriesService.findAll();
        return entries;
    }

```

`Request`对象的类型来自 express。在`package.json`的`devDependencies`中添加`@types/express`包以使用这些类型。

# 异步处理程序

到目前为止，在本章中展示的所有示例都假设处理程序是同步的。在实际应用中，许多处理程序将需要是异步的。

Nest.js 提供了许多方法来编写异步请求处理程序。

## 异步/等待

Nest.js 支持异步请求处理程序函数。

在我们的示例应用程序中，`entriesService.findAll()`函数实际上返回一个`Promise<Entry[]>`。使用 async 和 await，这个函数可以这样写。

```js
import { Controller, Get } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Get()
    async index(): Promise<Entry[]> {
        const entries: Entry[] = await this.entryService.findAll();
        return entries;
    }

```

异步函数必须返回 promises，但是在现代 JavaScript 中使用 async/await 模式，处理程序函数可以看起来是同步的。接下来，我们将解决返回的 promise 并生成响应。

## Promise

同样，您也可以直接从处理程序函数返回一个 promise，而不使用 async/await。

```js
import { Controller, Get } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Get()
    index(): Promise<Entry[]> {
        const entriesPromise: Promise<Entry[]> = this.entryService.findAll();
        return entriesPromise;
    }

```

## Observables

Nest.js 请求处理程序也可以返回 RxJS Observables。

例如，如果`entryService.findAll()`返回的是 Observable 而不是 Promise，那么以下内容将是完全有效的。

```js
import { Controller, Get } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Get()
    index(): Observable<Entry[]> {
        const entriesPromise: Observable<Entry[]> = this.entryService.findAll();
        return entriesPromise;
    }

```

没有推荐的方法来编写异步请求处理程序。使用您最熟悉的任何方法。

# 错误响应

Nest.js 有一个异常层，负责捕获来自请求处理程序的未处理异常，并向客户端返回适当的响应。

全局异常过滤器处理从请求处理程序抛出的所有异常。

## HttpException

如果从请求处理程序抛出的异常是`HttpException`，全局异常过滤器将把它转换为 JSON 响应。

例如，您可以从`create()`处理程序函数中抛出`HttpException`，如果 body 无效则如此。

```js
import { Body, Controller, HttpException, HttpStatus, Post } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Post()
    create(@Body() entry: Entry) {
        if (!entry) throw new HttpException('Bad request', HttpStatus.BAD_REQUEST);
        this.entryService.create(entry);
    }
}

```

如果抛出此异常，响应将如下所示：

```js
{
    "statusCode": 400,
    "message": "Bad request"
}

```

您还可以通过将对象传递给`HttpException`构造函数来完全覆盖响应体，如下所示。

```js
import { Body, Controller, HttpException, HttpStatus, Post } from '@nestjs/common';

@Controller('entries')
export class EntryController {
    @Post()
    create(@Body() entry: Entry) {
        if (!entry) throw new HttpException({ status: HttpStatus.BAD_REQUEST, error: 'Entry required' });
        this.entryService.create(entry);
    }
}

```

如果抛出此异常，响应将如下所示：

```js
{
    "statusCode": 400,
    "error": "Entry required"
}

```

## 未识别的异常

如果异常未被识别，意味着它不是`HttpException`或继承自`HttpException`的类，则客户端将收到下面的 JSON 响应。

```js
{
    "statusCode": 500,
    "message": "Internal server error"
}

```

# 总结

借助于我们示例博客应用程序中的 EntryController，本章涵盖了 Nest.js 中的路由和请求处理的方面。您现在应该了解各种方法，可以用来编写请求处理程序。

在下一章中，我们将详细介绍 OpenAPI 规范，这是一个 JSON 模式，可用于构建一组 restful API 的 JSON 或 YAML 定义。


# 第十一章：OpenAPI（Swagger）规范

OpenAPI 规范，最著名的是其前身 Swagger，是一个 JSON 模式，可用于构建一组 RESTful API 的 JSON 或 YAML 定义。OpenAPI 本身是与语言无关的，这意味着底层 API 可以使用开发人员喜欢的任何语言、任何工具或框架来构建。OpenAPI 文档的唯一关注点是描述 API 端点的输入和输出等内容。在这方面，OpenAPI 文档充当了一个文档工具，使开发人员能够轻松地以广泛已知、理解和支持的格式描述其公共 API。

然而，OpenAPI 文档不仅仅局限于文档。已开发了许多工具，这些工具能够使用 OpenAPI 文档自动生成客户端项目、服务器存根、用于直观检查 OpenAPI 文档的 API 资源管理器 UI，甚至服务器生成器。开发人员可以在[`swagger.io`](https://swagger.io)找到 Swagger Editor、Codegen 和 UI 等工具。

虽然存在一些工具可以生成 OpenAPI 文档，但许多开发人员将这些文档保存为单独的 JSON 或 YAML 文件。他们可以使用 OpenAPI 引用机制将文档分解成更小的部分。在 Nest.js 中，开发人员可以使用单独的模块来为他们的应用程序生成 OpenAPI 文档。Nest.js 将使用您在控制器中提供的装饰器来生成有关项目中 API 的尽可能多的信息，而不是手动编写 OpenAPI 文档。当然，它不会一步到位。为此，Nest.js swagger 模块提供了额外的装饰器，您可以使用它们来填补空白。

在本章中，我们将探讨使用 Nest.js Swagger 模块生成 swagger 版本 2 文档。我们将从配置 Nest.js Swagger 模块开始。我们将设置我们的博客示例应用程序以使用 Swagger UI 公开 swagger 文档，并开始探索 Nest.js 装饰器如何影响 swagger 文档。我们还将探索 swagger 模块提供的新装饰器。在本章结束时，您将完全了解 Nest.js 如何生成 swagger 文档。在开始之前，请确保在项目中运行`npm install @nestjs/swagger`以查看工作示例，记住您可以克隆本书的附带 Git 存储库：

`git clone https://github.com/backstopmedia/nest-book-example.git`

# 文档设置

每个 swagger 文档都可以包含一组基本属性，例如应用程序的标题。可以使用`DocumentBuilder`类上找到的各种公共方法来配置此信息。这些方法都返回文档实例，允许您链式调用尽可能多的方法。在调用`build`方法之前，请确保完成配置。一旦调用了`build`方法，文档设置将不再可修改。

```js
const swaggerOptions = new DocumentBuilder()
    .setTitle('Blog Application')
    .setDescription('APIs for the example blog application.')
    .setVersion('1.0.0')
    .setTermsOfService('http://swagger.io/terms/')
    .setContactEmail('admin@example.com')
    .setLicense('Apache 2.0', 'http://www.apache.org/licenses/LICENSE-2.0.html')
    .build();

```

这些方法用于配置 swagger 文档的`info`部分。Swagger 规范要求提供`title`和`version`字段，但 Nest.js 将这些值默认为一个空字符串和`"1.0.0"`，分别。如果您的项目有服务条款和许可证，您可以使用`setTermsOfService`和`setLicense`在应用程序中提供这些资源的 URL。

Swagger 文档还可以包含服务器信息。用户、开发人员和 UI 可以使用此信息来了解如何访问文档中描述的 API。

```js
const swaggerOptions = new DocumentBuilder()
    .setHost('localhost:3000')
    .setBasePath('/')
    .setSchemes('http')
    .build();

```

`setHost`应仅包含访问 API 的服务器和端口。如果在应用程序中使用`setGlobalPrefix`为 Nest.js 应用程序配置基本路径，则使用`setBasePath`在 swagger 文档中设置相同的值。swagger 规范使用`schemes`数组来描述 API 使用的传输协议。虽然 swagger 规范支持`ws`和`wss`协议以及多个值，但 Nest.js 将该值限制为`http`或`https`。还可以添加元数据和外部文档，以向 swagger 文档的用户提供有关 API 工作方式的其他详细信息。

```js
const swaggerOptions = new DocumentBuilder()
    .setExternalDoc('For more information', 'http://swagger.io')
    .addTag('blog', 'application purpose')
    .addTag('nestjs', 'framework')
    .build();

```

使用`setExternalDoc`的第一个参数描述外部文档，第二个参数是文档的 URL。可以使用`addTag`向文档添加无数个标签。唯一的要求是`addTag`的第一个参数必须是唯一的。第二个参数应描述标签。最后一个文档设置是用户如何与 API 进行身份验证。

## 记录身份验证

swagger 规范支持三种类型的身份验证：基本、API 密钥和 Oauth2。Nest.js 提供了两种不同的方法，可以用于自动配置 swagger 文档的身份验证信息，并且可以覆盖一些设置。请记住，这描述了用户如何对您的应用程序进行身份验证。

```js
const swaggerOptions = new DocumentBuilder()
    .addBearerAuth('Authorization', 'header', 'apiKey')
    .build();

```

如果您的应用程序使用`basic`身份验证，用户名和密码作为 base64 编码的字符串，或 JSON web 令牌（JWT），您将使用`addBearerAuth`配置方法。上面的示例使用 Nest.js 的默认值，如果没有传递参数，Nest.js 将使用这些默认值，并确定 API 使用类似 JWT 的 API 密钥在授权标头中。第一个参数应包含应提供身份验证密钥的密钥/标头。如果用户将使用应用程序密钥访问 API，则应使用相同的配置。应用程序密钥通常由公共 API 提供商（如 Google Maps）使用，以限制对 API 的访问并将 API 调用与特定的计费账户关联起来。

```js
const swaggerOptions = new DocumentBuilder()
    .addBearerAuth('token', 'query', 'apiKey')
    .addBearerAuth('appId', 'query', 'apiKey')
    .build();

```

此示例描述了调用需要身份验证的 API 时必须包含的两个查询参数。第二个参数描述了身份验证密钥应该放在哪里，可以是标头、查询或正文参数。第三个参数是身份验证的类型。使用`addBearerAuth`时，使用`apiKey`或`basic`。除了基本和 API 密钥身份验证外，swagger 还支持记录 Oauth2 身份验证流程。

```js
const swaggerOptions = new DocumentBuilder()
    .addOAuth2('password', 'https://example.com/oauth/authorize', 'https://example.com/oauth/token', {
      read: 'Grants read access',
      write: 'Grants write access',
      admin: 'Grants delete access'
    })
    .build();

```

`addOAuth2`方法的第一个参数是 API 用于身份验证的 OAuth2 流。在此示例中，我们使用`password`流来指示用户应向 API 发送用户名和密码。您还可以使用`implicit`、`application`和`accessCode`流。第二个和第三个参数是用户将授权访问 API 和请求刷新令牌的 URL。最后一个参数是应用程序中可用的所有范围及其描述的对象。

对于博客应用程序，我们将保持配置简单，并将配置存储在`shared/config`目录中的新文件中。有一个中心位置将使我们只需编写一次配置并多次实现。

```js
export const swaggerOptions = new DocumentBuilder()
    .setTitle('Blog Application')
    .setDescription('APIs for the example blog application.')
    .setVersion('1.0.0')
    .setHost('localhost:3000')
    .setBasePath('/')
    .setSchemes('http')
    .setExternalDoc('For more information', 'http://swagger.io')
    .addTag('blog', 'application purpose')
    .addTag('nestjs', 'framework')
    .addBearerAuth('Authorization', 'header', 'apiKey')
    .build();

```

我们的第一个实现将使用配置和 Nest.js swagger 模块在我们的应用程序中生成两个新的端点：一个用于提供 swagger UI 应用程序，另一个用于提供原始 JSON 格式的 swagger 文档。

# Swagger UI

swagger 模块与大多数其他 Nest.js 模块不同。它不是被导入到应用程序的主要 app 模块中，而是在应用程序的主要引导中进行配置。

```js
async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    const document = SwaggerModule.createDocument(app, swaggerOptions);
    SwaggerModule.setup('/swagger', app, document);

    await app.listen(process.env.PORT || 3000);
}

```

在声明 Nest 应用程序并在调用`listen`方法之前，我们使用上一节配置的 swagger 文档选项和`SwaggerModule.createDocument`来创建 swagger 文档。Swagger 模块将检查应用程序中的所有控制器，并使用装饰器在内存中构建 swagger 文档。

一旦我们创建了 swagger 文档，我们设置并指示 swagger 模块在指定路径上提供 swagger UI，`SwaggerModule.setup('/swagger', app, document)`。在幕后，swagger 模块使用`swagger-ui-express` NodeJS 模块将 swagger 文档转换为完整的 Web UI 应用程序。

![示例 Swagger UI 应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/basic-swagger-ui.png)

上图显示了一个使用我们示例博客应用程序的基本 Swagger UI 应用程序。用于生成 UI 的 JSON 也可以通过将我们为 UI 配置的路径添加`-json`来获得。在我们的示例中，访问`/swagger-json`将返回 swagger 文档。这可以与 Swagger Codegen 等代码生成器一起使用。有关 Swagger UI 和 Swagger Codegen 的更多信息，请参阅[`swagger.io`](https://swagger.io)。

如果您跟着本书创建了博客应用程序，您可能会发现 Swagger UI 生成的信息不包含应用程序中 API 的很多信息。由于 swagger 文档是使用 Typescript 装饰器元数据构建的，您可能需要修改您的类型或使用 Nest.js swagger 模块中找到的其他装饰器。

# API 输入装饰器

Nest.js swagger 模块可以使用`@Body`、`@Param`、`@Query`和`@Headers`装饰器生成 swagger 文档。然而，根据您编写 API 控制器的方式，swagger 文档可能包含的信息很少。swagger 模块将使用与装饰参数相关联的类型来描述 swagger 文档中 API 期望的参数。为了描述这一点，我们将修改评论 PUT API，使用所有四个装饰器，并通过查看 swagger UI 应用程序来展示这对 swagger 文档的影响。

```js
@Controller('entries/:entryId')
export class CommentController {
    @Put('comments/:commentId')
    public async update(
        @Body() body: UpdateCommentRequest,
        @Param('commentId') comment: string,
        @Query('testQuery') testQuery: string,
        @Headers('testHeader') testHeader: string
    ) {
    }
}

```

![评论放置 Swagger 示例](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example1.png)

从示例中，我们可以看到这个 API 卡的标题使用`@Controller`和`@Put`装饰器的组合来构建 API 的路径。参数部分使用`@Body`、`@Param`、`@Query`和`@Headers`查询参数构建。我们提供给装饰参数的类型在 Swagger UI 中被用作对用户的提示，说明参数中期望的内容。

![评论放置 Swagger 示例](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example2.png)

点击 API 卡标题中的**试一试**按钮会将卡片变成一组输入。这允许用户填写 API 的必需和可选参数，并执行 API 调用。我们将在稍后讨论 API 卡的其余部分。现在，让我们更详细地审查基本参数装饰器。

## @Body

您可能已经注意到在我们的示例中，我们用`@Body`装饰的参数的类型是`UpdateCommentRequest`。您的应用程序可能已经有这个类，也可能没有。如果没有，让我们现在编写它。

```js
export class UpdateCommentRequest {
    @ApiModelPropertyOptional()
    public body: string;
}

```

请求类非常基础，使用了 Nest.js swagger 模块中我们将要介绍的第一个装饰器`@ApiModelPropertyOptional`。这个装饰器通知 swagger 模块，请求类的`body`属性是一个可选属性，可以在调用 API 时包含在请求体中。这个装饰器实际上是`@ApiModelProperty`装饰器的快捷方式。我们可以将我们的请求类写成：

```js
export class UpdateCommentRequest {
    @ApiModelProperty({ required: false })
    public body: string;
}

```

然而，如果属性是可选的，请使用`@ApiModelPropertyOptional`装饰器来节省一些输入。这两个装饰器都可以接受传递给装饰器的对象中的几个附加属性，进一步定义请求体的数据模型。

+   **description**：一个字符串，可用于描述模型属性应包含的内容或其用途。

+   **required**：一个布尔值，指示模型属性是否是必需的。这仅适用于`@ApiModelProperty`装饰器。

+   **type**：Nest.js swagger 模块将使用与模型属性关联的类型，或者您可以将**type**作为任何字符串或类值传递。如果使用**isArray**属性，则还应使用**type**属性。此属性还可用于传递 swagger 规范中定义的任何数据类型。

+   **isArray**：一个布尔值，指示模型属性是否应该接受一组值。如果模型确实接受一组值，请确保在装饰器或 Nest.js swagger 模块中包含此值，以便知道将模型属性表示为数组。

+   **collectionFormat**：映射到 swagger 规范的**collectionFormat**设置。这用于描述模型属性数组值的格式应该如何格式化。对于请求体，可能不应该使用此属性。可能的值包括：

+   **csv**：逗号分隔的值`foo,bar`

+   **ssv**：空格分隔的值`foo bar`

+   **tsv**：制表符分隔的值`foo\tbar`

+   **pipes**：管道分隔的值`foo|bar`

+   **multi**：对应于多个参数实例，而不是单个实例的多个值 foo=bar&foo=baz。这仅适用于“query”或“formData”中的参数。

+   **default**：在 swagger 文档中用于模型属性的默认值。此值还将用于 Swagger UI 中提供的示例。此值的类型取决于模型属性的类型，但可以是字符串、数字，甚至是对象。

+   **enum**：如果您的模型属性类型是枚举，使用此属性将相同的枚举传递给装饰器，以便 Nest.js swagger 模块可以将这些枚举值注入到 swagger 文档中。

+   **format**：如果使用 swagger 规范中描述的数据类型的**type**属性，则可能还需要传递该数据类型的格式。例如，接受具有多个精度点、小数点后的值的字段，**type**将是`integer`，但**format**可能是`float`或`double`。

+   **multipleOf**：表示传递给模型属性的值应使用模运算符具有零余数的数字。仅当装饰器中的模型属性类型为`number`或装饰器提供的**type**为`integer`时，才可以设置此属性。

+   **maximum**：表示传递给模型属性的值应小于或等于给定值才有效的数字。仅当装饰器中的模型属性类型为`number`或装饰器提供的**type**为`integer`时，才可以设置此属性。此属性不应与**exclusiveMaximum**一起使用。

+   **exclusiveMaximum**：表示传递给模型属性的值应小于给定值才有效的数字。仅当装饰器中的模型属性类型为`number`或装饰器提供的**type**为`integer`时，才可以设置此属性。此属性不应与**maximum**一起使用。

+   **minimum**：表示传递给模型属性的值应大于或等于给定值才有效的数字。仅当装饰器中的模型属性类型为`number`或装饰器提供的**type**为`integer`时，才可以设置此属性。此属性不应与**exclusiveMinimum**一起使用。

+   **exclusiveMinimum**：表示传递给模型属性的值应小于给定值才有效的数字。仅当装饰器中的模型属性类型为`number`或装饰器提供的**type**为`integer`时，才可以设置此属性。此属性不应与**minimum**一起使用。

+   **maxLength**：一个数字，表示模型属性中传递的值应该是字符长度少于或等于给定值才能有效。如果在装饰器中设置此属性，则必须是模型属性类型为`string`或装饰器提供的**type**为`string`。

+   **minLength**：一个数字，表示模型属性中传递的值应该是字符长度大于或等于给定值才能有效。如果在装饰器中设置此属性，则必须是模型属性类型为`string`或装饰器提供的**type**为`string`。

+   **pattern**：包含 JavaScript 兼容正则表达式的字符串。模型属性中传递的值应与正则表达式匹配才能有效。如果在装饰器中设置此属性，则必须是模型属性类型为`string`或装饰器提供的**type**为`string`。

+   **maxItems**：一个数字，表示模型属性中传递的值应该是数组长度少于或等于给定值才能有效。如果在装饰器中设置此属性，则必须同时提供值为`true`的**isArray**。

+   **minItems**：一个数字，表示模型属性中传递的值应该是数组长度大于或等于给定值才能有效。如果在装饰器中设置此属性，则必须同时提供值为`true`的**isArray**。

+   **uniqueItems**：一个数字，表示模型属性中传递的值应包含一组唯一的数组值。如果在装饰器中设置此属性，则必须同时提供值为`true`的**isArray**。

+   **maxProperties**：一个数字，表示模型属性中传递的值应该包含少于或等于给定值的属性数量才能有效。如果模型属性类型是类或对象，则在装饰器中设置此属性才有效。

+   **minProperties**：一个数字，表示模型属性中传递的值应该包含的属性数量大于或等于给定值才能有效。如果模型属性类型是类或对象，则在装饰器中设置此属性才有效。

+   **readOnly**：一个布尔值，表示模型属性**可能**在 API 响应体中发送，但不应该在请求体中提供。如果您将使用相同的数据模型类来表示 API 的请求和响应体，请使用此选项。

+   **xml**：包含表示模型属性格式的 XML 的字符串。仅当模型属性将包含 XML 时使用。

+   **example**：在 Swagger 文档中放置的示例值。此值还将用于 Swagger UI 中提供的示例，并优先于**default**装饰器属性值。

已使用`@Body`装饰器装饰的属性应始终具有类类型。Typescript 接口无法被装饰，也不提供与带装饰器的类相同的元数据。如果在您的应用程序中，任何一个 API 具有带有`@Body`装饰器和接口类型的属性，则 Nest.js swagger 模块将无法正确创建 Swagger 文档。实际上，Swagger UI 很可能根本不会显示请求体参数。

## @Param

在我们的示例中，`@Param`装饰器包含一个字符串值，指示控制器方法的`comment`参数使用哪个 URL 参数。当 Nest.js swagger 模块遇到提供的字符串的装饰器时，它能够确定 URL 参数的名称，并将其与方法参数提供的类型一起包含在 swagger 文档中。但是，我们也可以在不向`@Param`装饰器传递字符串的情况下编写控制器方法，以获取包含所有 URL 参数的对象。如果这样做，Nest.js 只能在我们将类用作`comment`参数的类型或在控制器方法上使用 Nest.js swagger 模块提供的`@ApiImplicitParam`装饰器时，才能确定 URL 参数的名称和类型。让我们创建一个新类来描述我们的 URL 参数，并看看它如何影响 swagger UI。

```js
export class UpdateCommentParams {
    @ApiModelProperty()
    public entryId: string;

    @ApiModelProperty()
    public commentId: string;
}

```

在`UpdateCommentParams`类中，我们创建了一个属性，并使用了`@ApiModelProperty`装饰器，这样 Nest.js swagger 模块就知道在 swagger 文档中包含属性及其类型。不要尝试将`entryId`拆分成自己的类并扩展它，因为 Nest.js swagger 模块将无法捕捉扩展类的属性。在类中使用的属性名称与`@Controller`和`@Put`装饰器中使用的名称匹配也很重要。我们可以修改我们的评论以使用新的类。

```js
@Put('comments/:commentId')
public async update(
    @Body() body: UpdateCommentRequest,
    @Param() params: UpdateCommentParams,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

我们已更改控制器，以便所有路径参数作为对象提供给控制器方法的`params`参数。

![Comment Put Swagger Example](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example3.png)

swagger UI 已更新，显示评论 put API 需要两个必需的 URL 参数：`entryId`和`commentId`。如果您将编写使用单个参数在方法控制器中包含所有 URL 参数的 API，您应该期望 Nest.js swagger 模块通知您 URL 参数的首选方法。将类用作 URL 参数的类型不仅通知 Nest.js swagger 模块 URL 参数，还通过提供类型检查和代码自动完成来帮助编写应用程序。

然而，如果您不想创建一个新类来用作 URL 参数的类型，可以使用接口，或者一个或多个 URL 参数在 Nest.js 守卫、中间件或自定义装饰器中，而不在控制器方法中。您仍然可以使用`@ApiImplicitParam`装饰器通知 Nest.js swagger 模块有关 URL 参数。

```js
@Put('comments/:commentId')
@ApiImplicitParam({ name: 'entryId' })
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

如果需要路径参数才能到达控制器方法，但控制器方法并未专门使用该参数，Nest.js swagger 模块将不会在 swagger 文档中包含它，除非控制器方法使用了`@ApiImplicitParam`装饰器进行装饰。对于每个必要到达控制器方法的路径参数，使用装饰器一次，但它在控制器本身中并未使用。

```js
@Put('comments/:commentId')
@ApiImplicitParam({ name: 'entryId' })
@ApiImplicitParam({ name: 'commentId' })
public async update(
    @Body() body: UpdateCommentRequest,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

例如，上述控制器作为评论控制器的一部分，需要两个路径参数：`entryId`和`commentId`。由于控制器在方法参数中不包含任何`@Param`装饰器，因此使用`@ApiImplicitParam`来描述两个路径参数。

`@ApiImplicitParam`装饰器可以在传递给装饰器的对象中接受几个附加属性，进一步定义 swagger 文档中的 URL 参数。

+   **name**：包含 URL 参数名称的字符串。这个装饰器属性是唯一必需的。

+   **description**：一个字符串，可用于描述 URL 参数应包含什么或用于什么。

+   **required**：一个布尔值，指示 URL 参数是否是必需的。

+   **type**：包含 swagger 规范中定义的类型之一的字符串。不应使用类和对象。

## @Query

在我们的示例中，`@Query`装饰器包含一个字符串值，指示控制器方法的`testQuery`参数使用哪个查询参数。当 Nest.js swagger 模块遇到提供的字符串的装饰器时，它能够确定查询参数的名称，并将其与方法参数提供的类型一起包含在 swagger 文档中。但是，我们也可以编写控制器方法，而不传递字符串给`@Query`装饰器，以获得包含所有查询参数的对象。如果这样做，Nest.js 只能确定查询参数的名称和类型，如果我们使用类作为`testQuery`参数的类型或在控制器方法上使用 Nest.js swagger 模块提供的`@ApiImplicitQuery`装饰器。让我们创建一个新类来描述我们的查询参数，并看看它如何影响 Swagger UI。

```js
export class UpdateCommentQuery {
    @ApiModelPropertyOptional()
    public testQueryA: string;

    @ApiModelPropertyOptional()
    public testQueryB: string;
}

```

在`UpdateCommentQuery`类中，我们创建了两个属性，并使用`@ApiModelPropertyOptional`装饰器，以便 Nest.js swagger 模块知道在 swagger 文档中包含这些属性及其类型。我们可以更改我们的评论并将控制器方法更改为使用新类。

```js
@Put('comments/:commentId')
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query() queryParameters: UpdateCommentQuery,
    @Headers('testHeader') testHeader: string
) {
}

```

我们已更改控制器，以便所有查询参数作为对象提供给控制器方法的`queryParameters`参数。

![Comment Put Swagger Example](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example4.png)

Swagger UI 已更新以显示注释，并且`put` API 接受两个可选的查询参数：`testQueryA`和`testQueryB`。如果您将编写将在方法控制器中使用单个参数来保存所有查询参数的 API，那么这应该是您首选的方法，以通知 Nest.js swagger 模块您期望作为查询参数的内容。将类用作查询参数的类型不仅通知 Nest.js swagger 模块查询参数，还通过提供类型检查和代码自动完成来帮助编写应用程序。

但是，如果您不希望创建一个新类来用作查询参数的类型，可以使用接口，或者查询参数在 Nest.js 守卫或中间件中使用自定义装饰器，而不是在控制器方法中使用。您仍然可以使用`@ApiImplicitQuery`装饰器通知 Nest.js swagger 模块有关查询参数。

```js
@Put('comments/:commentId')
@ApiImplicitQuery({ name: 'testQueryA' })
@ApiImplicitQuery({ name: 'testQueryB' })
public async update(
    @Param('commentId') comment: string,
    @Body() body: UpdateCommentRequest,
    @Query() testQuery: any,
    @Headers('testHeader') testHeader: string
) {
}

```

如果需要查询参数才能到达控制器方法，但控制器方法没有专门使用查询参数，则 Nest.js swagger 模块将不会在 swagger 文档中包含它，除非控制器方法使用`@ApiImplicitQuery`装饰器进行装饰。对于每个必要到达控制器方法但在控制器本身中未使用的查询参数，使用装饰器一次。

```js
@Put('comments/:commentId')
@ApiImplicitQuery({ name: 'testQueryA' })
@ApiImplicitQuery({ name: 'testQueryB' })
public async update(
    @Param('commentId') comment: string,
    @Body() body: UpdateCommentRequest,
    @Headers('testHeader') testHeader: string
) {
}

```

例如，上述控制器需要两个查询参数：`testQueryA`和`testQueryB`。由于控制器在方法参数中不包含任何`@Query`装饰器，因此使用`@ApiImplicitQuery`来描述两个查询参数。

`@ApiImplicitQuery`装饰器可以在传递给装饰器的对象中接受几个额外的属性，这些属性将进一步定义 swagger 文档中的查询参数。

+   **name**：包含查询参数名称的字符串。这个装饰器属性是唯一必需的。

+   **description**：一个字符串，用于描述查询参数应包含什么或用于什么目的。

+   **required**：一个布尔值，指示查询参数是否是必需的。

+   **type**：包含 swagger 规范中定义的类型之一的字符串。不应使用类和对象。

+   **isArray**：一个布尔值，指示模型属性是否应该采用值数组。如果模型确实采用值数组，请确保在装饰器中包含此值，否则 Nest.js swagger 模块将不知道将模型属性表示为数组。

+   **collectionFormat**：映射到 swagger 规范**collectionFormat**设置。这用于描述如何格式化模型属性数组值。可能的值有：

+   **csv**：逗号分隔的值 `foo,bar`

+   **ssv**：空格分隔的值 `foo bar`

+   **tsv**：制表符分隔的值 `foo\tbar`

+   **pipes**：管道分隔的值 `foo|bar`

+   **multi**：对应于多个参数实例，而不是单个实例的多个值 foo=bar&foo=baz。这仅对“query”或“formData”中的参数有效。

## @Headers

在我们的示例中，`@Headers`装饰器包含一个字符串值，指示控制器方法的`testHeader`参数使用哪个请求头值。当 Nest.js swagger 模块遇到提供的字符串的装饰器时，它能够确定请求头的名称，并将其与方法参数提供的类型一起包含在 swagger 文档中。然而，我们也可以编写控制器方法，而不向`@Headers`装饰器传递字符串，以获得包含所有请求头的对象。如果我们这样做，Nest.js 只能确定请求头的名称和类型，如果我们使用类作为`testHeader`参数的类型，或者在控制器方法上使用 Nest.js swagger 模块提供的`@ApiImplicitHeader`装饰器。让我们创建一个新类来描述我们的查询参数，并看看它如何影响 swagger UI。

```js
export class UpdateCommentHeaders {
    @ApiModelPropertyOptional()
    public testHeaderA: string;

    @ApiModelPropertyOptional()
    public testHeaderB: string;
}

```

在`UpdateCommentHeaders`类中，我们创建了两个属性，并使用`@ApiModelPropertyOptional`装饰器，以便 Nest.js swagger 模块知道在 swagger 文档中包含这些属性及其类型。我们可以更改我们的评论`put`控制器方法以使用新类。

```js
@Put('comments/:commentId')
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers() headers: UpdateCommentHeaders
) {
}

```

我们已更改控制器，以便将控制器方法期望的所有请求参数作为对象提供给控制器方法的`queryParameters`参数。

![评论放置 Swagger 示例](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example5.png)

swagger UI 已更新，显示评论`put` API 需要两个头部：`testHeaderA`和`testHeaderB`。如果您将编写使用单个参数在方法控制器中保存所有预期头部的 API，这应该是通知 Nest.js swagger 模块您期望的首选方法。使用类作为预期头部的类型不仅通知 Nest.js swagger 模块头部，还通过提供类型检查和代码自动完成来帮助编写应用程序。

然而，如果您不希望创建一个新类作为预期头部的类型，您可以使用接口，或者头部用于 Nest.js 守卫、中间件或自定义装饰器，而不是在控制器方法中使用。您仍然可以使用`@ApiImplicitHeader`或`@ApiImplicitHeaders`装饰器通知 Nest.js swagger 模块有关查询参数。

```js
@Put('comments/:commentId')
@ApiImplicitHeader({ name: 'testHeader' })
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers() headers: any
) {
}

```

如果需要一个头部才能到达控制器方法，但控制器方法没有专门使用头部。除非控制器方法使用`@ApiImplicitHeader`或`@ApiImplicitHeaders`装饰器进行装饰，否则 Nest.js swagger 模块不会将其包含在 swagger 文档中。对于每个头部使用一次`@ApiImplicitHeader`装饰器，或者一次使用`@ApiImplicitHeaders`装饰器来描述所有头部是必要的。这是为了到达控制器方法，但它在控制器本身中没有使用。

```js
@Put('comments/:commentId')
@ApiImplicitHeader({ name: 'testHeaderA' })
@ApiImplicitHeader({ name: 'testHeaderB' })
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
) {
}

@Put('comments/:commentId')
@ApiImplicitHeader([
    { name: 'testHeaderA' },
    { name: 'testHeaderB' }
])
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
) {
}

```

例如，上述控制器需要两个头部：`testHeaderA`和`testHeaderB`。由于控制器方法在方法参数中不包含`@Headers`装饰器，因此使用`@ApiImplicitHeader`和`@ApiImplicitHeaders`来描述两个头部。

`@ApiImplicitHeader`和`@ApiImplicitHeaders`装饰器可以在对象或对象数组中接受几个额外的属性，分别传递给装饰器，以进一步定义 swagger 文档中的查询参数。

+   **name**：包含标头名称的字符串。这个装饰器属性是唯一必需的。

+   **description**：一个字符串，可用于描述标头应包含什么或用于什么。

+   **required**：一个布尔值，指示标头是否是必需的。

**注意：**`@ApiImplicitHeaders`装饰器只是使用`@ApiImplicitHeader`装饰器的快捷方式多次。如果需要描述多个标头，请使用`@ApiImplicitHeaders`。此外，您不应该使用这些标头来描述身份验证机制。有其他装饰器可以用于此目的。

## 身份验证

很可能您在某个时候需要在应用程序中设置某种形式的身份验证。博客示例应用程序使用`用户名`和`密码`组合来验证用户，并提供 JSON Web 令牌以允许用户访问 API。无论您决定如何设置身份验证，有一点是肯定的：您将需要查询参数或标头来维护身份验证状态，并且您很可能会使用 Nest.js 中间件或守卫来检查用户的身份验证状态。您这样做是因为在每个控制器方法中编写该代码会创建大量的代码重复，并且会使每个控制器方法变得复杂。

如果您的应用程序需要身份验证，请确保使用`addOAuth2`或`addBearerAuth`方法正确配置文档设置。如果您不确定这些方法的作用，请参考**文档设置**部分。

除了为 swagger 文档设置身份验证方案之外，您还应该在控制器类或控制器方法上使用`ApiBearerAuth`和/或`ApiOAuth2Auth`装饰器。当用于整个控制器类时，这些装饰器会通知 Nest.js swagger 模块所有控制器方法都需要身份验证。如果不是所有控制器方法都需要身份验证，则需要装饰那些需要的单个控制器方法。

```js
@Put('comments/:commentId')
@ApiBearerAuth()
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

此示例描述了一个需要持有者令牌才能使用 API 的单个控制器方法 API。

```js
@Put('comments/:commentId')
@ApiOAuth2Auth(['test'])
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

此示例描述了一个需要特定 OAuth2 角色集才能使用 API 的单个控制器方法 API。`@ApiOAuth2Auth`装饰器接受用户应具有的所有角色的数组，以便访问 API。

这些装饰器与`ApiBearerAuth`和`ApiOAuth2Auth`文档设置一起使用，以构建用户可以输入其凭据（API 密钥或 Oauth 密钥）并选择其角色（如果使用 OAuth2）的表单，位于 swagger UI 内。然后，当用户执行特定 API 时，这些值将传递到适当的位置，即作为查询参数或标头值。

![Swagger UI 登录表单](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/swagger-ui-login.png)

单击 swagger UI 页面顶部的**授权**按钮将打开授权表单。对于持有者令牌，请登录应用程序并将返回的授权令牌复制到 swagger UI 授权中提供的空间中。令牌应该是`Bearer <TOKEN VALUE>`的形式。对于 OAuth2 身份验证，请输入您的凭据并选择您要请求的角色。单击**授权**按钮将保存凭据，以便在 swagger UI 中执行 API 时使用。

# API 请求和响应装饰器

到目前为止，我们主要关注装饰控制器，以便 Nest.js swagger 模块可以构建包含我们的 API 期望或可能使用的所有输入的 swagger 文档。Nest.js swagger 模块还包含可以用于描述 API 如何响应以及它期望接收和发送的内容格式的装饰器。这些装饰器有助于在查看 swagger 文档或使用 swagger UI 时形成特定 API 如何工作的完整图像。

我们在示例博客应用中涵盖的所有 API 都遵循接受 JSON 形式输入的典型模式。然而，应用程序可能需要接受不同的输入类型，通常称为 MIME 类型。例如，我们可以允许我们示例博客应用的用户上传头像图像。图像不能轻松地表示为 JSON，因此我们需要构建一个接受`image/png`输入 MIME 类型的 API。我们可以通过使用`@ApiConsumes`装饰器确保这些信息存在于我们应用程序的 swagger 文档中。

```js
@Put('comments/:commentId')
@ApiConsumes('image/png')
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

在这个例子中，我们使用了`@ApiConsumes`装饰器来告知 Nest.js swagger 模块，评论`put` API 预期接收一个 png 图像。

![评论 Put Swagger UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example6.png)

Swagger UI 现在显示**参数内容类型**下拉菜单为`image/png`。`@ApiConsumes`装饰器可以接受任意数量的 MIME 类型作为参数。装饰器中的多个值将导致**参数内容类型**下拉菜单包含多个值，第一个值始终是默认值。如果控制器专门用于处理特定的 MIME 类型，比如`application/json`，则可以将`@ApiConsumes`装饰器放在控制器类上，而不是每个单独的控制器方法上。然而，如果您的 API 将消耗 JSON，可以不使用装饰器，Nest.js swagger 模块将默认 API 为`application/json`。

除了消耗各种 MIME 数据类型外，API 还可以响应各种 MIME 数据类型。例如，我们虚构的头像上传 API 可能会将图像存储在数据库或云存储提供商中。这样的存储位置可能不直接对用户可访问，因此可以创建一个 API 来查找并返回任何用户的头像图像。我们可以使用`@ApiProduces`装饰器来告知 Nest.js swagger 模块，API 使用`image/png` MIME 类型返回数据。

```js
@Put('comments/:commentId')
@ApiProduces('image/png')
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

在这个例子中，我们使用了`@ApiProduces`装饰器来告知 Nest.js swagger 模块，评论`put` API 预期返回一个 png 图像。

![评论 Put Swagger UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example7.png)

Swagger UI 现在显示**响应内容类型**下拉菜单为`image/png`。`@ApiProduces`装饰器可以接受任意数量的 MIME 类型作为参数。装饰器中的多个值将导致**响应内容类型**下拉菜单包含多个值，第一个值始终是默认值。如果控制器专门用于处理特定的 MIME 类型，比如`application/json`，则可以将`@ApiConsumes`装饰器放在控制器类上，而不是每个单独的控制器方法上。然而，如果您的 API 将消耗 JSON，可以不使用装饰器，Nest.js swagger 模块将默认 API 为`application/json`。

请求和响应的 MIME 类型信息在很大程度上可以告知 Swagger 文档的最终使用方式，以及如何使用 API 以及 API 的工作原理。然而，我们并没有完全记录 API 可能会响应的所有内容。例如，API 响应体中包含哪些数据值，以及可能返回的 HTTP 状态码是什么？可以使用`@ApiResponse`装饰器提供这样的信息。

`@ApiResponse`装饰器可以放在单个控制器方法上，也可以放在控制器类上。Nest.js swagger 模块将收集控制器类级别的装饰器数据，并将其与控制器方法的装饰器数据配对，以生成每个单独 API 可能产生的可能响应列表。

```js
@Controller('entries/:entryId')
@ApiResponse({
    status: 500,
    description: 'An unknown internal server error occurred'
})
export class CommentController {
    @Put('comments/:commentId')
    @ApiResponse({
        status: 200,
        description: 'The comment was successfully updated',
        type: UpdateCommentResponse
    })
    public async update(
        @Body() body: UpdateCommentRequest,
        @Param('commentId') comment: string,
        @Query('testQuery') testQuery: string,
        @Headers('testHeader') testHeader: string
    ) {
    }
}

```

在这个例子中，我们装饰了评论控制器，以便所有的 API 都包含一个用于内部服务器错误的通用响应。更新控制器方法已被装饰，以便状态码为`200`的响应表示评论已成功更新。类型是另一个数据模型，用于向 Nest.js swagger 模块提供有关响应体中各个属性的信息。

```js
export class UpdateCommentResponse {
  @ApiModelPropertyOptional()
  public success?: boolean;
}

```

`UpdateCommentResponse`数据模型包含一个可选属性`success`，可以进一步向 UI 传达评论已成功更新的信息。

![评论放置 swagger UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example8.png)

现在 swagger UI 在 API 卡的**响应**部分列出了两种可能的响应。使用`@ApiResponse`装饰器来告知用户关于使用 API 时可能需要处理的不同成功和错误场景。`@ApiResponse`装饰器可以在传递给它的对象中接受其他属性。

+   **status**：包含 API 将响应的 HTTP 状态码的数字。这个装饰器属性是唯一必需的。

+   **description**：一个字符串，可用于描述响应表示什么或者用户在遇到响应时应该如何反应。

+   **type**：使用数据模型类中 swagger 规范定义的任何数据类型，来告知用户可以在响应体中期望什么。如果使用了**isArray**属性，它表示响应将是一个包含提供类型的值的数组。

+   **isArray**：一个布尔值，指示响应体是否包含一系列值。如果响应体将包含一系列值，请确保在装饰器中包含此值，否则 Nest.js swagger 模块将不知道如何表示响应体为一系列值。

# API 元数据装饰器

如果你在任何 Nest.js 项目中工作，并且正确地使用我们到目前为止介绍的装饰器装饰所有的控制器和控制器方法，Nest.js swagger 模块生成的 swagger 文档将包含用户理解和使用 API 所需的每一个技术细节。在本章中，我们将介绍的最后两个装饰器只是为 swagger 文档提供更多的元数据。swagger UI 将使用这些元数据来生成更清晰的 UI，但功能不会改变。

我们将要介绍的第一个装饰器是`@ApiOperation`。不要将这个装饰器与`@Put`之类的 HTTP 方法装饰器混淆。这个装饰器用于为单个控制器方法提供**标题**、**描述**和称为**operationId**的唯一标识符。

```js
@Put('comments/:commentId')
@ApiOperation({
    title: 'Comment Update',
    description: 'Updates a specific comment with new content',
    operationId: 'commentUpdate'
})
public async update(
    @Body() body: UpdateCommentRequest,
    @Param('commentId') comment: string,
    @Query('testQuery') testQuery: string,
    @Headers('testHeader') testHeader: string
) {
}

```

在这个例子中，我们提供了一个简短的**标题**和一个更长的**评论放置 API 的描述**。**标题**应该保持简短，少于 240 个字符，并用于填充 swagger 规范的`summary`部分。虽然例子中的**描述**很短，但在你自己的项目中使用详细的描述。这应该传达用户为什么会使用 API 或者通过使用 API 可以实现什么。**operationId**必须根据 swagger 文档保持唯一。该值可以在各种 swagger 代码生成项目中用来引用特定的 API。

![评论放置 swagger UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/comment-put-swagger-example9.png)

在 swagger UI 中，我们可以看到我们传递给`@ApiOperation`装饰器的值，以及它们如何用来填充 API 卡的附加细节。**标题**放在 API 路径旁的标题中。**描述**是标题后面 API 卡中的第一部分信息。我们可以看到，使用长**标题**和**描述**会对 API 卡标题产生负面影响，但在 API 卡正文中效果非常好。

![评论放置 Swagger UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/basic-swagger-ui1.png)

从整体上看 Swagger UI 应用程序，我们可以看到示例博客应用程序的所有 API 都被分组在一起。虽然这样可以工作，但更好的是根据它们执行的操作或资源（评论、条目或关键字）对 API 进行分组。这就是`@ApiUseTags`装饰器的用途。

`@ApiUseTags`装饰器可以放置在控制器类或单个控制器方法上，并且可以接受任意数量的字符串参数。这些值将被放置在 swagger 文档中的每个单独 API 中。

```js
@Controller('entries/:entryId')
@ApiUseTags('comments')
export class CommentController {

}

```

在这个例子中，我们装饰了评论控制器类，以便所有控制器方法都被赋予`comments`标签。

![评论放置 Swagger UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/basic-swagger-ui2.png)

Swagger UI 现在使用标签对 API 进行分组。这确保了类似的 API 被分组，并在每个组之间提供一些间距，以产生更美观的 UI。这些组也是可展开和可折叠的，让用户有隐藏他们可能不感兴趣的 API 的选项。

# 保存 swagger 文档

我们已经介绍了 Nest.js swagger 模块中所有可用的装饰器，以及 Nest.js 中已有的装饰器，以生成 swagger 文档并公开 swagger UI。当您的 API 主要由开发人员在其自己的项目中使用，或者在本地开发服务器或分期环境中测试 API 时，这非常有效。对于主要用于特定前端应用程序的 API，您可能不希望公开 swagger UI 供一般公众使用。在这种情况下，您仍然可以生成 swagger 文档以供存储，并在您自己或您团队的其他项目中使用。

为了实现这一点，我们将编写一个新的 Typescript 文件，可以作为构建链的一部分执行。我们将使用`fs-extras` NodeJS 模块，使文件写入磁盘变得更简单。

```js
import * as fs from 'fs-extra';

async function writeDoc() {
    const app = await NestFactory.create(AppModule);
    const document = SwaggerModule.createDocument(app, swaggerOptions);

    fs.ensureDirSync(path.join(process.cwd(), 'dist'));
    fs.writeJsonSync(path.join(process.cwd(), 'dist', 'api-doc.json'), document, { spaces: 2 });
}

writeDoc();

```

您可以将此文件放在项目的根目录或源目录中，并使用 NPM 脚本条目来执行它，或者使用 NodeJS 运行它。示例代码将使用 Nest.js swagger 模块构建 swagger 文档，并使用`fs-extras`将文档写入`dist`目录作为 JSON 文件。

# 总结

在本章中，我们介绍了 Nest.js swagger 模块如何利用您在应用程序中使用的现有装饰器来创建 swagger v2 规范文档。我们还介绍了 Nest.js swagger 模块提供的所有额外装饰器，以增强 swagger 文档中的信息。我们还设置了示例博客应用程序以公开 swagger UI。

使用 Nest.js swagger 模块不仅可以记录应用程序的控制器，还可以为测试应用程序提供 UI。如果您完全记录了应用程序，Swagger UI 可以是一个很好的替代 UI，或者提供一个简单的测试区域，您或您的用户可以使用，而不必在应用程序的真实 UI 中观察网络调用。Swagger UI 也可以是 Postman 等工具的很好替代品。

如果您不希望使用 Swagger UI 或在生产环境中公开您的 swagger 文档，记住您可以始终将文件写入磁盘作为应用程序的单独构建作业。这允许您以多种方式存储和使用文档，尤其是使用 Swagger Codegen。

下一章将带您了解命令查询责任分离（CQRS）。


# 第十二章：命令查询职责分离（CQRS）

在本书的这一部分，我们已经努力使用 CRUD 模式构建了一个简单的博客应用程序：创建、检索、更新和删除。我们已经非常好地确保服务处理我们的业务逻辑，而我们的控制器只是这些服务的网关。控制器负责验证请求，然后将请求传递给服务进行处理。在这样一个小型应用程序中，CRUD 非常有效。

但是当我们处理可能具有独特和复杂业务逻辑的大型应用程序时会发生什么？或者也许我们希望在后台启动一些逻辑，以便 UI 能够调用 API 而无需等待所有业务逻辑完成。这些是 CQRS 有意义的领域。CQRS 可以用于隔离和分解复杂的业务逻辑，同步或异步地启动该业务逻辑，并组合这些隔离的部分来解决新的业务问题。

Nest.js 通过提供两个单独的流来实现 CQRS 的命令方面：一个命令总线和一个事件总线，还有一些 sagas 的糖。在本章中，我们将解决向博客条目添加关键字元数据的问题。我们当然可以使用 CRUD 模式来做到这一点，但是让 UI 进行多个 API 调用来存储博客条目及其所有关键字，甚至让我们的博客条目模块执行这一操作，都会使 UI 和我们的应用程序的业务逻辑变得复杂。

相反，我们将转换博客条目模块以使用 CQRS 命令，并使用命令`总线`来执行所有数据持久化，将其从博客条目模块中的服务中移除。我们将为我们的关键字创建一个新的实体和模块。关键字实体将维护最后更新的时间戳和所有关联条目的引用。将创建两个新的 API：一个提供“热门关键字”的列表，另一个提供与关键字关联的所有条目的列表。

为了确保 UI 不会遭受任何性能损失，所有关键字实体操作将以异步方式进行。关键字将以字符串形式存储在博客条目实体上，以便 UI 可以快速引用而无需查询数据库中的关键字表。在开始之前，请确保在项目中运行了`npm install @nestjs/cqrs`。要查看一个工作示例，记住你可以克隆本书的附带 Git 存储库：

`git clone https://github.com/backstopmedia/nest-book-example.git`

# 入口模块命令

为了使围绕入口模型的业务逻辑更容易扩展，我们首先需要将模块服务中更新数据库的方法提取为单独的命令。让我们首先将博客条目的`create`方法转换为 Nest.js CQRS 风格的命令。

```js
export class CreateEntryCommand implements ICommand {
    constructor(
        public readonly title: string,
        public readonly content: string,
        public readonly userId: number
    ) {}
}

```

我们的命令是一个简单的对象，实现了`ICommand`接口。`ICommand`接口在 Nest.js 内部用于指示对象是一个命令。这个文件通常在我们模块的子目录中创建，模式类似于`commands/impl/`。现在我们已经完成了一个示例，让我们完成评论模块的其余命令。

```js
export class UpdateEntryCommand implements ICommand {
    constructor(
        public readonly id: number,
        public readonly title: string,
        public readonly content: string
    ) {}
}

export class DeleteEntryCommand implements ICommand {
    constructor(
        public readonly id: number
    ) {}
}

```

注意更新和删除命令的一些区别？对于更新命令，我们需要知道正在更新的数据库模型。同样，对于删除命令，我们只需要知道要删除的数据库模型的 id。在这两种情况下，拥有`userId`是没有意义的，因为博客条目永远不会移动到另一个用户，并且`userId`对博客条目的删除没有影响。

## 命令处理程序

现在我们有了用于数据库写操作的命令，我们需要一些命令处理程序。每个命令应该以一对一的方式有一个相应的处理程序。命令处理程序很像我们当前的博客条目服务。它将负责所有数据库操作。通常，命令处理程序放在模块的子目录中，类似于`commands/handlers`。

```js
@CommandHandler(CreateEntryCommand)
export class CreateEntryCommandHandler implements ICommandHandler<CreateEntryCommand> {
    constructor(
        @Inject('EntryRepository') private readonly entryRepository: typeof Entry,
        @Inject('SequelizeInstance') private readonly sequelizeInstance
    ) { }

    async execute(command: CreateEntryCommand, resolve: () => void) {
    }
}

```

命令处理程序是简单的类，具有一个名为`execute`的方法，负责处理命令。实现`ICommandHandler<CreateEntryCommand>`接口有助于确保我们正确编写命令处理程序。在我们的示例中，Nest.js 使用`@CommandHandler`注解来知道这个类是用来处理我们的新`CreateEntryCommand`命令的。

由于命令处理程序将成为模块服务的替代品，因此命令处理程序还需要访问我们的数据库。这可能会有所不同，取决于您使用的 ORM 以及应用程序的配置方式。实际上，我们的命令处理程序目前并没有做任何事情。事实上，使用它会破坏应用程序，因为我们还没有实现`execute`方法的细节。

```js
async execute(command: CreateEntryCommand, resolve: () => void) {
    await this.sequelizeInstance.transaction(async transaction => {
        return await this.entryRepository.create<Entry>(command, {
            returning: true,
            transaction
        });
    });

    resolve();
}

```

如果您正在跟随示例项目，您可能会注意到我们的`execute`方法几乎与博客条目服务的`create`方法相似。实际上，命令处理程序的几乎所有代码都是直接从博客条目服务复制而来的。最大的区别是我们不返回一个值。相反，所有命令处理程序的`execute`方法都将回调方法作为它们的第二个参数。

Nest.js 允许我们对提供给`execute`方法的回调执行几种不同的操作。在我们的示例中，我们使用 ORM 来创建和保存新的博客条目。一旦事务解决，我们调用`resolve`回调来让 Nest.js 知道我们的命令已经执行完毕。如果这看起来很熟悉，那是因为在幕后，Nest.js 正在将我们的`execute`包装在一个 Promise 中，并将 promise 自己的`resolve`回调作为我们的`execute`方法的第二个参数传递进去。

请注意，我们的命令处理程序没有传递`reject`回调。Nest.js 在调用命令处理程序时不执行任何类型的错误处理。由于我们的命令处理程序正在调用 ORM 将数据存储在数据库中，很可能会抛出异常。如果我们当前的命令处理程序发生这种情况，根据使用的 NodeJS 版本，控制台可能会记录`UnhandledPromiseRejectionWarning`警告，并且 UI 将一直等待 API 返回直到超时。为了防止这种情况，我们应该将命令处理程序逻辑包装在`try...catch`块中。

```js
async execute(command: CreateEntryCommand, resolve: () => void) {
    try {
        await this.sequelizeInstance.transaction(async transaction => {
            return await this.entryRepository.create<Entry>(command, {
                returning: true,
                transaction
            });
        });
    } catch (error) {

    } finally {
        resolve();
    }
}

```

请注意，我们在`finally`块中调用`resolve`回调。这是为了确保无论结果如何，命令处理程序都将完成执行，API 都将完成处理。但是当我们的 ORM 抛出异常时会发生什么呢？博客条目没有保存到数据库中，但由于 API 控制器不知道发生了错误，它将向 UI 返回一个 200 的 HTTP 状态。为了防止这种情况，我们可以捕获错误并将其作为参数传递给`resolve`方法。这可能会违反 CQRS 模式，但是让 UI 知道发生了错误要比假设博客条目已保存更好。

```js
async execute(command: CreateEntryCommand, resolve: (error?: Error) => void) {
    let caught: Error;

    try {
        await this.sequelizeInstance.transaction(async transaction => {
            return await this.entryRepository.create<Entry>(command, {
                returning: true,
                transaction
            });
        });
    } catch (error) {
        caught = error
    } finally {
        resolve(caught);
    }
}

```

**注意：** Nest.js 没有规定回调方法必须在何时被调用。我们可以在`execute`方法的开头调用回调。Nest.js 会将处理返回给控制器，因此 UI 会立即更新，并在之后处理`execute`方法的其余部分。

让我们通过创建命令来处理更新和删除数据库中的博客条目，完成将我们的博客条目模块转换为 CQRS。

```js
@CommandHandler(UpdateEntryCommand)
export class UpdateEntryCommandHandler implements ICommandHandler<UpdateEntryCommand> {
    constructor(
        @Inject('EntryRepository') private readonly entryRepository: typeof Entry,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize,
        private readonly databaseUtilitiesService: DatabaseUtilitiesService
    ) { }

    async execute(command: UpdateEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                let entry = await this.entryRepository.findById<Entry>(command.id, { transaction });
                if (!entry) throw new Error('The blog entry was not found.');

                entry = this.databaseUtilitiesService.assign(
                    entry,
                    {
                        ...command,
                        id: undefined
                    }
                );
                return await entry.save({
                    returning: true,
                    transaction,
                });
            });
        } catch (error) {
            caught = error
        } finally {
            resolve(caught);
        }
    }
}

```

我们的`UpdateEntryCommand`命令的命令处理程序需要对博客条目服务中的内容进行一些更改。由于我们的命令包含了要更新的博客条目的所有数据，包括`id`，我们需要剥离`id`并将命令中的其余值应用到实体中，然后将其保存回数据库。就像我们上一个命令处理程序一样，我们使用`try...catch`来处理错误，并将任何抛出的异常作为参数传递回`resolve`回调函数。

```js
@CommandHandler(DeleteEntryCommand)
export class DeleteEntryCommandHandler implements ICommandHandler<DeleteEntryCommand> {
    constructor(
        @Inject('EntryRepository') private readonly entryRepository: typeof Entry,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize
    ) { }

    async execute(command: DeleteEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                return await this.entryRepository.destroy({
                    where: { id: command.id },
                    transaction,
                });
            });
        } catch (error) {
            caught = error
        } finally {
            resolve(caught);
        }

        resolve();
    }
}

```

我们的`DeleteEntryCommand`的命令处理程序基本上是博客条目服务中`delete`方法的副本。我们现在有了三个新的命令及其相应的处理程序。剩下的就是将它们连接起来并开始使用它们。在我们这样做之前，我们必须决定在哪里调用这些新命令。

## 调用命令处理程序

文档和 NodeJS 应用程序中关于关注点分离的一般共识可能会指示我们从博客条目服务中调用我们的命令。这样做会使控制器像现在这样简单，但不会简化服务。或者，我们将采取的方法是减少服务的复杂性，使其严格用于数据检索，并从控制器中调用我们的命令。无论采取哪种路线，利用新命令的第一步是注入 Nest.js 的`CommandBus`。

**注意：**您计划在哪里使用您的命令，无论是控制器还是服务，对于实现都没有影响。请随意尝试。

```js
@Controller()
export class EntryController {
    constructor(
        private readonly entryService: EntryService,
        private readonly commandBus: CommandBus
    ) { }

    @Post('entries')
    public async create(@User() user: IUser, @Body() body: any, @Res() res) {
        if (!body || (body && Object.keys(body).length === 0)) return res.status(HttpStatus.BAD_REQUEST).send('Missing some information.');

        const error = await this.commandBus.execute(new CreateEntryCommand(
            body.title,
            body.content,
            user.id
        ));

        if (error) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(result);
        } else {
            return res.set('location', `/entries/${result.id}`).status(HttpStatus.CREATED).send();
        }
    }

```

上面的例子包含了两个关键更改。首先，我们已经将`commandBus`添加到构造函数中。Nest.js 会为我们注入一个`CommandBus`的实例到这个变量中。最后一个更改是`create`控制器方法。我们不再调用博客条目服务中的`create`方法，而是使用命令总线创建和执行一个新的`CreateEntryCommand`。博客条目控制器的其余实现细节几乎与`create`方法的模式相同。

```js
@Controller()
export class EntryController {
    constructor(
        private readonly entryService: EntryService,
        private readonly commandBus: CommandBus
    ) { }

    @Get('entries')
    public async index(@User() user: IUser, @Res() res) {
        const entries = await this.entryService.findAll();
        return res.status(HttpStatus.OK).json(entries);
    }

    @Post('entries')
    public async create(@User() user: IUser, @Body() body: any, @Res() res) {
        if (!body || (body && Object.keys(body).length === 0)) return res.status(HttpStatus.BAD_REQUEST).send('Missing some information.');

        const error = await this.commandBus.execute(new CreateEntryCommand(
            body.title,
            body.content,
            user.id
        ));

        if (error) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(result);
        } else {
            return res.set('location', `/entries/${result.id}`).status(HttpStatus.CREATED).send();
        }
    }

    @Get('entries/:entryId')
    public async show(@User() user: IUser, @Entry() entry: IEntry, @Res() res) {
        return res.status(HttpStatus.OK).json(entry);
    }

    @Put('entries/:entryId')
    public async update(@User() user: IUser, @Entry() entry: IEntry, @Param('entryId') entryId: number, @Body() body: any, @Res() res) {
        if (user.id !== entry.userId) return res.status(HttpStatus.NOT_FOUND).send('Unable to find the entry.');
        const error = await this.commandBus.execute(new UpdateEntryCommand(
            entryId,
            body.title,
            body.content,
            user.id
        ));

        if (error) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(error);
        } else {
            return res.status(HttpStatus.OK).send();
        }
    }

    @Delete('entries/:entryId')
    public async delete(@User() user: IUser, @Entry() entry: IEntry, @Param('entryId') entryId: number, @Res() res) {
        if (user.id !== entry.userId) return res.status(HttpStatus.NOT_FOUND).send('Unable to find the entry.');
        const error = await this.commandBus.execute(new DeleteEntryCommand(entryId));

        if (error) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(error);
        } else {
            return res.status(HttpStatus.OK).send();
        }
    }
}

```

从这个例子中可以看出，控制器已经更新，所以博客条目服务只用于检索，所有修改方法现在都在命令总线上分发命令。我们需要配置的最后一件事是博客条目模块。为了使这更容易，让我们首先设置一个 Typescript barrel 来将所有处理程序导出为一个单一变量。

```js
export const entryCommandHandlers = [
    CreateEntryCommandHandler,
    UpdateEntryCommandHandler,
    DeleteEntryCommandHandler
];

```

将 barrel 导入到博客条目模块中，并将模块连接到命令总线。

```js
@Module({
    imports: [CQRSModule, EntryModule],
    controllers: [CommentController],
    components: [commentProvider, CommentService, ...CommentCommandHandlers],
    exports: [CommentService]
})
export class EntryModule implements NestModule, OnModuleInit {
    public constructor(
        private readonly moduleRef: ModuleRef,
        private readonly commandBus: CommandBus
    ) {}

    public onModuleInit() {
        this.commandBus.setModuleRef(this.moduleRef);
        this.commandBus.register(CommentCommandHandlers);
    }
}

```

为了将我们的模块连接到命令总线，我们将`CQRSModule`导入到我们的模块定义中，并将`ModuleRef`和`CommandBus`注入到模块类构造函数中。模块类还需要实现`OnModuleInit`接口。最后，在`onModuleInit`生命周期钩子中发生了魔术。Nest.js 将在实例化我们的模块类后立即执行此方法。在方法内部，我们使用`setModuleRef`和`register`将博客条目命令处理程序注册到为该模块创建的命令总线中。

**注意：**如果您跟随并在控制器中实现了命令的调用，您可以从评论服务中删除`create`、`update`和`delete`方法。

![CQRS Comments Flow](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/CQRSFlow001.png)

上面的图表提供了入口控制器的命令和查询方面如何被划分的可视化表示。当用户发送请求到`create`控制器方法时，处理是通过 CQRS 命令总线执行的，但仍然使用 ORM 来更新数据库。当用户希望检索所有条目时，入口控制器使用`EntryService`，然后使用 ORM 来查询数据库。所有命令（CQRS 中的`C`）现在都通过命令总线处理，而所有查询（CQRS 中的`Q`）仍然通过入口服务处理。

# 将关键字与事件链接起来

现在我们已经展示了在 Nest.js CQRS 中创建命令并使用命令总线的基础知识，我们需要解决存储与博客条目关联的关键字。关键字可以在创建博客条目时添加，并在以后删除。我们可以为关键字创建一个新实体，并使条目实体维护与关键字实体的一对多关系。然而，这将需要我们的数据库查找从更多的表中拉取更多的数据，并且发送回 UI 的响应将变得更大。相反，让我们从只将关键字作为 JSON 字符串存储在博客条目实体上开始。为此，我们需要更新博客条目实体并添加一个新字段。

```js
@Table(tableOptions)
export class Entry extends Model<Entry> {

    @Column({
        type: DataType.TEXT,
        allowNull: true,

    })
    public keywords: string;

}

```

新数据库列的 ORM 定义将取决于您正在使用的 ORM 和数据库服务器。在这里，我们使用`TEXT`数据类型。这种数据类型在许多不同的数据库服务器中得到广泛支持，并提供了存储数据量的大限制。例如，Microsoft SQL Server 将此字段限制为最多 2³⁰-1 个字符，而 Postgres 则不施加限制。由于我们正在使用具有迁移功能的 ORM，因此我们还需要创建迁移脚本。如果您不确定如何操作，请参考 TypeORM 或 Sequelize 章节。

```js
export async function up(sequelize) {
    // language=PostgreSQL
    await sequelize.query(`
        ALTER TABLE entries ADD COLUMN keywords TEXT;
    `);

    console.log('*keywords column added to entries table*');
}

export async function down(sequelize) {
    // language=PostgreSQL
    await sequelize.query(`
        ALTER TABLE entries DROP COLUMN keywords;
    `);
}

```

如果您一直在跟进，您的条目数据库表现在应该有一个关键字列。测试博客条目控制器中的`index` API 现在应返回带有关键字值的对象。我们仍然需要更新博客条目命令、命令处理程序和控制器，以处理新的和更新的博客条目的关键字。

```js
@Controller()
export class EntryController {

    @Post('entries')
    public async create(@User() user: IUser, @Body() body: any, @Res() res) {
        if (!body || (body && Object.keys(body).length === 0)) return res.status(HttpStatus.BAD_REQUEST).send('Missing some information.');

        const error = await this.commandBus.execute(new CreateEntryCommand(
            body.title,
            body.content,
            body.keywords,
            user.id
        ));

        if (error) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(result);
        } else {
            return res.set('location', `/entries/${result.id}`).status(HttpStatus.CREATED).send();
        }
    }

    @Put('entries/:entryId')
    public async update(@User() user: IUser, @Entry() entry: IEntry, @Param('entryId') entryId: number, @Body() body: any, @Res() res) {
        if (user.id !== entry.userId) return res.status(HttpStatus.NOT_FOUND).send('Unable to find the entry.');
        const error = await this.commandBus.execute(new UpdateEntryCommand(
            entryId,
            body.title,
            body.content,
            body.keywords,
            user.id
        ));

        if (error) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(error);
        } else {
            return res.status(HttpStatus.OK).send();
        }
    }
}

```

博客条目控制器将接受关键字作为字符串数组。这将有助于保持 UI 简单，并防止 UI 执行任意字符串解析。

```js
export class CreateEntryCommand implements ICommand, IEntry {
    constructor(
        public readonly title: string,
        public readonly content: string,
        public readonly keywords: string[],
        public readonly userId: number
    ) {}
}

export class UpdateEntryCommand implements ICommand, IEntry {
    constructor(
        public readonly id: number,
        public readonly title: string,
        public readonly content: string,
        public readonly keywords: string[],
        public readonly userId: number
    ) {}
}

```

`CreateEntryCommand`和`UpdateEntryCommand`命令已更新以接受新属性`keywords`。我们保持字符串数组类型，以便将命令的处理转移到命令处理程序。

```js
@CommandHandler(CreateEntryCommand)
export class CreateEntryCommandHandler implements ICommandHandler<CreateEntryCommand> {

    async execute(command: CreateEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                return await this.EntryRepository.create<Entry>({
                    ...command,
                    keywords: JSON.stringify(command.keywords)
                }, {
                    returning: true,
                    transaction
                });
            });
        } catch (error) {
            caught = error;
        } finally {
            resolve(caught);
        }
    }
}

@CommandHandler(UpdateEntryCommand)
export class UpdateEntryCommandHandler implements ICommandHandler<UpdateEntryCommand> {

    async execute(command: UpdateEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                let comment = await this.EntryRepository.findById<Entry>(command.id, { transaction });
                if (!comment) throw new Error('The comment was not found.');

                comment = this.databaseUtilitiesService.assign(
                    comment,
                    {
                        ...command,
                        id: undefined,
                        keywords: JSON.stringify(command.keywords)
                    }
                );
                return await comment.save({
                    returning: true,
                    transaction,
                });
            });
        } catch (error) {
            caught = error;
        } finally {
            resolve(caught);
        }
    }
}

```

`CreateEntryCommandHandler`和`UpdateEntryCommandHandler`命令处理程序已更新为将关键字字符串数组转换为 JSON 字符串。关键字还需要单独存储在自己的表中，其中包含它们适用于的博客条目列表和最后更新日期。为此，我们需要创建一个新的 Nest.js 模块和实体。我们稍后将回来添加更多功能。首先，创建新实体。

```js
const tableOptions: IDefineOptions = { timestamp: true, tableName: 'keywords' } as IDefineOptions;

@DefaultScope({
    include: [() => Entry]
})
@Table(tableOptions)
export class Keyword extends Model<Keyword> {
    @PrimaryKey
    @AutoIncrement
    @Column(DataType.BIGINT)
    public id: number;

    @Column({
        type: DataType.STRING,
        allowNull: false,
        validate: {
            isUnique: async (value: string, next: any): Promise<any> => {
                const isExist = await Keyword.findOne({ where: { keyword: value } });
                if (isExist) {
                    const error = new Error('The keyword already exists.');
                    next(error);
                }
                next();
            },
        },
    })
    public keyword: string;

    @CreatedAt
    public createdAt: Date;

    @UpdatedAt
    public updatedAt: Date;

    @DeletedAt
    public deletedAt: Date;

    @BelongsToMany(() => Entry, () => KeywordEntry)
    public entries: Entry[];

    @BeforeValidate
    public static validateData(entry: Entry, options: any) {
        if (!options.transaction) throw new Error('Missing transaction.');
    }
}

```

`BelongsToMany`装饰器用于将关键字连接到许多不同的博客条目。由于我们使用字符串列来保持查找速度，因此我们不会在博客条目表中放置`BelongsToMany`列。`() => KeywordEntry`参数告诉 ORM 我们将使用`KeywordEntry`实体来存储关联。我们还需要创建实体。

```js
const tableOptions: IDefineOptions = { timestamp: true, tableName: 'keywords_entries', deletedAt: false, updatedAt: false } as IDefineOptions;

@Table(tableOptions)
export class KeywordEntry extends Model<KeywordEntry> {
    @ForeignKey(() => Keyword)
    @Column({
        type: DataType.BIGINT,
        allowNull: false
    })
    public keywordId: number;

    @ForeignKey(() => Entry)
    @Column({
        type: DataType.BIGINT,
        allowNull: false
    })
    public entryId: number;

    @CreatedAt
    public createdAt: Date;
}

```

我们的 ORM 将使用`@ForeignKey`装饰器将此数据库表中的条目链接到`keywords`和`entries`表。我们还添加了一个`createdAt`列，以帮助我们找到最新链接到博客条目的关键字。我们将使用此功能创建我们的“热门关键字”列表。接下来，创建迁移脚本以将新表添加到数据库中。

```js
export async function up(sequelize) {
    // language=PostgreSQL
    await sequelize.query(`
        CREATE TABLE "keywords" (
            "id" SERIAL UNIQUE PRIMARY KEY NOT NULL,
            "keyword" VARCHAR(30) UNIQUE NOT NULL,
            "createdAt" TIMESTAMP NOT NULL,
            "updatedAt" TIMESTAMP NOT NULL,
            "deletedAt" TIMESTAMP
        );
        CREATE TABLE "keywords_entries" (
            "keywordId" INTEGER NOT NULL
                CONSTRAINT "keywords_entries_keywordId_fkey"
                REFERENCES keywords
                ON UPDATE CASCADE ON DELETE CASCADE,
            "entryId" INTEGER NOT NULL
                CONSTRAINT "keywords_entries_entryId_fkey"
                REFERENCES entries
                ON UPDATE CASCADE ON DELETE CASCADE,
            "createdAt" TIMESTAMP NOT NULL,
            UNIQUE("keywordId", "entryId")
        );
  `);

    console.log('*Table keywords created!*');
}

export async function down(sequelize) {
    // language=PostgreSQL
    await sequelize.query(`DROP TABLE keywords_entries`);
    await sequelize.query(`DROP TABLE keywords`);
}

```

我们的迁移脚本在`keywords_entries`表中包括一个唯一约束，以确保我们不会将相同的关键字和博客条目链接超过一次。`entryId`列定义的`ON DELETE CASCADE`部分将确保当我们删除博客条目时，关键字链接也将被删除。这意味着我们不必创建任何代码来处理删除博客条目时取消关键字的链接。请务必将新的数据库实体添加到数据库提供程序中。

```js
export const databaseProvider = {
    provide: 'SequelizeInstance',
    useFactory: async () => {
        let config;
        switch (process.env.NODE_ENV) {
            case 'prod':
            case 'production':
            case 'dev':
            case 'development':
            default:
                config = databaseConfig.development;
        }

        const sequelize = new Sequelize(config);
        sequelize.addModels([User, Entry, Comment, Keyword, KeywordEntry]);
        /* await sequelize.sync(); */
        return sequelize;
    },
};

```

最后，创建关键字提供程序和模块。

```js
export const keywordProvider = {
    provide: 'KeywordRepository',
    useValue: Keyword,
};

export const keywordEntryProvider = {
    provide: 'KeywordEntryRepository',
    useValue: KeywordEntry
};

@Module({
    imports: [],
    controllers: [],
    components: [keywordProvider, keywordEntryProvider],
    exports: []
})
export class KeywordModule {}

```

现在我们有了一个可工作的关键字模块，我们可以开始考虑如何构建存储关键字的应用程序逻辑。为了保持在 CQRS 模式内，我们可以在关键字模块中创建新的命令和命令处理程序。然而，Nest.js 对命令总线的所有实例都施加了模块隔离。这意味着命令处理程序必须在执行命令的同一模块中注册。例如，如果我们尝试从博客条目控制器执行关键字命令，Nest.js 将抛出异常，指示没有为该命令注册处理程序。这就是 Nest.js CQRS 中的事件发挥作用的地方。事件总线不是隔离的。事实上，事件总线允许从任何模块执行事件，无论是否为它们注册了处理程序。

## 关键事件

事件可以被视为具有一些不同之处的命令。除了不是模块范围之外，它们还是异步的，通常由模型或实体分发，并且每个事件可以有任意数量的事件处理程序。这使它们非常适合处理在创建和更新博客条目时对关键字数据库表进行后台更新。

在我们开始编写代码之前，让我们考虑一下我们希望应用程序如何工作。当创建新的博客条目时，应用程序需要通知关键字模块，博客条目已与关键字关联。我们应该让关键字模块决定关键字是否是新的，需要创建，还是已经存在，只需要更新。相同的逻辑应该适用于对博客条目的更新，但是如果我们不尝试确定哪些关键字是新的，哪些已被删除，我们可以使我们的博客条目更新过程更简单。为了支持这两种情况，我们应该创建一个通用事件来更新博客条目的所有关键字链接。

现在我们对我们要完成的逻辑有了基本的理解，我们可以构建事件类。就像命令一样，CQRS 事件功能需要事件的基本类。事件文件通常在我们模块的子目录中创建，模式类似于`events/impl/`。

```js
export class UpdateKeywordLinksEvent implements IEvent {
    constructor(
        public readonly entryId: number,
        public readonly keywords: string[]
    ) { }
}

```

事件类应该看起来与我们在本章前面编写的命令类非常相似。不同之处在于事件类实现了`IEvent`接口，让 Nest.js 知道这些类的实例是 CQRS 事件。我们还需要为这些事件设置处理程序。就像命令处理程序一样，我们的事件处理程序将负责所有数据库操作。通常，事件处理程序放在模块的子目录中，类似于`events/handlers`。

```js
@EventsHandler(UpdateKeywordLinksEvent)
export class UpdateKeywordLinksEventHandler implements IEventHandler<UpdateKeywordLinksEvent> {
    constructor(
        @Inject('KeywordRepository') private readonly keywordRepository: typeof Keyword,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize,
    ) { }

    async handle(event: UpdateKeywordLinksEvent) {
    }
}

```

事件处理程序是简单的类，只有一个方法`handle`，负责处理事件。实现`IEventHandler<UpdateKeywordLinksEvent>`接口有助于确保我们正确编写事件处理程序。在我们的示例中，Nest.js 使用`@EventsHandler`注解来知道这个类是用来处理我们的新`UpdateKeywordLinksEvent`事件的。

我们的事件处理程序与命令处理程序相比的一个关键区别是，事件处理程序不会作为第二个参数得到一个回调方法。Nest.js 将异步调用`handle`方法。它不会等待它完成，也不会尝试捕获任何返回值，也不会捕获或处理调用`handle`方法可能导致的任何错误。这并不是说我们不应该仍然使用`try...catch`来防止任何错误导致与 NodeJS 的问题。

对于更新链接事件处理程序，我们应该将逻辑拆分成单独的方法，以使类更容易阅读和管理。让我们编写`handle`方法，使其循环遍历所有关键字，并确保关键字存在，并且博客条目与关键字关联。最后，我们应该确保博客条目不与事件`keywords`数组中不存在的任何关键字关联。

```js
@EventsHandler(UpdateKeywordLinksEvent)
export class UpdateKeywordLinksEventHandler implements IEventHandler<UpdateKeywordLinksEvent> {
    constructor(
        @Inject('KeywordRepository') private readonly keywordRepository: typeof Keyword,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize,
    ) { }

    async handle(event: UpdateKeywordLinksEvent) {
        try {
            await this.sequelizeInstance.transaction(async transaction => {
                let newKeywords: string[] = [];
                let removedKeywords: Keyword[] = [];

                const keywordEntities = await this.keywordRepository.findAll({
                    include: [{ model: Entry, where: { id: event.entryId }}],
                    transaction
                });

                keywordEntities.forEach(keywordEntity => {
                    if (event.keywords.indexOf(keywordEntity.keyword) === -1) {
                        removedKeywords.push(keywordEntity);
                    }
                });

                event.keywords.forEach(keyword => {
                    if (keywordEntities.findIndex(keywordEntity => keywordEntity.keyword === keyword) === -1) {
                        newKeywords.push(keyword)
                    }
                });

                await Promise.all(
                    newKeywords.map(
                        keyword => this.ensureKeywordLinkExists(transaction, keyword, event.entryId)
                    )
                );
                await Promise.all(
                    removedKeywords.map(
                        keyword => keyword.$remove('entries', event.entryId, { transaction })
                    )
                );
            });
        } catch (error) {
            console.log(error);
        }
    }

    async ensureKeywordLinkExists(transaction: Transaction, keyword: string, entryId: number) {
        const keywordEntity = await this.ensureKeywordExists(transaction, keyword);
        await keywordEntity.$add('entries', entryId, { transaction });
    }

    async ensureKeywordExists(transaction: Transaction, keyword: string): Promise<Keyword> {
        const result = await this.keywordRepository.findOrCreate<Keyword>({
            where: { keyword },
            transaction
        });
        return result[0];
    }
}

```

事件处理程序逻辑从查找博客条目当前链接到的所有关键字开始。我们循环遍历这些关键字，并提取出不在新关键字数组中的任何关键字。为了找到所有新关键字，我们循环遍历事件中的关键字数组，找到不在`keywordEntities`数组中的关键字。新关键字通过`ensureKeywordLinkExists`方法进行处理。`ensureKeywordLinkExists`使用`ensureKeywordExists`来在关键字数据库表中创建或查找关键字，并将博客条目添加到关键字条目数组中。`$add`和`$remove`方法由`sequelize-typescript`提供，用于快速添加和删除博客条目，而无需查询博客条目。所有处理都使用事务来确保任何错误都将取消所有数据库更新。如果发生错误，数据库将变得不同步，但由于我们处理的是元数据，这并不是什么大问题。我们记录错误，以便应用管理员知道他们需要重新同步元数据。

即使我们只有一个事件处理程序，我们仍然应该创建一个 Typescript barrel 来将其导出为数组。这将确保以后添加新事件是一个简单的过程。

```js
export const keywordEventHandlers = [
    UpdateKeywordLinksEventHandler,
    RemoveKeywordLinksEventHandler
];

```

在关键字模块中导入 barrel 并连接事件总线。

```js
@Module({
    imports: [CQRSModule],
    controllers: [],
    components: [keywordProvider, ...keywordEventHandlers],
    exports: []
})
export class KeywordModule implements OnModuleInit {
    public constructor(
        private readonly moduleRef: ModuleRef,
        private readonly eventBus: EventBus
    ) {}

    public onModuleInit() {
        this.eventBus.setModuleRef(this.moduleRef);
        this.eventBus.register(keywordEventHandlers);
    }
}

```

在模块中，导入`CQRSModule`并将`ModuleRef`和`EventBus`添加为构造函数参数。实现`OnModuleInit`接口并创建`onModuleInit`方法。在`onModuleInit`方法中，我们使用`setModuleRef`将事件总线的模块引用设置为当前模块，并使用`register`注册所有事件处理程序。记得也将事件处理程序添加到`components`数组中，否则 Nest.js 将无法实例化事件处理程序。现在，我们已经编写并链接了关键字模块中的事件和事件处理程序，我们准备开始调用事件以存储和更新数据库中的关键字链接。

## 调用事件处理程序

事件处理程序是从数据模型中调用的。数据模型通常是表示存储在数据库中的数据的简单类。Nest.js 对数据模型的唯一规定是它们必须扩展`AggregateRoot`抽象类。根据您使用的 ORM 以及其配置方式，您可能能够重用现有的数据模型来实现此目的，也可能不能。由于我们的示例使用 Sequelize，`sequelize-typescript`包要求我们的数据模型扩展`Model`类。在 Typescript 中，类只能扩展另一个类。我们需要为调用我们的事件处理程序创建一个单独的数据模型。

```js
export class EntryModel extends AggregateRoot {
  constructor(private readonly id: number) {
    super();
  }

  updateKeywordLinks(keywords: string[]) {
    this.apply(new UpdateKeywordLinksEvent(this.id, keywords));
  }
}

```

我们在博客条目模块中创建我们的数据模型，因为我们将在创建和更新博客条目时调用我们的事件。数据模型包含一个名为`updateKeywordLinks`的方法，用于在创建或更新博客条目时刷新博客条目关键字链接。如果需要新的事件，我们将向模型添加更多方法来处理调用这些事件。`updateKeywordLinks`方法实例化了我们创建的事件，并调用了`AggregateRoot`抽象类中的`apply`方法来应用事件实例。

对于命令，我们直接使用命令总线来`execute`我们的命令。对于事件，我们采取了一种不太直接的方法，使用`EventPublisher`将我们的数据模型链接到事件总线，然后调用我们在数据模型中创建的方法来`apply`事件。让我们更新`CreateEntryCommandHandler`以更好地了解发生了什么。

```js
@CommandHandler(CreateEntryCommand)
export class CreateEntryCommandHandler implements ICommandHandler<CreateEntryCommand> {
    constructor(
        @Inject('EntryRepository') private readonly EntryRepository: typeof Entry,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize,
        private readonly eventPublisher: EventPublisher
    ) { }

    async execute(command: CreateEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            const entry = await this.sequelizeInstance.transaction(async transaction => {
                return await this.EntryRepository.create<Entry>({
                    ...command,
                    keywords: JSON.stringify(command.keywords)
                }, {
                    returning: true,
                    transaction
                });
            });

            const entryModel = this.eventPublisher.mergeObjectContext(new EntryModel(entry.id));
            entryModel.updateKeywordLinks(command.keywords);
            entryModel.commit();
        } catch (error) {
            caught = error;
        } finally {
            resolve(caught);
        }
    }
}

```

命令处理程序构造函数已更新为注入 Nest.js 的`EventPublisher`的实例。`EventPublisher`有两个我们关心的方法：`mergeClassContext`和`mergeObjectContext`。这两种方法都可以用来实现相同的结果，只是方式不同。在我们的例子中，我们使用`mergeObjectContext`将我们的数据模型的新实例与事件总线合并。这为数据模型实例提供了一个`publish`方法，该方法在抽象的`AggregateRoot`类中用于在事件总线上`publish`新事件。

事件永远不会立即分发。当我们调用`updateKeywordLinks`时，创建的事件将被放入队列中。当我们在我们的数据模型上调用`commit`方法时，事件队列将被刷新。如果您发现您的事件处理程序没有触发，请确保您已经在您的数据模型上调用了`commit`方法。

我们可以使用事件发布者的`mergeClassContext`方法来实现相同的功能。

```js
const Model = this.eventPublisher.mergeClassContext(EntryModel);
const entryModel = new Model(entry.id);
entryModel.updateKeywordLinks(command.keywords);
entryModel.commit();

```

`UpdateEntryCommandHandler`命令处理程序也需要进行相同的更新，以便在更新博客条目时更新关键词链接。

```js
@CommandHandler(UpdateEntryCommand)
export class UpdateEntryCommandHandler implements ICommandHandler<UpdateEntryCommand> {
    constructor(
        @Inject('EntryRepository') private readonly EntryRepository: typeof Entry,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize,
        private readonly databaseUtilitiesService: DatabaseUtilitiesService,
        private readonly eventPublisher: EventPublisher
    ) { }

    async execute(command: UpdateEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                let entry = await this.EntryRepository.findById<Entry>(command.id, { transaction });
                if (!entry) throw new Error('The comment was not found.');

                entry = this.databaseUtilitiesService.assign(
                    entry,
                    {
                        ...command,
                        id: undefined,
                        keywords: JSON.stringify(command.keywords)
                    }
                );
                return await entry.save({
                    returning: true,
                    transaction,
                });
            });

            const entryModel = this.eventPublisher.mergeObjectContext(new EntryModel(command.id));
            entryModel.updateKeywordLinks(command.keywords);
            entryModel.commit();
        } catch (error) {
            caught = error;
        } finally {
            resolve(caught);
        }
    }
}

```

如果您在自己的项目中跟随了这些步骤，现在您应该能够创建或更新一个博客条目，使用新的或现有的关键词，并且在数据库中看到关键词链接被创建、更新和删除。当然，我们可以通过添加一个新的 API 来返回所有关键词和它们链接到的博客条目，使这些更改更容易查看。

![CQRS Keywords Flow](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/CQRSFlow002.png)

上图提供了一个视觉表示，说明了条目命令处理程序如何工作以保持关键词的更新。请注意控制流的单向性。命令处理程序使用条目模型调用事件，然后忘记它。这是 Nest.js CQRS 中事件总线的异步性质。

# 检索关键词 API

我们需要在关键词模块中创建一个新的控制器和服务，以支持检索关键词。我们希望允许 UI 列出所有关键词，获取特定关键词，并获取“热门关键词”的列表。让我们先创建服务。

```js
@Injectable()
export class KeywordService implements IKeywordService {
    constructor(@Inject('KeywordRepository') private readonly keywordRepository: typeof Keyword,
                @Inject('KeywordEntryRepository') private readonly keywordEntryRepository: typeof KeywordEntry) { }

    public async findAll(search?: string, limit?: number): Promise<Array<Keyword>> {
        let options: IFindOptions<Keyword> = {};

        if (search) {
            if (!limit || limit < 1 || limit === NaN) {
                limit = 10;
            }

            options = {
                where: {
                    keyword: {
                        [Op.like]: `%${search}%`
                    }
                },
                limit
            }
        }

        return await this.keywordRepository.findAll<Keyword>(options);
    }

    public async findById(id: number): Promise<Keyword | null> {
        return await this.keywordRepository.findById<Keyword>(id);
    }

    public async findHotLinks(): Promise<Array<Keyword>> {
        // Find the latest 5 keyword links
        const latest5 = await this.keywordEntryRepository.findAll<KeywordEntry>({
            attributes: {
                exclude: ['entryId', 'createdAt']
            },
            group: ['keywordId'],
            order: [[fn('max', col('createdAt')), 'DESC']],
            limit: 5
        } as IFindOptions<any>);

        // Find the 5 keywords with the most links
        const biggest5 = await this.keywordEntryRepository.findAll<KeywordEntry>({
            attributes: {
                exclude: ['entryId', 'createdAt']
            },
            group: 'keywordId',
            order: [[fn('count', 'entryId'), 'DESC']],
            limit: 5,
            where: {
                keywordId: {
                    // Filter out keywords that already exist in the latest5
                    [Op.notIn]: latest5.map(keywordEntry => keywordEntry.keywordId)
                }
            }
        } as IFindOptions<any>);

        // Load the keyword table data
        const result = await Promise.all(
            [...latest5, ...biggest5].map(keywordEntry => this.findById(keywordEntry.keywordId))
        );

        return result;
    }
}

```

`findAll`方法接受一个可选的搜索字符串和限制，可以用来过滤关键词。UI 可以使用这个来支持关键词搜索自动完成。如果在搜索时未指定限制，服务将自动将结果限制为 10 个项目。`findById`方法将支持加载单个关键词的所有信息，包括关联的条目。这些方法相对基本，并模仿其他模块的服务中的方法。然而，`findHotLinks`方法稍微复杂一些。

`findHotLinks`方法负责返回最近使用的关键词和具有最多链接的博客条目的关键词。为了做到这一点，我们需要将 ORM 提供程序与连接表`KeywordEntry`数据模型结合起来。连接表包含关键词和博客条目之间的实际链接，以及它们加入的日期。对于`latest5`，我们按最大的`createdAt`日期对列表进行排序，以获取最新的关键词列表。`biggest5`按`entryId`的计数进行排序，以产生一个包含最多链接的博客条目的关键词列表。在这两个列表中，我们按`keywordId`进行分组，以产生一个唯一关键词的列表，并将结果限制为前五个。为了确保我们不产生重叠的列表，`biggest5`还包含一个 where 子句，以不包括已经包含在`latest5`列表中的任何关键词。

一旦我们有了这两个列表，我们就可以重用服务的`findById`方法来加载所有找到的关键词的完整数据记录。然后返回这个列表，其中具有最新链接的关键词首先按最新到最旧的顺序排列，然后是具有最多链接的关键词，按最多到最少的顺序排列。现在剩下的就是创建一个控制器，这样 UI 就可以利用我们的新查询方法。

**注意：**请注意`as IFindOptions<any>`。这是为了解决`sequelize-typescript`引起的 linting 错误而需要的。您的应用程序可能需要或不需要这个。

```js
@Controller()
export class KeywordController {
    constructor(
        private readonly keywordService: KeywordService
    ) { }

    @Get('keywords')
    public async index(@Query('search') search: string, @Query('limit') limit: string, @Res() res) {
        const keywords = await this.keywordService.findAll(search, Number(limit));
        return res.status(HttpStatus.OK).json(keywords);
    }

    @Get('keywords/hot')
    public async hot(@Res() res) {
        const keywords = await this.keywordService.findHotLinks();
        return res.status(HttpStatus.OK).json(keywords);
    }

    @Get('keywords/:keywordId')
    public async show(@Param('keywordId') keywordId: string, @Res() res) {
        const keyword = await this.keywordService.findById(Number(keywordId));
        return res.status(HttpStatus.OK).json(keyword);
    }
}

```

控制器包含三种方法，对应于服务中的三种查询方法。在所有三种方法中，我们调用服务中的适当方法，并将结果作为 JSON 返回。请注意，`hot`方法在`show`方法之前列出。如果更改此顺序，调用`/keywords/hot` API 将导致执行`show`方法。由于 Nest.js 运行在 ExpressJS 之上，我们声明控制器方法的顺序很重要。ExpressJS 将始终执行与 UI 请求的路径匹配的第一个路由控制器。

我们现在有一个应用程序，它使用 Nest.js CQRS 来拆分业务逻辑，并以异步方式实现其中的一部分。该应用程序能够对博客条目的创建和更新做出反应，以改变关键字元数据。所有这些都是通过事件的使用变得可能的。但是还有另一种方法可以实现相同的目标，即使用传奇而不是我们创建的事件处理程序。

# 使用传奇链接关键字

传奇可以被视为返回命令的特殊事件处理程序。传奇通过利用 RxJS 来接收和对事件总线发布的所有事件做出反应。使用`UpdateKeywordLinksEvent`事件处理程序，我们可以将工作逻辑上分为两个单独的命令：一个用于创建关键字链接，一个用于删除它们。由于传奇返回命令，因此传奇和命令必须在同一个模块中创建。否则，命令模块作用域将成为一个问题，当我们的传奇尝试返回在不同模块中找到的命令时，Nest.js 将抛出异常。要开始，我们需要设置将替换我们的单一事件处理程序的命令和命令处理程序。

## 关键词传奇命令

仅仅因为我们使用传奇来执行我们的新命令并不会改变我们编写这些命令和命令处理程序的方式。我们将在关键字模块中将`UpdateKeywordLinksEvent`拆分为两个单独的命令。

```js
export class LinkKeywordEntryCommand implements ICommand {
    constructor(
        public readonly keyword: string,
        public readonly entryId: number
    ) { }
}

export class UnlinkKeywordEntryCommand implements ICommand {
    constructor(
        public readonly keyword: string,
        public readonly entryId: number
    ) { }
}

```

命令有两个属性：`keyword`和`entryId`。命令采用简单的`keyword`字符串，因为命令处理程序不应假设关键字已经存在于数据库中。`entryId`已知存在，因为它是`UpdateKeywordLinksEvent`事件的参数。

```js
@CommandHandler(LinkKeywordEntryCommand)
export class LinkKeywordEntryCommandHandler implements ICommandHandler<LinkKeywordEntryCommand> {
    constructor(
        @Inject('KeywordRepository') private readonly keywordRepository: typeof Keyword,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize
    ) { }

    async execute(command: LinkKeywordEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                const keyword = await this.keywordRepository.findOrCreate({
                    where: {
                        keyword: command.keyword
                    },
                    transaction
                });

                await keyword[0].$add('entries', command.entryId, { transaction });
            });
        } catch (error) {
            caught = error;
        } finally {
            resolve(caught);
        }
    }
}

```

`LinkKeywordEntryCommandHandler`命令处理程序负责确保关键字存在于数据库中，然后使用`sequelize-typescript`提供的`$add`方法，通过其 id 将博客条目链接到关键字。

```js
@CommandHandler(UnlinkKeywordEntryCommand)
export class UnlinkKeywordEntryCommandHandler implements ICommandHandler<UnlinkKeywordEntryCommand> {
    constructor(
        @Inject('KeywordRepository') private readonly keywordRepository: typeof Keyword,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize
    ) { }

    async execute(command: UnlinkKeywordEntryCommand, resolve: (error?: Error) => void) {
        let caught: Error;

        try {
            await this.sequelizeInstance.transaction(async transaction => {
                const keyword = await this.keywordRepository.findOrCreate<Keyword>({
                    where: {
                        keyword: command.keyword
                    },
                    transaction
                });

                await keyword[0].$remove('entries', command.entryId, { transaction });
            });
        } catch (error) {
            caught = error;
        } finally {
            resolve(caught);
        }
    }
}

```

`UnlinkKeywordEntryCommandHandler`命令处理程序负责确保关键字存在于数据库中，然后使用`sequelize-typescript`提供的`$remove`方法，通过其 id 删除博客条目与关键字的链接。这些命令比`UpdateKeywordLinksEventHandler`事件处理程序简单得多。它们有一个单一的目的，即链接或取消链接关键字和博客条目。确定要链接和取消链接的关键字的繁重工作是由传奇保留的。不要忘记在关键字模块中连接命令处理程序。

```js
export const keywordCommandHandlers = [
    LinkKeywordEntryCommandHandler,
    UnlinkKeywordEntryCommandHandler
];

@Module({
    imports: [CQRSModule],
    controllers: [KeywordController],
    components: [keywordProvider, keywordEntryProvider, ...keywordEventHandlers, KeywordService, ...keywordCommandHandlers],
    exports: []
})
export class KeywordModule implements OnModuleInit {
    public constructor(
        private readonly moduleRef: ModuleRef,
        private readonly eventBus: EventBus,
        private readonly commandBus: CommandBus
    ) {}

    public onModuleInit() {
        this.commandBus.setModuleRef(this.moduleRef);
        this.commandBus.register(keywordCommandHandlers);
        this.eventBus.setModuleRef(this.moduleRef);
        this.eventBus.register(keywordEventHandlers);
    }
}

```

就像条目模块一样，我们创建了一个 Typescript 桶来将命令处理程序导出为数组。这将被导入到模块定义中，并使用`register`方法注册到命令总线。

## 关键词传奇

传奇始终以组件类内的公共方法编写，以允许依赖注入。通常，您会为希望在其中实现传奇的每个模块创建一个单独的传奇类，但在拆分复杂的业务逻辑时，创建多个类是有意义的。对于更新关键字传奇，我们将需要一个接受`UpdateKeywordLinksEvent`事件并输出多个`LinkKeywordEntryCommand`和`UnlinkKeywordEntryCommand`命令的单一传奇方法。

```js
@Injectable()
export class KeywordSagas {
    constructor(
        @Inject('KeywordRepository') private readonly keywordRepository: typeof Keyword,
        @Inject('SequelizeInstance') private readonly sequelizeInstance: Sequelize,
    ) { }

    public updateKeywordLinks(events$: EventObservable<any>) {
        return events$.ofType(UpdateKeywordLinksEvent).pipe(
            mergeMap(event =>
                merge( // From the rxjs package
                    this.getUnlinkCommands(event),
                    this.getLinkCommands(event)
                )
            )
        );
    }
}

```

`KeywordSagas`类包含一个单独的 saga `updateKeywordLinks`，并使用依赖注入来获取关键字存储库和 Sequelize 实例的引用。传递给`updateKeywordLinks` saga 的参数由 Nest.js CQRS 事件总线提供。`EventObservable`是 Nest.js CQRS 提供的一个特殊 observable，其中包含`ofType`方法。我们使用这个方法来过滤`events$` observable，这样我们的 saga 只会处理`UpdateKeywordLinksEvent`事件。如果忘记使用`ofType`方法，你的 saga 将对应用程序中发布的每个事件都触发。

我们 saga 的剩余部分严格是 RxJS 功能。你可以自由使用任何 RxJS 操作符，只要 saga 发出一个或多个 CQRS 命令。对于我们的 saga，我们将使用`mergeMap`来展平命令的内部 observable 流。不要在这里使用`switchMap`，否则由于`switchMap`在外部 observable 多次触发时会被取消，命令可能会丢失，因为内部 observable 是两个不同 observable 流的合并：`this.getUnlinkCommands(event)`是一个`UnlinkKeywordEntryCommand`命令流，`this.getLinkCommands(event)`是一个`LinkKeywordEntryCommand`命令流。

```js
private getUnlinkCommands(event: UpdateKeywordLinksEvent) {
    return from(this.keywordRepository.findAll({
        include: [{ model: Entry, where: { id: event.entryId }}]
    })).pipe(
        // Filter keywordEntities so only those being removed are left
        map(keywordEntities =>
            keywordEntities.filter(keywordEntity => event.keywords.indexOf(keywordEntity.keyword) === -1)
        ),
        // Create new commands for each keywordEntity
        map(keywordEntities => keywordEntities.map(keywordEntity => new UnlinkKeywordEntryCommand(keywordEntity.keyword, event.entryId))),
        switchMap(commands => Observable.of(...commands))
    );
}

private getLinkCommands(event: UpdateKeywordLinksEvent) {
    return from(this.keywordRepository.findAll({
        include: [{ model: Entry, where: { id: event.entryId }}]
    })).pipe(
        // Filter keywordEntities so only those being add are left
        map(keywordEntities =>
            event.keywords.filter(keyword => keywordEntities.findIndex(keywordEntity => keywordEntity.keyword === keyword) === -1)
        ),
        // Create new commands for each keyword
        map(keywords => keywords.map(keyword => new LinkKeywordEntryCommand(keyword, event.entryId))),
        switchMap(commands => Observable.of(...commands))
    );
}

```

`getUnlinkCommands`和`getLinkCommands`方法首先获取现有关键字博客条目链接的列表。我们使用`Observable.fromPromise`，因为我们需要从这些方法返回一个 observable。两个命令之间的区别在于过滤的方式。在`getUnlinkCommands`中，我们需要过滤现有关键字博客条目链接的列表，以找到那些不在事件的关键字数组中的链接。我们在`getLinkCommands`中颠倒逻辑，并过滤事件中的关键字列表，以找到那些尚未链接到博客条目的关键字。最后，我们将数组映射到命令，并使用`switchMap(commands => Observable.of(...commands))`，这样我们的 observable 流会发出所有命令，而不是一组命令。由于唯一的区别是过滤，我们可以清理一下，这样就不会频繁查询数据库。

```js
public updateKeywordLinks(events$: EventObservable<any>) {
    return events$.ofType(UpdateKeywordLinksEvent).pipe(
        mergeMap(event => this.compileKeywordLinkCommands(event))
    );
}

private compileKeywordLinkCommands(event: UpdateKeywordLinksEvent) {
    return from(this.keywordRepository.findAll({
        include: [{ model: Entry, where: { id: event.entryId }}]
    })).pipe(
        switchMap(keywordEntities =>
            of(
                ...this.getUnlinkCommands(event, keywordEntities),
                ...this.getLinkCommands(event, keywordEntities)
            )
        )
    );
}

private getUnlinkCommands(event: UpdateKeywordLinksEvent, keywordEntities: Keyword[]) {
    return keywordEntities
        .filter(keywordEntity => event.keywords.indexOf(keywordEntity.keyword) === -1)
        .map(keywordEntity => new UnlinkKeywordEntryCommand(keywordEntity.keyword, event.entryId));
}

private getLinkCommands(event: UpdateKeywordLinksEvent, keywordEntities: Keyword[]) {
    return event.keywords
        .filter(keyword => keywordEntities.findIndex(keywordEntity => keywordEntity.keyword === keyword) === -1)
        .map(keyword => new LinkKeywordEntryCommand(keyword, event.entryId));
}

```

现在我们的 saga 只查询数据库中现有的关键字博客条目链接一次，`getUnlinkCommands`和`getLinkCommands`方法已经大大简化。这些方法现在接受事件和现有关键字博客条目链接列表，并返回需要执行的命令数组。检索现有关键字博客条目链接的繁重工作已经转移到`compileKeywordLinkCommands`方法。这个方法使用`switchMap`将数据库中的结果投影到`getUnlinkCommands`和`getLinkCommands`中。仍然使用`Observable.of`来逐个发出命令数组。现在，创建和更新博客条目将通过 saga 和关键字命令处理所有关键字链接和取消链接。

![CQRS 事件 sagas 流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/CQRSFlow003.png)

上图提供了一个视觉表示，展示了我们的新 sagas 如何将数据库更新的处理交还给关键字模块中的命令总线。一旦执行更新关键字链接的事件，saga 会查询数据库以确定要链接和取消链接的关键字，最后返回适当的命令。请记住，命令处理程序包含一个回调方法，因此它并不是显式地异步的。然而，由于它们是从事件总线调用的，任何响应都不会传递回 sage 或入口命令总线。

# 总结

CQRS 不仅仅是一个 Nest.js 的包。它是一种设计和布局应用程序的模式。它要求你将数据的命令、创建和更新与数据的查询以及应用程序的方面分开。对于小型应用程序，CQRS 可能会增加许多不必要的复杂性，因此并非适用于每个应用程序。对于中型和大型应用程序，CQRS 可以帮助将复杂的业务逻辑分解为更易管理的部分。

Nest.js 提供了两种实现 CQRS 模式的方法，即命令总线和事件总线，以及一些 saga 形式的糖。命令总线将命令执行隔离到每个模块，这意味着命令只能在注册它的同一模块中执行。命令处理程序并不总是异步的，并且限制了应用程序的其他部分对变化的反应。因此，Nest.js 提供了事件总线。事件总线不局限于单个模块，并提供了一种让同一应用程序的不同模块对其他模块发布的事件做出反应的方式。事实上，事件可以有任意数量的处理程序，使业务逻辑可以轻松扩展而无需更改现有代码。

Saga 是对模块内部事件做出反应的一种不同方式。Saga 是一个简单的函数，它监听事件总线上的事件，并通过返回要执行的命令来做出反应。虽然看似简单，但 saga 允许您利用 RxJS 的强大功能来确定应用程序对事件做出反应的方式。就像我们在示例应用程序中所做的那样，saga 并不局限于仅返回一个或一种类型的命令。

下次当您发现自己在编写复杂的代码来执行一些基于用户与应用程序交互的业务逻辑时，请考虑尝试使用 CQRS 模式。模式的复杂性可能会被应用程序业务逻辑的复杂性或最终复杂性所抵消。

在下一章中，我们将研究两种不同类型项目的架构：一个服务器应用程序，以及一个使用`Angular universal`与 Nest.js 和 Angular 6 的应用程序。
