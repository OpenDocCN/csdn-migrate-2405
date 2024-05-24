# Go 无服务应用实用指南（二）

> 原文：[`zh.annas-archive.org/md5/862FBE1FF9A9C074341990A4C2200D42`](https://zh.annas-archive.org/md5/862FBE1FF9A9C074341990A4C2200D42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：部署您的无服务器应用程序

在之前的章节中，我们学习了如何从头开始构建一个无服务器 API。在本章中，我们将尝试完成以下内容：

+   通过一些高级 AWS CLI 命令构建、部署和管理我们的 Lambda 函数

+   发布 API 的多个版本

+   学习如何使用别名分隔多个部署环境（沙盒、暂存和生产）

+   覆盖 API Gateway 阶段变量的使用，以更改方法端点的行为。

# Lambda CLI 命令

在本节中，我们将介绍各种 AWS Lambda 命令，您可能在构建 Lambda 函数时使用。我们还将学习如何使用它们来自动化您的部署过程。

# 列出函数命令

如果您还记得，此命令是在第二章中引入的，*开始使用 AWS Lambda*。顾名思义，它会列出您提供的 AWS 区域中的所有 Lambda 函数。以下命令将返回北弗吉尼亚地区的所有 Lambda 函数：

```go
aws lambda list-functions --region us-east-1
```

对于每个函数，响应中都包括函数的配置信息（`FunctionName`、资源使用情况、`Environment`变量、IAM 角色、`Runtime`环境等），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3f3674b0-2fca-4d32-83e7-5b3fbe287e66.png)

要仅列出一些属性，例如函数名称，可以使用`query`筛选选项，如下所示：

```go
aws lambda list-functions --query Functions[].FunctionName[]
```

# 创建函数命令

如果您已经阅读了前面的章节，您应该对此命令很熟悉，因为它已经多次用于从头开始创建新的 Lambda 函数。

除了函数的配置，您还可以使用该命令以两种方式提供部署包（ZIP）：

+   **ZIP 文件**：它使用`--zip-file`选项提供代码的 ZIP 文件路径：

```go
aws lambda create-function --function-name UpdateMovie \
 --description "Update an existing movie" \
 --runtime go1.x \
 --role arn:aws:iam::ACCOUNT_ID:role/UpdateMovieRole \
 --handler main \
 --environment Variables={TABLE_NAME=movies} \
 --zip-file fileb://./deployment.zip \
 --region us-east-1a
```

+   **S3 存储桶对象**：它使用`--code`选项提供 S3 存储桶和对象名称：

```go
aws lambda create-function --function-name UpdateMovie \
 --description "Update an existing movie" \
 --runtime go1.x \
 --role arn:aws:iam::ACCOUNT_ID:role/UpdateMovieRole \
 --handler main \
 --environment Variables={TABLE_NAME=movies} \
 --code S3Bucket=movies-api-deployment-package,S3Key=deployment.zip \
 --region us-east-1
```

如上述命令将以 JSON 格式返回函数设置的摘要，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/dff57c7d-d25e-456b-a915-b9c2200697bd.png)

值得一提的是，在创建 Lambda 函数时，您可以根据函数的行为覆盖计算使用率和网络设置，使用以下选项：

+   `--timeout`：默认执行超时时间为三秒。当达到三秒时，AWS Lambda 终止您的函数。您可以设置的最大超时时间为五分钟。

+   `--memory-size`：执行函数时分配给函数的内存量。默认值为 128 MB，最大值为 3,008 MB（以 64 MB 递增）。

+   `--vpc-config`：这将在私有 VPC 中部署 Lambda 函数。虽然如果函数需要与内部资源通信，这可能很有用，但最好避免，因为它会影响 Lambda 的性能和扩展性（这将在即将到来的章节中讨论）。

AWS 不允许您设置函数的 CPU 使用率，因为它是根据为函数分配的内存自动计算的。 CPU 使用率与内存成比例。

# 更新函数代码命令

除了 AWS 管理控制台外，您还可以使用 AWS CLI 更新 Lambda 函数的代码。该命令需要目标 Lambda 函数名称和新的部署包。与上一个命令类似，您可以按以下方式提供包：

+   新`.zip`文件的路径：

```go
aws lambda update-function-code --function-name UpdateMovie \
    --zip-file fileb://./deployment-1.0.0.zip \
    --region us-east-1
```

+   存储`.zip`文件的 S3 存储桶：

```go
aws lambda update-function-code --function-name UpdateMovie \
    --s3-bucket movies-api-deployment-packages \
    --s3-key deployment-1.0.0.zip \
    --region us-east-1
```

此操作会为 Lambda 函数代码中的每个更改打印一个新的唯一 ID（称为`RevisionId`）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3b88a78d-a93b-4d00-9be4-b35adbc7f447.png)

# 获取函数配置命令

为了检索 Lambda 函数的配置信息，请发出以下命令：

```go
aws lambda get-function-configuration --function-name UpdateMovie --region us-east-1
```

前面的命令将以输出提供与使用`create-function`命令时显示的相同信息。

要检索特定 Lambda 版本或别名的配置信息（下一节），您可以使用`--qualifier`选项。

# 调用命令

到目前为止，我们直接从 AWS Lambda 控制台和通过 API Gateway 的 HTTP 事件调用了我们的 Lambda 函数。除此之外，Lambda 还可以通过 AWS CLI 使用`invoke`命令进行调用：

```go
aws lambda invoke --function-name UpdateMovie result.json

```

上述命令将调用`UpdateMovie`函数，并将函数的输出保存在`result.json`文件中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0bf38ec4-0da7-4488-8e80-638a8f6613c7.png)

状态码为 400，这是正常的，因为`UpdateFunction`需要 JSON 输入。让我们看看如何使用`invoke`命令向我们的函数提供 JSON。

返回到 DynamoDB 的`movies`表，并选择要更新的电影。在本例中，我们将更新 ID 为 13 的电影，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/cf4c4a5a-47d0-4cff-8131-68edd932fb20.png)

创建一个包含新电影项目属性的`body`属性的 JSON 文件，因为 Lambda 函数期望输入以 API Gateway 代理请求格式呈现：

```go
{
  "body": "{\"id\":\"13\", \"name\":\"Deadpool 2\"}"
}
```

最后，再次运行`invoke`函数命令，将 JSON 文件作为输入参数：

```go
aws lambda invoke --function UpdateMovie --payload file://input.json result.json
```

如果打印`result.json`的内容，更新后的电影应该会返回，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a0e91b21-4b46-4ba5-a805-6b9cf5783fcf.png)

您可以通过调用`FindAllMovies`函数来验证 DynamoDB 表中电影的名称是否已更新：

```go
aws lambda invoke --function-name FindAllMovies result.json
```

`body`属性应该包含新更新的电影，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4d2551c4-7c08-45ab-833a-d237a6585924.png)

返回到 DynamoDB 控制台；ID 为 13 的电影应该有一个新的名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/cc7602d9-b2e1-400c-9718-68dd610decc2.png)

# 删除函数命令

要删除 Lambda 函数，您可以使用以下命令：

```go
aws lambda delete-function --function-name UpdateMovie
```

默认情况下，该命令将删除所有函数版本和别名。要删除特定版本或别名，您可能需要使用`--qualifier`选项。

到目前为止，您应该熟悉了在构建 AWS Lambda 中的无服务器应用程序时可能使用和需要的所有 AWS CLI 命令。在接下来的部分中，我们将看到如何创建 Lambda 函数的不同版本，并使用别名维护多个环境。

# 版本和别名

在构建无服务器应用程序时，您必须将部署环境分开，以便在不影响生产的情况下测试新更改。因此，拥有多个 Lambda 函数版本是有意义的。

# 版本控制

版本代表了您函数代码和配置在某个时间点的状态。默认情况下，每个 Lambda 函数都有一个`$LATEST`版本，指向您函数的最新更改，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f0af4671-f79f-4c0b-a52e-53d80a392b58.png)

要从`$LATEST`版本创建新版本，请单击“操作”并选择“发布新版本”。让我们称其为`1.0.0`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3e0d3aa0-b07c-48bc-adc8-f9bf75607245.png)

新版本将创建一个 ID=1（递增）。请注意以下截图中窗口顶部的 ARN Lambda 函数；它具有版本 ID：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f123634e-9126-42a6-bf0b-ce5ffcae414b.png)

版本创建后，您无法更新函数代码，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c93eb73c-fb64-48ae-9a55-7d0b047a6b7f.png)

此外，高级设置，如 IAM 角色、网络配置和计算使用情况，无法更改，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e9fff6eb-11e2-4438-8632-92fc609387a3.png)

版本被称为**不可变**，这意味着一旦发布，它们就无法更改；只有`$LATEST`版本是可编辑的。

现在，我们知道如何从控制台发布新版本。让我们使用 AWS CLI 发布一个新版本。但首先，我们需要更新`FindAllMovies`函数，因为如果自从发布版本`1.0.0`以来对`$LATEST`没有进行任何更改，我们就无法发布新版本。

新版本将具有分页系统。该函数将仅返回用户请求的项目数量。以下代码将读取`Count`头参数，将其转换为数字，并使用带有`Limit`参数的`Scan`操作从 DynamoDB 中获取电影：

```go
func findAll(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  size, err := strconv.Atoi(request.Headers["Count"])
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusBadRequest,
      Body: "Count Header should be a number",
    }, nil
  }

  ...

  svc := dynamodb.New(cfg)
  req := svc.ScanRequest(&dynamodb.ScanInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
    Limit: aws.Int64(int64(size)),
  })

  ...
}
```

接下来，使用`update-function-code`命令更新`FindAllMovies` Lambda 函数的代码：

```go
aws lambda update-function-code --function-name FindAllMovies \
    --zip-file fileb://./deployment.zip
```

然后，基于当前配置和代码，使用以下命令发布一个新版本`1.1.0`：

```go
aws lambda publish-version --function-name FindAllMovies --description 1.1.0
```

返回到 AWS Lambda 控制台，导航到您的`FindAllMovies`；应该创建一个新版本，ID=2，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/93db27df-86fe-4dd5-b7c7-cd37eb140f69.png)

现在我们的版本已经创建，让我们通过使用 AWS CLI `invoke`命令来测试它们。

# FindAllMovies v1.0.0

使用以下命令在限定参数中调用`FindAllMovies` v1.0.0 版本：

```go
aws lambda invoke --function-name FindAllMovies --qualifier 1 result.json
```

`result.json`应该包含 DynamoDB`movies`表中的所有电影，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ba6b88b5-5a6e-4bf4-817d-69b80be8635c.png)

输出显示 DynamoDB 电影表中的所有电影

# FindAllMovies v1.1.0

创建一个名为`input.json`的新文件，并粘贴以下内容。此函数的版本需要一个名为`Count`的 Header 参数，用于返回电影的数量：

```go
{
  "headers": {
    "Count": "4"
  }
}
```

执行该函数，但这次使用`--payload`参数和指向`input.json`文件的路径位置：

```go
aws lambda invoke --function-name FindAllMovies --payload file://input.json
    --qualifier 2 result.json
```

`result.json`应该只包含四部电影，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a5be9c81-be0c-4c0e-9daf-3010a0d4959c.png)

这就是如何创建多个版本的 Lambda 函数。但是，Lambda 函数版本控制的最佳实践是什么？

# 语义化版本控制

当您发布 Lambda 函数的新版本时，应该给它一个重要且有意义的版本名称，以便您可以通过其开发周期跟踪对函数所做的不同更改。

当您构建一个将被数百万客户使用的公共无服务器 API 时，您命名不同 API 版本的方式至关重要，因为它允许您的客户知道新版本是否引入了破坏性更改。它还让他们选择合适的时间升级到最新版本，而不会冒太多破坏他们流水线的风险。

这就是语义化版本控制（[`semver.org`](https://semver.org)）的作用，它是一种使用三个数字序列的版本方案：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/95b25d49-ebb1-489a-a43f-f77522dcd791.png)

每个数字都根据以下规则递增：

+   **主要**：如果 Lambda 函数与先前版本不兼容，则递增。

+   **次要**：如果新功能或特性已添加到函数中，并且仍然向后兼容，则递增。

+   **补丁**：如果修复了错误和问题，并且函数仍然向后兼容，则递增。

例如，`FindAllMovies`函数的版本`1.1.0`是第一个主要版本，带有一个次要版本带来了一个新功能（分页系统）。

# 别名

别名是指向特定版本的指针，它允许您将函数从一个环境提升到另一个环境（例如从暂存到生产）。别名是可变的，而版本是不可变的。

为了说明别名的概念，我们将创建两个别名，如下图所示：一个指向`FindAllMovies` Lambda 函数`1.0.0`版本的`Production`别名，和一个指向函数`1.1.0`版本的`Staging`别名。然后，我们将配置 API Gateway 使用这些别名，而不是`$LATEST`版本：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e87027dd-a651-498d-bbab-2684b4573f3c.png)

返回到`FindAllMovies`配置页面。如果单击**Qualifiers**下拉列表，您应该看到一个名为`Unqualified`的默认别名，指向您的`$LATEST`版本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/521e0803-990d-40aa-8c5c-c5ce67395608.png)

要创建一个新别名，单击操作，然后创建一个名为`Staging`的新别名。选择`5`版本作为目标，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9b245509-65f5-45c0-b87d-a5d7ca17cc02.png)

创建后，新版本应添加到别名列表中，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/39136427-32c5-4e9a-bfaa-322cb13c6827.png)

接下来，使用 AWS 命令行为`Production`环境创建一个指向版本`1.0.0`的新别名：

```go
aws lambda create-alias --function-name FindAllMovies \
    --name Production --description "Production environment" \
    --function-version 1
```

同样，新别名应成功创建：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/87f2947c-f8ef-4520-8c29-99e84af8ea17.png)

现在我们已经创建了别名，让我们配置 API Gateway 以使用这些别名和**阶段变量**。

# 阶段变量

阶段变量是环境变量，可用于在每个部署阶段运行时更改 API Gateway 方法的行为。接下来的部分将说明如何在 API Gateway 中使用阶段变量。

在 API Gateway 控制台上，导航到`Movies` API，单击`GET`方法，并更新目标 Lambda 函数，以使用阶段变量而不是硬编码的 Lambda 函数名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c74cdbfd-622f-4eb3-a166-55242aed9c8b.png)

当您保存时，将会出现一个新的提示，要求您授予 API Gateway 调用 Lambda 函数别名的权限，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c9ea0a69-ead1-478f-a915-0ad36c30bf95.png)

执行以下命令以允许 API Gateway 调用`Production`和`Staging`别名：

+   **Production 别名：**

```go
aws lambda add-permission --function-name "arn:aws:lambda:us-east-1:ACCOUNT_ID:function:FindAllMovies:Production" \
 --source-arn "arn:aws:execute-api:us-east-1:ACCOUNT_ID:API_ID/*/GET/movies" \
 --principal apigateway.amazonaws.com \
 --statement-id STATEMENT_ID \
 --action lambda:InvokeFunction
```

+   **Staging 别名：**

```go
aws lambda add-permission --function-name "arn:aws:lambda:us-east-1:ACCOUNT_ID:function:FindAllMovies:Staging" \
 --source-arn "arn:aws:execute-api:us-east-1:ACCOUNT_ID:API_ID/*/GET/movies" \
 --principal apigateway.amazonaws.com \
 --statement-id STATEMENT_ID \
 --action lambda:InvokeFunction
```

然后，创建一个名为`production`的新阶段，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/311b2b02-9a37-49a5-b79f-b0755d8ebc44.png)

接下来，单击**Stages Variables**选项卡，并创建一个名为`lambda`的新阶段变量，并将`FindAllMovies:Production`设置为值，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/541715f5-692e-4694-8e41-ce523f6560ec.png)

对于`staging`环境，使用指向 Lambda 函数`Staging`别名的`lambda`变量进行相同操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5d2cc7e7-8ecb-4879-96ab-9e3272681b45.png)

要测试端点，请使用`cURL`命令或您熟悉的任何 REST 客户端。我选择了 Postman。在 API Gateway 的`production`阶段调用的 URL 上使用`GET`方法应该返回数据库中的所有电影，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a5b9c15a-4785-453d-89f1-ee518e30279b.png)

对于`staging`环境，执行相同操作，使用名为`Count=4`的新`Header`键；您应该只返回四个电影项目，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9e739b39-c75a-4cd4-88c8-1b4abba35045.png)

这就是您可以维护 Lambda 函数的多个环境的方法。现在，您可以通过将`Production`指针从`1.0.0`更改为`1.1.0`而轻松将`1.1.0`版本推广到生产环境，并在失败时回滚到以前的工作版本，而无需更改 API Gateway 设置。

# 摘要

AWS CLI 对于创建自动化脚本来管理 AWS Lambda 函数非常有用。

版本是不可变的，一旦发布就无法更改。另一方面，别名是动态的，它们的绑定可以随时更改以实现代码推广或回滚。采用 Lambda 函数版本的语义化版本控制可以更容易地跟踪更改。

在下一章中，我们将学习如何从头开始设置 CI/CD 流水线，以自动化部署 Lambda 函数到生产环境的过程。我们还将介绍如何在持续集成工作流程中使用别名和版本。


# 第七章：实施 CI/CD 流水线

本章将讨论高级概念，如：

+   如何建立一个高度弹性和容错的 CI/CD 流水线，自动化部署您的无服务器应用程序

+   拥有一个用于 Lambda 函数的集中式代码存储库的重要性

+   如何自动部署代码更改到生产环境。

# 技术要求

在开始本章之前，请确保您已经创建并上传了之前章节中构建的函数的源代码到一个集中的 GitHub 存储库。此外，强烈建议具有 CI/CD 概念的先前经验。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 持续集成和部署工作流

持续集成、持续部署和持续交付是加速软件上市时间并通过反馈推动创新的绝佳方式，同时确保在每次迭代中构建高质量产品。但这些实践意味着什么？在构建 AWS Lambda 中的无服务器应用程序时，如何应用这些实践？

# 持续集成

**持续集成**（**CI**）是指拥有一个集中的代码存储库，并在将所有更改和功能整合到中央存储库之前，通过一个复杂的流水线进行处理的过程。经典的 CI 流水线在代码提交时触发构建，运行单元测试和所有预整合测试，构建构件，并将结果推送到构件管理存储库。

# 持续部署

**持续部署**（**CD**）是持续集成的延伸。通过持续集成流水线的所有阶段的每个更改都会自动发布到您的暂存环境。

# 持续交付

**持续交付**（**CD**）与 CD 类似，但在将发布部署到生产环境之前需要人工干预或业务决策。

现在这些实践已经定义，您可以使用这些概念来利用自动化的力量，并构建一个端到端的部署流程，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ea5ed17b-20e6-4887-a819-1a96ad05f26e.png)

在接下来的章节中，我们将介绍如何使用最常用的 CI 解决方案构建这个流水线。

为了说明这些概念，只使用`FindAllMovies`函数的代码，但相同的步骤可以应用于其他 Lambda 函数。

# 自动化部署 Lambda 函数

在本节中，我们将看到如何构建一个流水线，以不同的方式自动化部署前一章中构建的 Lambda 函数的部署过程。

+   由 AWS 管理的解决方案，如 CodePipeline 和 CodeBuild

+   本地解决方案，如 Jenkins

+   SaaS 解决方案，如 Circle CI

# 使用 CodePipeline 和 CodeBuild 进行持续部署

AWS CodePipeline 是一个工作流管理工具，允许您自动化软件的发布和部署过程。用户定义一组步骤，形成一个可以在 AWS 托管服务（如 CodeBuild 和 CodeDeploy）或第三方工具（如 Jenkins）上执行的 CI 工作流。

在本例中，AWS CodeBuild 将用于测试、构建和部署您的 Lambda 函数。因此，应在代码存储库中创建一个名为`buildspec.yml`的构建规范文件。

`buildspec.yml`定义了将在 CI 服务器上执行的一组步骤，如下所示：

```go
version: 0.2
env:
 variables:
 S3_BUCKET: "movies-api-deployment-packages"
 PACKAGE: "github.com/mlabouardy/lambda-codepipeline"

phases:
 install:
 commands:
 - mkdir -p "/go/src/$(dirname ${PACKAGE})"
 - ln -s "${CODEBUILD_SRC_DIR}" "/go/src/${PACKAGE}"
 - go get -u github.com/golang/lint/golint

 pre_build:
 commands:
 - cd "/go/src/${PACKAGE}"
 - go get -t ./...
 - golint -set_exit_status
 - go vet .
 - go test .

 build:
 commands:
 - GOOS=linux go build -o main
 - zip $CODEBUILD_RESOLVED_SOURCE_VERSION.zip main
 - aws s3 cp $CODEBUILD_RESOLVED_SOURCE_VERSION.zip s3://$S3_BUCKET/

 post_build:
 commands:
 - aws lambda update-function-code --function-name FindAllMovies --s3-bucket $S3_BUCKET --s3-key $CODEBUILD_RESOLVED_SOURCE_VERSION.zip
```

构建规范分为以下四个阶段：

+   **安装**：

+   设置 Go 工作空间

+   安装 Go linter

+   预构建：

+   安装 Go 依赖项

+   检查我们的代码是否格式良好，并遵循 Go 的最佳实践和常见约定

+   使用`go test`命令运行单元测试

+   **构建**：

+   使用`go build`命令构建单个二进制文件

+   从生成的二进制文件创建一个部署包`.zip`

+   将`.zip`文件存储在 S3 存储桶中

+   **后构建**：

+   使用新的部署包更新 Lambda 函数的代码

单元测试命令将返回一个空响应，因为我们将在即将到来的章节中编写我们的 Lambda 函数的单元测试。

# 源提供者

现在我们的工作流已经定义，让我们创建一个持续部署流水线。打开 AWS 管理控制台（[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)），从**开发人员工具**部分导航到 AWS CodePipeline，并创建一个名为 MoviesAPI 的新流水线，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6db6f695-2630-45c0-9e83-63576d34ac8f.png)

在源位置页面上，选择 GitHub 作为源提供者，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7feb1fde-06dc-4999-bca6-e0b6e3e3bb34.png)

除了 GitHub，AWS CodePipeline 还支持 Amazon S3 和 AWS CodeCommit 作为代码源提供者。

点击“连接到 GitHub”按钮，并授权 CodePipeline 访问您的 GitHub 存储库；然后，选择存储代码的 GitHub 存储库和要构建的目标 git 分支，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e08b129d-2bec-4f09-aecf-54945f743df1.png)

# 构建提供者

在构建阶段，选择 AWS CodeBuild 作为构建服务器。Jenkins 和 Solano CI 也是支持的构建提供者。请注意以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/37e4784e-e34f-49aa-9565-0fd685bd95b1.png)

在创建流水线的下一步是定义一个新的 CodeBuild 项目，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8cbc481f-cf4f-421f-a11e-6f113046700e.png)

将构建服务器设置为带有 Golang 的 Ubuntu 实例作为运行时环境，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9ae9b608-e711-4bc6-9d36-c5c052dd42b5.png)

构建环境也可以基于 DockerHub 上公开可用的 Docker 镜像或私有注册表，例如**弹性容器注册表**（**ECR**）。

CodeBuild 将在 S3 存储桶中存储构件（`部署`包），并更新 Lambda 函数的`FindAllMovies`代码。因此，应该附加一个具有以下策略的 IAM 角色：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "lambda:UpdateFunctionCode"
      ],
      "Resource": [
        "arn:aws:s3:::movies-api-deployment-packages/*",
        "arn:aws:lambda:us-east-1:305929695733:function:FindAllMovies"
      ]
    }
  ]
}
```

在上述代码块中，`arn:aws:lambda:us-east-1`帐户 ID 应该替换为您的帐户 ID。

# 部署提供者

项目构建完成后，在流水线中配置的下一步是部署到一个环境。在本章中，我们将选择**无部署**选项，并让 CodeBuild 使用 AWS CLI 将新代码部署到 Lambda，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a0b7d842-1fa3-4663-9c84-406a128fd17e.png)

这个部署过程需要解释无服务器应用程序模型和 CloudFormation，这将在后续章节中详细解释。

审查详细信息；当您准备好时，点击保存，将创建一个新的流水线，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c9d03e61-ad1c-4484-8b0e-c7edfa0871ae.png)

流水线将启动，并且构建阶段将失败，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0408b126-c629-4b9f-8fdf-6768e30b5714.png)

如果我们点击“详细信息”链接，它将带您到该特定构建的 CodeBuild 项目页面。可以在这里看到描述构建规范文件的阶段：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0ccda68d-2537-4456-b2f1-2887fce22148.png)

如图所示，预构建阶段失败了；在底部的日志部分，我们可以看到这是由于`golint`命令：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3652dce2-7f12-4e5a-bc81-1780af212983.png)

在 Golang 中，所有顶级的、公开的名称（大写）都应该有文档注释。因此，应该在 Movie 结构声明的顶部添加一个新的注释，如下所示：

```go
// Movie entity
type Movie struct {
  ID string `json:"id"`
  Name string `json:"name"`
}
```

将新更改提交到 GitHub，新的构建将触发流水线的执行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/71c96abb-5edc-4974-ad01-e7f4f073733f.png)

您可能想知道如何将代码更改推送到代码存储库会触发新的构建。答案是 GitHub Webhooks。当您创建 CodeBuild 项目时，GitHub 存储库中会自动创建一个新的 Webhook。因此，所有对代码存储库的更改都会通过 CI 流水线，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/447e1a2c-6cc8-497f-bb5e-a5b7f13beac8.png)

一旦流水线完成，所有 CodeBuild 阶段都应该通过，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e4d8cb20-435f-44d6-b3a2-3eacaae3da54.png)

打开 S3 控制台，然后单击流水线使用的存储桶；新的部署包应该以与提交 ID 相同的键名存储：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/31f28b91-80da-4e4b-a8f7-69f8b19aebda.png)

最后，CodeBuild 将使用`update-function-code`命令更新 Lambda 函数的代码。

# 使用 Jenkins 的连续管道

多年来，Jenkins 一直是首选工具。它是一个用 Java 编写的开源持续集成服务器，构建在 Hudson 项目之上。由于其插件驱动的架构和丰富的生态系统，它具有很高的可扩展性。

在接下来的部分中，我们将使用 Jenkins 编写我们的第一个*Pipeline as Code*，但首先我们需要设置我们的 Jenkins 环境。

# 分布式构建

要开始，请按照此指南中的官方说明安装 Jenkins：[`jenkins.io/doc/book/installing/`](https://jenkins.io/doc/book/installing/)。一旦 Jenkins 启动并运行，将浏览器指向`http://instance_ip:8080`。此链接将打开 Jenkins 仪表板，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/90272e44-925b-4db2-84fd-8cbe1ce885a8.png)

使用 Jenkins 的一个优势是其主/从架构。它允许您设置一个 Jenkins 集群，其中有多个负责构建应用程序的工作节点（代理）。这种架构有许多好处：

+   响应时间，队列中等待构建的作业不多

+   并发构建数量增加

+   支持多个平台

以下步骤描述了为 Jenkins 构建服务器启动新工作节点的配置过程。工作节点是一个 EC2 实例，安装了最新稳定版本的`JDK8`和`Golang`（有关说明，请参见第二章，*使用 AWS Lambda 入门*）。

工作节点运行后，将其 IP 地址复制到剪贴板，返回 Jenkins 主控台，单击“管理 Jenkins”，然后单击“管理节点”。单击“新建节点”，给工作节点命名，并选择永久代理，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6eb5aa4c-9635-4f22-933c-d7880e1c857c.png)

然后，将节点根目录设置为 Go 工作空间，并粘贴节点的 IP 地址并选择 SSH 密钥，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2b292f78-f740-42b5-94dd-d43be27c7f15.png)

如果一切配置正确，节点将上线，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d1f68289-1dcd-4cd1-989b-581ab26cd843.png)

# 设置 Jenkins 作业

现在我们的集群已部署，我们可以编写我们的第一个 Jenkins 流水线。这个流水线定义在一个名为`Jenkinsfile`的文本文件中。这个定义文件必须提交到 Lambda 函数的代码存储库中。

Jenkins 必须安装`Pipeline`插件才能使用*Pipeline as Code*功能。这个功能提供了许多即时的好处，比如代码审查、回滚和版本控制。

考虑以下`Jenkinsfile`，它实现了一个基本的五阶段连续交付流水线，用于`FindAllMovies` Lambda 函数：

```go
def bucket = 'movies-api-deployment-packages'

node('slave-golang'){
    stage('Checkout'){
        checkout scm
    }

    stage('Test'){
        sh 'go get -u github.com/golang/lint/golint'
        sh 'go get -t ./...'
        sh 'golint -set_exit_status'
        sh 'go vet .'
        sh 'go test .'
    }

    stage('Build'){
        sh 'GOOS=linux go build -o main main.go'
        sh "zip ${commitID()}.zip main"
    }

    stage('Push'){
        sh "aws s3 cp ${commitID()}.zip s3://${bucket}"
    }

    stage('Deploy'){
        sh "aws lambda update-function-code --function-name FindAllMovies \
                --s3-bucket ${bucket} \
                --s3-key ${commitID()}.zip \
                --region us-east-1"
    }
}

def commitID() {
    sh 'git rev-parse HEAD > .git/commitID'
    def commitID = readFile('.git/commitID').trim()
    sh 'rm .git/commitID'
    commitID
}
```

流水线使用基于 Groovy 语法的**领域特定语言**（**DSL**）编写，并将在我们之前添加到集群的节点上执行。每次对 GitHub 存储库进行更改时，您的更改都将经过多个阶段：

+   检查来自源代码控制的代码

+   运行单元和质量测试

+   构建部署包并将此构件存储到 S3 存储桶

+   更新`FindAllMovies`函数的代码

请注意使用 git 提交 ID 作为部署包的名称，以便为每个发布提供有意义且重要的名称，并且如果出现问题，可以回滚到特定的提交。

现在我们的管道已经定义好，我们需要通过单击“新建”在 Jenkins 上创建一个新作业。然后，为作业输入名称，并选择多分支管道。设置存储您的 Lambda 函数代码的 GitHub 存储库以及`Jenkinsfile`的路径如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6c2d7eef-3dc1-42ae-9724-7a9060ad836a.png)

在构建之前，必须在 Jenkins 工作程序上配置具有对 S3 的写访问权限和对 Lambda 的更新操作的 IAM 实例角色。

保存后，管道将在主分支上执行，并且作业应该变为绿色，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5999f09e-3cd7-425c-a278-4c03911f888c.png)

管道完成后，您可以单击每个阶段以查看执行日志。在以下示例中，我们可以看到`部署`阶段的日志：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2ec68058-25b9-4726-840c-a30fc6fb7ffc.png)

# Git 钩子

最后，为了使 Jenkins 在您推送到代码存储库时触发构建，请从您的 GitHub 存储库中单击**设置**，然后在**集成和服务**中搜索**Jenkins（GitHub 插件）**，并填写类似以下的 URL：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/22de4b90-b340-41dc-8dbb-50039bfdf719.png)

现在，每当您将代码推送到 GitHub 存储库时，完整的 Jenkins 管道将被触发，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/be76cf6c-6847-458a-addc-59fd7147419e.png)

另一种使 Jenkins 在检测到更改时创建构建的方法是定期轮询目标 git 存储库（cron 作业）。这种解决方案效率有点低，但如果您的 Jenkins 实例在私有网络中，这可能是有用的。

# 使用 Circle CI 进行持续集成

CircleCI 是“CI/CD 即服务”。这是一个与基于 GitHub 和 BitBucket 的项目非常好地集成，并且内置支持 Golang 应用程序的平台。

在接下来的部分中，我们将看到如何使用 CircleCI 自动化部署我们的 Lambda 函数的过程。

# 身份和访问管理

使用您的 GitHub 帐户登录 Circle CI（[`circleci.com/vcs-authorize/`](https://circleci.com/vcs-authorize/)）。然后，选择存储您的 Lambda 函数代码的存储库，然后单击“设置项目”按钮，以便 Circle CI 可以自动推断设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/30df529b-2ac3-49b8-adbf-52e0d1a25501.png)

与 Jenkins 和 CodeBuild 类似，CircleCI 将需要访问一些 AWS 服务。因此，需要一个 IAM 用户。返回 AWS 管理控制台，并创建一个名为**circleci**的新 IAM 用户。生成 AWS 凭据，然后从 CircleCI 项目的设置中点击“设置”，然后粘贴 AWS 访问和秘密密钥，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e0d21756-8048-4f19-ad06-380ce93e7305.png)

确保附加了具有对 S3 读/写权限和 Lambda 函数的权限的 IAM 策略到 IAM 用户。

# 配置 CI 管道

现在我们的项目已经设置好，我们需要定义 CI 工作流程；为此，我们需要在`.circleci`文件夹中创建一个名为`config.yml`的定义文件，其中包含以下内容：

```go
version: 2
jobs:
  build:
    docker:
      - image: golang:1.8

    working_directory: /go/src/github.com/mlabouardy/lambda-circleci

    environment:
        S3_BUCKET: movies-api-deployment-packages

    steps:
      - checkout

      - run:
         name: Install AWS CLI & Zip
         command: |
          apt-get update
          apt-get install -y zip python-pip python-dev
          pip install awscli

      - run:
          name: Test
          command: |
           go get -u github.com/golang/lint/golint
           go get -t ./...
           golint -set_exit_status
           go vet .
           go test .

      - run:
         name: Build
         command: |
          GOOS=linux go build -o main main.go
          zip $CIRCLE_SHA1.zip main

      - run:
          name: Push
          command: aws s3 cp $CIRCLE_SHA1.zip s3://$S3_BUCKET

      - run:
          name: Deploy
          command: |
            aws lambda update-function-code --function-name FindAllMovies \
                --s3-bucket $S3_BUCKET \
                --s3-key $CIRCLE_SHA1.zip --region us-east-1
```

构建环境将是 DockerHub 中 Go 官方 Docker 镜像。从该镜像中，将创建一个新容器，并按照*steps*部分中列出的命令执行：

1.  从 GitHub 存储库中检出代码。

1.  安装 AWS CLI 和 ZIP 命令。

1.  执行自动化测试。

1.  从源代码构建单个二进制文件并压缩部署包。与构建对应的提交 ID 将用作 zip 文件的名称（请注意使用`CIRCLE_SHA1`环境变量）。

1.  将工件保存在 S3 存储桶中。

1.  使用 AWS CLI 更新 Lambda 函数的代码。

一旦模板被定义并提交到 GitHub 存储库，将触发新的构建，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f46c72c5-477e-4220-9556-19942ed5767b.png)

当流水线成功运行时，它会是这个样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e1b70165-60af-4bd9-a945-ec27afc3dbee.png)

基本上就是这样。本章只是初步介绍了 CI/CD 流水线的功能，但应该为您开始实验和构建 Lambda 函数的端到端工作流提供了足够的基础。

# 总结

在本章中，我们学习了如何从头开始设置 CI/CD 流水线，自动化 Lambda 函数的部署过程，以及如何使用不同的 CI 工具和服务来实现这个解决方案，从 AWS 托管服务到高度可扩展的构建服务器。

在下一章中，我们将通过为我们的无服务器 API 编写自动化单元和集成测试，以及使用无服务器函数构建带有 REST 后端的单页面应用程序，构建这个流水线的改进版本。

# 问题

1.  使用 CodeBuild 和 CodePipeline 为其他 Lambda 函数实现 CI/CD 流水线。

1.  使用 Jenkins Pipeline 实现类似的工作流。

1.  使用 CircleCI 实现相同的流水线。

1.  在现有流水线中添加一个新阶段，如果当前的 git 分支是主分支，则发布一个新版本。

1.  配置流水线，在每次部署或更新新的 Lambda 函数时，在 Slack 频道上发送通知。


# 第八章：扩展您的应用程序

本章是上一技术章节的一个短暂休息，我们将深入探讨以下内容：

+   无服务器自动扩展的工作原理

+   Lambda 如何在高峰服务使用期间处理流量需求，而无需容量规划或定期扩展

+   AWS Lambda 如何使用并发性来并行创建多个执行以执行函数的代码

+   它如何影响您的成本和应用程序性能。

# 技术要求

本章是上一章的后续，因为它将使用上一章中构建的无服务器 API；建议在处理本节之前先阅读上一章。

# 负载测试和扩展

在这部分中，我们将生成随机工作负载，以查看 Lambda 在传入请求增加时的表现。为了实现这一点，我们将使用负载测试工具，比如**Apache Bench**。在本章中，我将使用`hey`，这是一个基于 Go 的工具，由于 Golang 内置的并发性，它非常高效和快速，比传统的`HTTP`基准测试工具更快。您可以通过在终端中安装以下`Go`包来下载它：

```go
go get -u github.com/rakyll/hey
```

确保`$GOPATH`变量被设置，以便能够在任何当前目录下执行`hey`命令，或者您可以将`$HOME/go/bin`文件夹添加到`$PATH`变量中。

# Lambda 自动扩展

现在，我们准备通过执行以下命令来运行我们的第一个测试或负载测试：

```go
hey -n 1000 -c 50 https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies
```

如果您更喜欢 Apache Benchmark，可以通过将**hey**关键字替换为**ab**来使用相同的命令。

该命令将打开 50 个连接，并对 API Gateway 端点 URL 执行 1,000 个请求，用于`FindAllMovies`函数。在测试结束时，**hey**将显示有关总响应时间的信息以及每个请求的详细信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/745a0e79-f00a-40af-a9a0-8bd988ec3b7b.png)

确保用您自己的调用 URL 替换调用 URL。另外，请注意，截图的某些部分已被裁剪，以便只关注有用的内容。

除了总响应时间外，**hey**还输出了一个响应时间直方图，显示第一个请求花费更多时间（大约 2 秒）来响应，这可以解释为 Lambda 需要下载部署包并初始化新容器的**冷启动**。然而，其余的请求很快（不到 800 毫秒），这是由于**热启动**和使用先前请求的现有容器。

从先前的基准测试中，我们可以说 Lambda 在流量增加时保持了自动扩展的承诺；虽然这可能是一件好事，但它也有缺点，我们将在下一节中看到。

# 下游资源

在我们的 Movies API 示例中，DynamoDB 表已被用于解决无状态问题。该表要求用户提前定义读取和写入吞吐量容量，以创建必要的基础设施来处理定义的流量。在第五章中，*使用 DynamoDB 管理数据持久性*，我们使用了默认的吞吐量，即五个读取容量单位和五个写入容量单位。五个读取容量单位对于不太重读的 API 来说非常有效。在先前的负载测试中，我们创建了 50 个并发执行，也就是说，对`movies`表进行了 50 次并行读取。结果，表将遭受高读取吞吐量，并且`Scan`操作将变慢，DynamoDB 可能会开始限制请求。

我们可以通过转到 DynamoDB 控制台，并点击`movies`表的**Metrics**选项卡来验证这一点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3ee6584d-7f97-4382-8ccb-30bf7198d4c6.png)

显然，读取容量图经历了一个高峰期，导致读取请求被限制，并且表格被所有这些传入的请求压倒。

DynamoDB 的限流请求可以通过启用自动扩展机制来增加预留的读写容量以处理突然增加的流量，或者通过重用存储在内存缓存引擎中的查询结果（可以使用 AWS ElastiCache 与 Redis 或 Memcached 引擎等解决方案）来避免过载表并减少函数执行时间。但是，您无法限制和保护数据库资源免受 Lambda 函数扩展事件的影响。

# 私有 Lambda 函数

如果您的 Lambda 函数在私有 VPC 中运行，可能会出现并发问题，因为它需要将**弹性网络接口**（ENI）附加到 Lambda 容器，并等待分配 IP 地址。AWS Lambda 使用 ENI 安全连接到 VPC 中的内部资源。

除了性能不佳（附加 ENI 平均需要 4 秒），启用 VPC 的 Lambda 函数还需要您维护和配置一个用于互联网访问的 NAT 实例和多个可支持函数 ENI 扩展需求的 VPC 子网，这可能导致 VPC 的 IP 地址用尽。

总之，Lambda 函数的自动扩展是一把双刃剑；它不需要您进行容量规划。但是，它可能导致性能不佳和令人惊讶的月度账单。这就是**并发执行**模型发挥作用的地方。

# 并发执行

AWS Lambda 会根据流量增加动态扩展容量。但是，每次执行函数的代码数量是有限的。这个数量称为并发执行，它是根据 AWS 区域定义的。默认并发限制是每个 AWS 区域 1000 个。那么，如果您的函数超过了这个定义的阈值会发生什么呢？继续阅读以了解详情。

# Lambda 限流

如果并发执行计数超过限制，Lambda 会对您的函数应用限流（速率限制）。因此，剩余的传入请求将不会调用该函数。

调用客户端负责根据返回的`HTTP`代码（`429` =请求过多）实施基于退避策略的重试失败请求。值得一提的是，Lambda 函数可以配置为在一定数量的重试后将未处理的事件存储到名为**死信队列**的队列中。

在某些情况下，限流可能是有用的，因为并发执行容量是所有函数共享的（在我们的示例中，`find`、`update`、`insert`和`delete`函数）。您可能希望确保一个函数不会消耗所有容量，并避免其他 Lambda 函数的饥饿。如果您的某个函数比其他函数更常用，这种情况可能经常发生。例如，考虑`FindAllMovies`函数。假设现在是假期季，很多客户会使用您的应用程序查看可租用的电影列表，这可能导致多次调用`FindAllMovies` Lambda 函数。

幸运的是，AWS 增加了一个新功能，允许您预先保留和定义每个 Lambda 函数的并发执行值。这个属性允许您为函数指定一定数量的保留并发，以确保您的函数始终具有足够的容量来处理即将到来的事件或请求。例如，您可以为您的函数设置如下速率限制：

+   `FindAllMovies`函数：500

+   `InsertMovie`函数：100

+   `UpdateMovie`函数：50

+   剩下的将分享给其他人

在接下来的部分中，我们将看到如何为`FindAllMovies`定义保留的并发执行，并且它如何影响 API 的性能。

您可以使用以下公式估算并发执行计数：`每秒事件/请求*函数持续时间`。

# 并发执行预留

导航到 AWS Lambda 控制台（[`console.aws.amazon.com/lambda/home`](https://console.aws.amazon.com/lambda/home)）并单击 FindAllMovies 函数。在并发 部分，我们可以看到我们的函数仅受账户中可用并发总量的限制，该总量为**1000**，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/627e3cc6-60f8-43b8-8aab-a245c4a10ba2.png)

我们将通过在保留账户的并发字段中定义 10 来更改这一点。这样可以确保在任何给定时间内只有 10 个并行执行函数。这个值将从未保留账户的并发池中扣除，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/efe5e643-809c-4050-a213-e3d8633c152e.png)

您可以设置的最大保留并发数是 900，因为 AWS Lambda 保留了 100 个用于其他函数，以便它们仍然可以处理请求和事件。

或者，可以使用 AWS CLI 与`put-function-concurrency`命令来设置并发限制：

```go
aws lambda put-function-concurrency --function FindAllMovies --reserved-concurrent-executions 10
```

再次使用之前给出的相同命令生成一些工作负载：

```go
hey -n 1000 -c 50 https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies
```

这一次，结果将会不同，因为 1000 个请求中有 171 个失败，显示为 502 错误代码，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f4d76c40-6cb2-4b71-a121-7c4d8f6820a0.png)

超过 10 个并发执行时，将应用限流，并拒绝部分请求，返回 502 响应代码。

我们可以通过返回到函数控制台来确认这一点；我们应该看到类似于以下截图中显示的警告消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6c89cab8-ef3a-4792-905c-a3c916fb588f.png)

如果您打开与`movies`表相关的指标并跳转到读取容量图表，您会看到我们的读取容量仍然受到控制，并且低于定义的 5 个读取单位容量：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f413ad7d-8d50-4d52-8aa9-51750286955c.png)

如果您计划对 Lambda 函数进行维护并希望暂时停止其调用，可以使用限流。这可以通过将函数并发设置为 0 来实现。

限流按预期工作，现在您正在保护下游资源免受 Lambda 函数过载的影响。

# 摘要

在本章中，我们了解到 Lambda 由于 AWS 区域设置的执行限制，无法无限扩展。这个限制可以通过联系 AWS 支持团队来提高。我们还介绍了函数级别的并发预留如何帮助您保护下游资源，如果您正在使用启用了 VPC 的 Lambda 函数，则匹配子网大小，并在开发和测试函数期间控制成本。

在下一章中，我们将在无服务器 API 的基础上构建一个用户友好的 UI，具有 S3 静态托管网站功能。


# 第九章：使用 S3 构建前端

在这一章中，我们将学习以下内容：

+   如何构建一个消耗 API Gateway 响应的静态网站，使用 AWS 简单存储服务

+   如何通过 CloudFront 分发优化对网站资产的访问，例如 JavaScript、CSS、图像

+   如何为无服务器应用程序设置自定义域名

+   如何创建 SSL 证书以使用 HTTPS 显示您的内容

+   使用 CI/CD 管道自动化 Web 应用程序的部署过程。

# 技术要求

在继续本章之前，您应该对 Web 开发有基本的了解，并了解 DNS 的工作原理。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 单页应用程序

在本节中，我们将学习如何构建一个 Web 应用程序，该应用程序将调用我们在之前章节中构建的 API Gateway 调用 URL，并列出电影，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/03e5c169-f346-4aa6-b14e-aa8e484514a3.png)

对于每部电影，我们将显示其封面图像和标题。此外，用户可以通过单击右侧的按钮来按类别筛选电影。最后，如果用户单击导航栏上的“New”按钮，将弹出一个模态框，要求用户填写以下字段：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/52d23b4d-2387-4b89-b66a-31f1b0bc0b67.png)

现在应用程序的模拟已经定义，我们将使用 JavaScript 框架快速构建 Web 应用程序。例如，我将使用当前最新稳定版本的 Angular 5。

# 使用 Angular 开发 Web 应用程序

Angular 是由 Google 开发的完全集成的框架。它允许您构建动态 Web 应用程序，而无需考虑选择哪些库以及如何处理日常问题。请记住，目标是要吸引大量观众，因此选择了 Angular 作为最常用的框架之一。但是，您可以选择您熟悉的任何框架，例如 React、Vue 或 Ember。

除了内置的可用模块外，Angular 还利用了**单页应用程序**（SPA）架构的强大功能。这种架构允许您在不刷新浏览器的情况下在页面之间导航，因此使应用程序更加流畅和响应，包括更好的性能（您可以预加载和缓存额外的页面）。

Angular 自带 CLI。您可以按照[`cli.angular.io`](https://cli.angular.io)上的逐步指南进行安装。本书专注于 Lambda。因此，本章仅涵盖了 Angular 的基本概念，以便让那些不是 Web 开发人员的人能够轻松理解。

一旦安装了**Angular CLI**，我们需要使用以下命令创建一个新的 Angular 应用程序：

```go
ng new frontend
```

CLI 将生成基本模板文件并安装所有必需的**npm**依赖项以运行 Angular 5 应用程序。文件结构如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/dc7d0c0d-e3c7-469e-af1b-bd5248fcea5e.png)

接下来，在`frontend`目录中，使用以下命令启动本地 Web 服务器：

```go
ng serve
```

该命令将编译所有的`TypeScripts`文件，构建项目，并在端口`4200`上启动 Web 服务器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/38a446fd-123d-4aaf-ae92-912de1d9a18d.png)

打开浏览器并导航至[`localhost:4200`](http://localhost:4200)。您在浏览器中应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3da4087e-5f28-4843-96d6-532f7b448647.png)

现在我们的示例应用程序已构建并运行，让我们创建我们的 Web 应用程序。Angular 结构基于组件和服务架构（类似于模型-视图-控制器）。

# 生成您的第一个 Angular 组件

对于那些没有太多 Angular 经验的人来说，组件基本上就是 UI 的乐高积木。您的 Web 应用程序可以分为多个组件。每个组件都有以下文件：

+   **COMPONENT_NAME.component.ts**：用 TypeScript 编写的组件逻辑定义

+   **COMPONENT_NAME.component.html**：组件的 HTML 代码

+   **COMPONENT_NAME.component.css**：组件的 CSS 结构

+   **COMPONENT_NAME.component.spec.ts**：组件类的单元测试

在我们的示例中，我们至少需要三个组件：

+   导航栏组件

+   电影列表组件

+   电影组件

在创建第一个组件之前，让我们安装**Bootstrap**，这是 Twitter 开发的用于构建吸引人用户界面的前端 Web 框架。它带有一组基于 CSS 的设计模板，用于表单、按钮、导航和其他界面组件，以及可选的 JavaScript 扩展。

继续在终端中安装 Bootstrap 4：

```go
npm install bootstrap@4.0.0-alpha.6
```

接下来，在`.angular-cli.json`文件中导入 Bootstrap CSS 类，以便在应用程序的所有组件中使 CSS 指令可用：

```go
"styles": [
   "styles.css",
   "../node_modules/bootstrap/dist/css/bootstrap.min.css"
]
```

现在我们准备通过发出以下命令来创建我们的导航栏组件：

```go
ng generate component components/navbar
```

覆盖默认生成的`navbar.component.html`中的 HTML 代码，以使用 Bootstrap 框架提供的导航栏：

```go
<nav class="navbar navbar-toggleable-md navbar-light bg-faded">
  <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <a class="navbar-brand" href="#">Movies</a>

  <div class="collapse navbar-collapse" id="navbarSupportedContent">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="#">New <span class="sr-only">(current)</span></a>
      </li>
    </ul>
    <form class="form-inline my-2 my-lg-0">
      <input class="form-control mr-sm-2" type="text" placeholder="Search ...">
      <button class="btn btn-outline-success my-2 my-sm-0" type="submit">GO !</button>
    </form>
  </div>
</nav>
```

打开`navbar.component.ts`并将选择器属性更新为`movies-navbar`。这里的选择器只是一个标签，可以用来引用其他组件上的组件：

```go
@Component({
  selector: 'movies-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {
   ...
}
```

`movies-navbar`选择器需要添加到`app.component.html`文件中，如下所示：

```go
<movies-navbar></movies-navbar> 
```

Angular CLI 使用实时重新加载。因此，每当我们的代码更改时，CLI 将重新编译，重新注入（如果需要），并要求浏览器刷新页面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6c6f1c45-5246-4dfb-a0b3-fbe06fdfe08a.png)

当添加`movies-navbar`标签时，`navbar.component.html`文件中的所有内容都将显示在浏览器中。

同样，我们将为电影项目创建一个新组件：

```go
ng generate component components/movie-item
```

我们将在界面中将电影显示为卡片；用以下内容替换`movie-item.component.html`代码：

```go
<div class="card" style="width: 20rem;">
  <img class="card-img-top" src="img/185x287" alt="movie title">
  <div class="card-block">
    <h4 class="card-title">Movie</h4>
    <p class="card-text">Some quick description</p>
    <a href="#" class="btn btn-primary">Rent</a>
  </div>
</div>
```

在浏览器中，您应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c7123f3d-1d1a-44b3-9d50-3afa01f7bc29.png)

创建另一个组件来显示电影列表：

```go
ng generate component components/list-movies
```

该组件将使用 Angular 的`ngFor`指令来遍历`movies`数组中的`movie`并通过调用`movie-item`组件打印出电影（这称为组合）：

```go
<div class="row">
  <div class="col-sm-3" *ngFor="let movie of movies">
    <movie-item></movie-item>
  </div>
</div>
```

`movies`数组在`list-movies.component.ts`中声明，并在类构造函数中初始化：

```go
import { Component, OnInit } from '@angular/core';
import { Movie } from '../../models/movie';

@Component({
  selector: 'list-movies',
  templateUrl: './list-movies.component.html',
  styleUrls: ['./list-movies.component.css']
})
export class ListMoviesComponent implements OnInit {

  public movies: Movie[];

  constructor() {
    this.movies = [
      new Movie("Avengers", "Some description", "https://image.tmdb.org/t/p/w370_and_h556_bestv2/cezWGskPY5x7GaglTTRN4Fugfb8.jpg"),
      new Movie("Thor", "Some description", "https://image.tmdb.org/t/p/w370_and_h556_bestv2/bIuOWTtyFPjsFDevqvF3QrD1aun.jpg"),
      new Movie("Spiderman", "Some description"),
    ]
  }

  ...

}
```

`Movie`类是一个简单的实体，有三个字段，即`name`，`cover`和`description`，以及用于访问和修改类属性的 getter 和 setter：

```go
export class Movie {
  private name: string;
  private cover: string;
  private description: string;

  constructor(name: string, description: string, cover?: string){
    this.name = name;
    this.description = description;
    this.cover = cover ? cover : "http://via.placeholder.com/185x287";
  }

  public getName(){
    return this.name;
  }

  public getCover(){
    return this.cover;
  }

  public getDescription(){
    return this.description;
  }

  public setName(name: string){
    this.name = name;
  }

  public setCover(cover: string){
    this.cover = cover;
  }

  public setDescription(description: string){
    this.description = description;
  }
}
```

如果我们运行上述代码，我们将在浏览器中看到三部电影：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5cd01aa8-7d2d-4026-90ac-d566046acdd9.png)

到目前为止，电影属性在 HTML 页面中是硬编码的，为了改变这一点，我们需要将电影项目传递给`movie-item`元素。更新`movie-item.component.ts`以添加一个新的电影字段，并使用`Input`注释来使用 Angular 输入绑定：

```go
export class MovieItemComponent implements OnInit {
  @Input()
  public movie: Movie;

  ...
}
```

在前面组件的 HTML 模板中，使用`Movie`类的 getter 来获取属性的值：

```go
<div class="card">
    <img class="card-img-top" [src]="movie.getCover()" alt="{{movie.getName()}}">
    <div class="card-block">
      <h4 class="card-title">{{movie.getName()}}</h4>
      <p class="card-text">{{movie.getDescription()}}</p>
      <a href="#" class="btn btn-primary">Rent</a>
    </div>
</div>
```

最后，使`ListMoviesComponent`将`MovieItemComponent`子嵌套在`*ngFor`重复器中，并在每次迭代中将`movie`实例绑定到子的`movie`属性上：

```go
<div class="row">
  <div class="col-sm-3" *ngFor="let movie of movies">
    <movie-item [movie]="movie"></movie-item>
  </div>
</div>
```

在浏览器中，您应该确保电影的属性已经正确定义：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/630275ba-4d91-40d0-a0d8-d402270dc7c9.png)

到目前为止一切都很顺利。但是，电影列表仍然是静态的和硬编码的。我们将通过调用无服务器 API 从数据库动态检索电影列表来解决这个问题。

# 使用 Angular 访问 Rest Web 服务

在前几章中，我们创建了两个阶段，即`staging`和`production`环境。因此，我们应该创建两个环境文件，以指向正确的 API Gateway 部署阶段：

+   `environment.ts`：包含开发 HTTP URL：

```go
export const environment = {
  api: 'https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies'
};
```

+   `environment.prod.ts`：包含生产 HTTP URL：

```go
export const environment = {
  api: 'https://51cxzthvma.execute-api.us-east-1.amazonaws.com/production/movies'
};
```

如果执行`ng build`或`ng serve`，`environment`对象将从`environment.ts`中读取值，并且如果使用`ng build --prod`命令将应用程序构建为生产模式，则将从`environment.prod.ts`中读取值。

要创建服务，我们需要使用命令行。命令如下：

```go
ng generate service services/moviesApi
```

`movies-api.service.ts`将实现`findAll`函数，该函数将使用`Http`服务调用 API Gateway 的`findAll`端点。`map`方法将帮助将响应转换为 JSON 格式：

```go
import { Injectable } from '@angular/core';
import { Http } from '@angular/http';
import 'rxjs/add/operator/map';
import { environment } from '../../environments/environment';

@Injectable()
  export class MoviesApiService {

    constructor(private http:Http) { }

    findAll(){
      return this.http
      .get(environment.api)
      .map(res => {
        return res.json()
      })
    }

}
```

在调用`MoviesApiService`之前，需要在`app.module.ts`的主模块中的提供程序部分导入它。

更新`MoviesListComponent`以调用新服务。在浏览器控制台中，您应该会收到有关 Access-Control-Allow-Origin 头在 API Gateway 返回的响应中不存在的错误消息。这将是即将到来部分的主题：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/851f2f1c-7972-4bc7-bdc7-5f9b7f7a7bb5.png)

# 跨域资源共享

出于安全目的，如果外部请求与您的网站的确切主机、协议和端口不匹配，浏览器将阻止流。在我们的示例中，我们有不同的域名（localhost 和 API Gateway URL）。

这种机制被称为**同源策略**。为了解决这个问题，您可以使用 CORS 头、代理服务器或 JSON 解决方法。在本节中，我将演示如何在 Lambda 函数返回的响应中使用 CORS 头来解决此问题：

1.  修改`findAllMovie`函数的代码以添加`Access-Control-Allow-Origin:*`以允许来自任何地方的跨域请求（或指定域而不是*）：

```go
return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
    Body: string(response),
  }, nil
```

1.  提交您的更改；应触发新的构建。在 CI/CD 管道的最后，`FindAllMovies` Lambda 函数的代码将被更新。测试一下；您应该会在`headers`属性的一部分中看到新的密钥：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/07d58921-c7aa-4a90-b4c1-07eeb1c06fc0.png)

1.  如果刷新 Web 应用程序页面，JSON 对象也将显示在控制台中：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c4214806-29e1-4105-98d1-f7c212456f0e.png)

1.  更新`list-movies.component.ts`以调用`MoviesApiService`的`findAll`函数。返回的数据将存储在`movies`变量中：

```go
constructor(private moviesApiService: MoviesApiService) {
  this.movies = []

  this.moviesApiService.findAll().subscribe(res => {
    res.forEach(movie => {
    this.movies.push(new Movie(movie.name, "Some description"))
    })
  })
}
```

1.  结果，电影列表将被检索并显示：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/deeaef10-1459-4d94-ba8d-3ce1d7d111c0.png)

1.  我们没有封面图片；您可以更新 DynamoDB 的`movies`表以添加图像和描述属性：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/05553e5c-ccd9-442f-b0e1-340b1d1880ec.png)

NoSQL 数据库允许您随时更改表模式，而无需首先定义结构，而关系数据库则要求您使用预定义的模式来确定在处理数据之前的结构。

1.  如果刷新 Web 应用程序页面，您应该可以看到带有相应描述和海报封面的电影：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/38fd8f1e-4d36-468e-baca-ea0ea6b6d55f.png)

1.  通过实现新的电影功能来改进此 Web 应用程序。由于用户需要填写电影的图像封面和描述，因此我们需要更新`insert` Lambda 函数，以在后端生成随机唯一 ID 的同时添加封面和描述字段：

```go
svc := dynamodb.New(cfg)
req := svc.PutItemRequest(&dynamodb.PutItemInput{
  TableName: aws.String(os.Getenv("TABLE_NAME")),
  Item: map[string]dynamodb.AttributeValue{
    "ID": dynamodb.AttributeValue{
      S: aws.String(uuid.Must(uuid.NewV4()).String()),
    },
    "Name": dynamodb.AttributeValue{
      S: aws.String(movie.Name),
    },
    "Cover": dynamodb.AttributeValue{
      S: aws.String(movie.Cover),
    },
    "Description": dynamodb.AttributeValue{
      S: aws.String(movie.Description),
    },
  },
})
```

1.  一旦新更改被推送到代码存储库并部署，打开您的 REST 客户端并发出 POST 请求以添加新的电影，其 JSON 方案如下：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/06a712ec-4680-4479-a7a0-0ff4dd8b9a4f.png)

1.  应返回`200`成功代码，并且在 Web 应用程序中应列出新电影：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/604c09c6-c24d-4dae-916c-2e9d1cffd8ba.png)

如*单页应用程序*部分所示，当用户点击“新建”按钮时，将弹出一个带有创建表单的模态框。为了构建这个模态框并避免使用 jQuery，我们将使用另一个库，该库提供了一组基于 Bootstrap 标记和 CSS 的本机 Angular 指令：

+   使用以下命令安装此库：

```go
npm install --save @ng-bootstrap/ng-bootstrap@2.0.0
```

+   安装后，需要将其导入到主`app.module.ts`模块中，如下所示：

```go
import {NgbModule} from '@ng-bootstrap/ng-bootstrap';

@NgModule({
  declarations: [AppComponent, ...],
  imports: [NgbModule.forRoot(), ...],
  bootstrap: [AppComponent]
})
export class AppModule {
}
```

+   为了容纳创建表单，我们需要创建一个新的组件：

```go
ng generate component components/new-movie
```

+   该组件将有两个用于电影标题和封面链接的`input`字段。另外，还有一个用于电影描述的`textarea`元素：

```go
<div class="modal-header">
 <h4 class="modal-title">New Movie</h4>
 <button type="button" class="close" aria-label="Close" (click)="d('Cross click')">
 <span aria-hidden="true">&times;</span>
 </button>
</div>
<div class="modal-body">
 <div *ngIf="showMsg" class="alert alert-success" role="alert">
 <b>Well done !</b> You successfully added a new movie.
 </div>
 <div class="form-group">
 <label for="title">Title</label>
 <input type="text" class="form-control" #title>
 </div>
 <div class="form-group">
 <label for="description">Description</label>
 <textarea class="form-control" #description></textarea>
 </div>
 <div class="form-group">
 <label for="cover">Cover</label>
 <input type="text" class="form-control" #cover>
 </div>
</div>
<div class="modal-footer">
   <button type="button" class="btn btn-success" (click)="save(title.value, description.value, cover.value)">Save</button>
</div>
```

+   用户每次点击保存按钮时，将响应点击事件调用`save`函数。`MoviesApiService`服务中定义的`insert`函数调用 API Gateway 的`insert`端点上的`POST`方法：

```go
insert(movie: Movie){
  return this.http
    .post(environment.api, JSON.stringify(movie))
    .map(res => {
    return res
  })
}
```

+   在导航栏中的 New 元素上添加点击事件：

```go
<a class="nav-link" href="#" (click)="newMovie(content)">New <span class="badge badge-danger">+</span></a>
```

+   点击事件将调用`newMovie`并通过调用`ng-bootstrap`库的`ModalService`模块打开模态框：

```go
import { Component, OnInit, Input } from '@angular/core';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';

@Component({
 selector: 'movies-navbar',
 templateUrl: './navbar.component.html',
 styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {

 constructor(private modalService: NgbModal) {}

 ngOnInit() {}

 newMovie(content){
 this.modalService.open(content);
 }

}
```

+   一旦编译了这些更改，从导航栏中单击“新建”项目，模态框将弹出。填写必填字段，然后单击保存按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e44877e8-d1ca-4658-9c42-39974e51867e.png)

+   电影将保存在数据库表中。如果刷新页面，电影将显示在电影列表中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a92e0046-6172-4658-abb6-19d3781897f5.png)

# S3 静态网站托管

现在我们的应用程序已创建，让我们将其部署到远程服务器。不要维护 Web 服务器，如 EC2 实例中的 Apache 或 Nginx，让我们保持无服务器状态，并使用启用了 S3 网站托管功能的 S3 存储桶。

# 设置 S3 存储桶

要开始，可以从 AWS 控制台或使用以下 AWS CLI 命令创建一个 S3 存储桶：

```go
aws s3 mb s3://serverlessmovies.com
```

接下来，为生产模式构建 Web 应用程序：

```go
ng build --prod
```

`--prod`标志将生成代码的优化版本，并执行额外的构建步骤，如 JavaScript 和 CSS 文件的最小化，死代码消除和捆绑：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/322a7e1e-7bf4-4653-a81c-ea30977265c7.png)

这将为您提供`dist/`目录，其中包含`index.html`和所有捆绑的`js`文件，准备用于生产。配置存储桶以托管网站：

```go
aws s3 website s3://serverlessmovies.com  -- index-document index.html
```

将*dist/*文件夹中的所有内容复制到之前创建的 S3 存储桶中：

```go
aws s3 cp --recursive dist/ s3://serverlessmovies.com/
```

您可以通过 S3 存储桶仪表板或使用`aws s3 ls`命令验证文件是否已成功存储：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ba4ee6eb-461b-4b32-b183-62721b89b64a.png)

默认情况下，创建 S3 存储桶时是私有的。因此，您应该使用以下存储桶策略使其公开访问：

```go
{
  "Id": "Policy1529862214606",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1529862213126",
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::serverlessmovies.com/*",
      "Principal": "*"
    }
  ]
}
```

在存储桶配置页面上，单击“权限”选项卡，然后单击“存储桶策略”，将策略内容粘贴到编辑器中，然后保存。将弹出警告消息，指示存储桶已变为公共状态：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b07d05cc-d54b-4ed7-a076-8db8261c65f4.png)

要访问 Web 应用程序，请将浏览器指向[`serverlessmovies.s3-website-us-east-1.amazonaws.com`](http://serverlessmovies.s3-website-us-east-1.amazonaws.com)（用您自己的存储桶名称替换）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ce0b68f2-d681-4e91-bb0d-3341014dc12f.png)

现在我们的应用程序已部署到生产环境，让我们创建一个自定义域名，以便用户友好地访问网站。为了将域流量路由到 S3 存储桶，我们将使用**Amazon Route 53**创建一个指向存储桶的别名记录。

# 设置 Route 53

如果您是 Route 53 的新手，请使用您拥有的域名创建一个新的托管区域，如下图所示。您可以使用现有的域名，也可以从亚马逊注册商或 GoDaddy 等外部 DNS 注册商购买一个域名。确保选择公共托管区域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b0d9e07c-47dc-4076-a2da-0d1b79f751a9.png)

创建后，`NS`和`SOA`记录将自动为您创建。如果您从 AWS 购买了域名，您可以跳过此部分。如果没有，您必须更改您从域名注册商购买的域名的名称服务器记录。在本例中，我从 GoDaddy 购买了[`serverlessmovies.com/`](http://serverlessmovies.com/)域名，因此在域名设置页面上，我已将名称服务器更改为 AWS 提供的`NS`记录值，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/841ce75e-ea5f-4dc9-a242-19a701c61d99.png)

更改可能需要几分钟才能传播。一旦由注册商验证，跳转到`Route 53`并创建一个新的`A`别名记录，该记录指向我们之前创建的 S3 网站，方法是从下拉列表中选择目标 S3 存储桶：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/1d24fc9d-79d0-4dbc-814f-3f1af412a9db.png)

完成后，您将能够打开浏览器，输入您的域名，并查看您的 Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c14323ae-631c-4a93-9724-5839221e9c21.png)

拥有一个安全的网站可以产生差异，并使用户更加信任您的 Web 应用程序，这就是为什么在接下来的部分中，我们将使用 AWS 提供的免费 SSL 来显示自定义域名的内容，并使用`HTTPS`。

# 证书管理器

您可以轻松地通过**AWS 证书管理器（ACM）**获得 SSL 证书。点击“请求证书”按钮创建一个新的 SSL 证书：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2440c5ce-c1b2-4233-bfbc-42b7fe24561c.png)

选择请求公共证书并添加您的域名。您可能还希望通过添加一个星号来保护您的子域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8931642d-6d2c-423d-b287-0f63b7952fd2.png)

在两个域名下，点击 Route 53 中的创建记录按钮。这将自动在 Route 53 中创建一个`CNAME`记录集，并由 ACM 检查以验证您拥有这些域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/da7ccd6e-11a6-44a0-bef5-9d1036d6c1ba.png)

一旦亚马逊验证域名属于您，证书状态将从“待验证”更改为“已签发”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6629d9fa-fbb7-43a4-a7f5-10f1c68b672b.png)

然而，我们无法配置 S3 存储桶以使用我们的 SSL 来加密流量。这就是为什么我们将在 S3 存储桶前使用一个 CloudFront 分发，也被称为 CDN。

# CloudFront 分发

除了使用 CloudFront 在网站上添加 SSL 终止外，CloudFront 主要用作**内容交付网络（CDN）**，用于在世界各地的多个边缘位置存储静态资产（如 HTML 页面、图像、字体、CSS 和 JavaScript），从而实现更快的下载和更短的响应时间。

也就是说，导航到 CloudFront，然后创建一个新的 Web 分发。在原始域名字段中设置 S3 网站 URL，并将其他字段保留为默认值。您可能希望将`HTTP`流量重定向到`HTTPS`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b7c1a87b-b91d-4312-97dd-e7006fa3b72b.png)

接下来，选择我们在*证书管理器*部分创建的 SSL 证书，并将您的域名添加到备用域名（CNAME）区域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e35d051d-c500-49ee-bdbe-60b5dde4ea99.png)

点击保存，并等待几分钟，让 CloudFront 复制所有文件到 AWS 边缘位置：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9709af60-4dd2-4963-b3aa-6dd5b70eb130.png)

一旦 CDN 完全部署，跳转到域名托管区域页面，并更新网站记录以指向 CloudFront 分发域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/01ecaef5-9cfb-466d-9572-b5919502ef19.png)

如果您再次转到 URL，您应该会被重定向到`HTTPS`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/82344bd0-45df-49a9-8b65-2215ddd6f002.png)

随意创建一个新的`CNAME`记录用于 API Gateway URL。该记录可能是[`api.serverlessmovies.com`](https://api.serverlessmovies.com)，指向[`51cxzthvma.execute-api.us-east-1.amazonaws.com/production/movies`](http://51cxzthvma.execute-api.us-east-1.amazonaws.com/production/movies)。

# CI/CD 工作流

我们的无服务器应用程序已部署到生产环境。但是，为了避免每次实现新功能时都重复相同的步骤，我们可以创建一个 CI/CD 流水线，自动化前一节中描述的工作流程。我选择 CircleCI 作为 CI 服务器。但是，您可以使用 Jenkins 或 CodePipeline——请确保阅读前几章以获取更多详细信息。

如前几章所示，流水线应该在模板文件中定义。以下是用于自动化 Web 应用程序部署流程的流水线示例：

```go
version: 2
jobs:
  build:
    docker:
      - image: node:10.5.0

    working_directory: ~/serverless-movies

    steps:
      - checkout

      - restore_cache:
          key: node-modules-{{checksum "package.json"}}

      - run:
          name: Install dependencies
          command: npm install && npm install -g @angular/cli

      - save_cache:
          key: node-modules-{{checksum "package.json"}}
          paths:
            - node_modules

      - run:
          name: Build assets
          command: ng build --prod --aot false

      - run:
          name: Install AWS CLI
          command: |
            apt-get update
            apt-get install -y awscli

      - run:
          name: Push static files
          command: aws s3 cp --recursive dist/ s3://serverlessmovies.com/
```

以下步骤将按顺序执行：

+   从代码存储库检出更改

+   安装 AWS CLI，应用程序 npm 依赖项和 Angular CLI

+   使用`ng build`命令构建工件

+   将工件复制到 S3 存储桶

现在，您的 Web 应用程序代码的所有更改都将通过流水线进行，并将自动部署到生产环境：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3d1c29e1-1de2-410b-bff5-ba6ce1d90eca.png)

# API 文档

在完成本章之前，我们将介绍如何为迄今为止构建的无服务器 API 创建文档。

在 API Gateway 控制台上，选择要为其生成文档的部署阶段。在下面的示例中，我选择了`production`环境。然后，单击“导出”选项卡，单击“导出为 Swagger”部分：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/68a99745-c216-4fa1-ba0a-3d7851162a5c.png)

Swagger 是**OpenAPI**的实现，这是 Linux Foundation 定义的关于如何描述和定义 API 的标准。这个定义被称为**OpenAPI 规范文档**。

您可以将文档保存为 JSON 或 YAML 文件。然后，转到[`editor.swagger.io/`](https://editor.swagger.io/)并将内容粘贴到网站编辑器上，它将被编译，并生成一个 HTML 页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0c8796d5-7187-469e-be1b-263ab3498dac.png)

AWS CLI 也可以用于导出 API Gateway 文档，使用`aws apigateway get-export --rest-api-id API_ID --stage-name STAGE_NAME --export-type swagger swagger.json`命令。

API Gateway 和 Lambda 函数与无服务器应用程序类似。可以编写 CI/CD 来自动化生成文档，每当在 API Gateway 上实现新的端点或资源时。流水线必须执行以下步骤：

+   创建一个 S3 存储桶

+   在存储桶上启用静态网站功能

+   从[`github.com/swagger-api/swagger-ui`](https://github.com/swagger-api/swagger-ui)下载 Swagger UI，并将源代码复制到 S3

+   创建 DNS 记录（[docs.serverlessmovies.com](http://docs.serverlessmovies.com)）

+   运行`aws apigateway export`命令生成 Swagger 定义文件

+   使用`aws s3 cp`命令将`spec`文件复制到 S3

# 摘要

总之，我们已经看到了如何使用多个 Lambda 函数从头开始构建无服务器 API，以及如何使用 API Gateway 创建统一的 API 并将传入的请求分派到正确的 Lambda 函数。我们通过 DynamoDB 数据存储解决了 Lambda 的无状态问题，并了解了保留并发性如何帮助保护下游资源。然后，我们在 S3 存储桶中托管了一个无服务器 Web 应用程序，并在其前面使用 CloudFront 来优化 Web 资产的交付。最后，我们学习了如何使用 Route 53 将域流量路由到 Web 应用程序，并如何使用 SSL 终止来保护它。

以下图示了我们迄今为止实施的架构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/1db81716-6ac1-4b45-bb1b-070252a8166d.png)

在下一章中，我们将改进 CI/CD 工作流程，添加单元测试和集成测试，以在将 Lambda 函数部署到生产环境之前捕获错误和问题。

# 问题

1.  实现一个以电影类别为输入并返回与该类别对应的电影列表的 Lambda 函数。

1.  实现一个 Lambda 函数，以电影标题作为输入，返回所有标题中包含关键字的电影。

1.  在 Web 应用程序上实现一个删除按钮，通过调用 API Gateway 的`DeleteMovie` Lambda 函数来删除电影。

1.  在 Web 应用程序上实现一个编辑按钮，允许用户更新电影属性。

1.  使用 CircleCI、Jenkins 或 CodePipeline 实现 CI/CD 工作流程，自动化生成和部署 API Gateway 文档。


# 第十章：测试您的无服务器应用程序

本章将教您如何使用 AWS 无服务器应用程序模型在本地测试您的无服务器应用程序。我们还将介绍使用第三方工具进行 Go 单元测试和性能测试，以及如何使用 Lambda 本身执行测试工具。

# 技术要求

本章是第七章的后续内容，*实施 CI/CD 流水线*，因此建议先阅读该章节，以便轻松地跟随本章。此外，建议具有测试驱动开发实践经验。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 单元测试

对 Lambda 函数进行单元测试意味着尽可能完全地（尽可能）从外部资源（如以下事件：DynamoDB、S3、Kinesis）中隔离测试函数处理程序。这些测试允许您在实际部署新更改到生产环境之前捕获错误，并维护源代码的质量、可靠性和安全性。

在我们编写第一个单元测试之前，了解一些关于 Golang 中测试的背景可能会有所帮助。要在 Go 中编写新的测试套件，文件名必须以`_test.go`结尾，并包含以`TestFUNCTIONNAME`前缀的函数。`Test`前缀有助于识别测试例程。以`_test`结尾的文件将在构建部署包时被排除，并且只有在发出`go test`命令时才会执行。此外，Go 自带了一个内置的`testing`包，其中包含许多辅助函数。但是，为了简单起见，我们将使用一个名为`testify`的第三方包，您可以使用以下命令安装：

```go
go get -u github.com/stretchr/testify
```

以下是我们在上一章中构建的 Lambda 函数的示例，用于列出 DynamoDB 表中的所有电影。以下代表我们要测试的代码：

```go
func findAll() (events.APIGatewayProxyResponse, error) {
  ...

  svc := dynamodb.New(cfg)
  req := svc.ScanRequest(&dynamodb.ScanInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
  })
  res, err := req.Send()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while scanning DynamoDB",
    }, nil
  }

  ...

  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
    Body: string(response),
  }, nil
}
```

为了充分覆盖代码，我们需要测试所有边缘情况。我们可以执行的测试示例包括：

+   测试在未分配给函数的 IAM 角色的情况下的行为。

+   使用分配给函数的 IAM 角色进行测试。

为了模拟 Lambda 函数在没有 IAM 角色的情况下运行，我们可以删除凭据文件或取消设置本地使用的 AWS 环境变量。然后，发出`aws s3 ls`命令以验证 AWS CLI 无法找到 AWS 凭据。如果看到以下消息，那么您应该可以继续：

```go
Unable to locate credentials. You can configure credentials by running "aws configure".
```

在名为`main_test.go`的文件中编写您的单元测试：

```go
package main

import (
  "net/http"
  "testing"

  "github.com/aws/aws-lambda-go/events"
  "github.com/stretchr/testify/assert"
)

func TestFindAll_WithoutIAMRole(t *testing.T) {
  expected := events.APIGatewayProxyResponse{
    StatusCode: http.StatusInternalServerError,
    Body: "Error while scanning DynamoDB",
  }
  response, err := findAll()
  assert.IsType(t, nil, err)
  assert.Equal(t, expected, response)
}
```

测试函数以`Test`关键字开头，后跟函数名称和我们要测试的行为。然后，它调用`findAll`处理程序并将实际结果与预期响应进行比较。然后，您可以按照以下步骤进行：

1.  使用以下命令启动测试。该命令将查找当前文件夹中的任何文件中的任何测试并运行它们。确保设置`TABLE_NAME`环境变量：

```go
TABLE_NAME=movies go test
```

太棒了！我们的测试有效，因为预期和实际响应体等于**扫描 DynamoDB 时出错**的值：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b4ba8220-279b-4562-92f4-29cdf384bd74.png)

1.  编写另一个测试函数，以验证如果在运行时将 IAM 角色分配给 Lambda 函数的处理程序行为：

```go
package main

import (
  "testing"

  "github.com/stretchr/testify/assert"
)

func TestFindAll_WithIAMRole(t *testing.T) {
  response, err := findAll()
  assert.IsType(t, nil, err)
  assert.NotNil(t, response.Body)
}
```

再次，测试应该通过，因为预期和实际响应体不为空：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e9ea1546-d3a4-4e18-8d47-de990ba34e8c.png)

您现在已经在 Go 中运行了一个单元测试；让我们为期望输入参数的 Lambda 函数编写另一个单元测试。让我们以`insert`方法为例。我们要测试的代码如下（完整代码可以在 GitHub 存储库中找到）：

```go
func insert(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  ...
  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  }, nil
}
```

这种情况是输入参数的无效有效负载。函数应返回带有`Invalid payload`消息的`400`错误：

```go
func TestInsert_InvalidPayLoad(t *testing.T) {
  input := events.APIGatewayProxyRequest{
    Body: "{'name': 'avengers'}",
  }

  expected := events.APIGatewayProxyResponse{
    StatusCode: 400,
    Body: "Invalid payload",
  }
  response, _ := insert(input)
  assert.Equal(t, expected, response)
}
```

另一个用例是在给定有效负载的情况下，函数应将电影插入数据库并返回`200`成功代码：

```go
func TestInsert_ValidPayload(t *testing.T) {
  input := events.APIGatewayProxyRequest{
    Body: "{\"id\":\"40\", \"name\":\"Thor\", \"description\":\"Marvel movie\", \"cover\":\"poster url\"}",
  }
  expected := events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  }
  response, _ := insert(input)
  assert.Equal(t, expected, response)
}
```

两个测试应该成功通过。这次，我们将以代码覆盖模式运行`go test`命令，使用`-cover`标志：

```go
TABLE_NAME=movies go test -cover
```

我们有 78%的代码被单元测试覆盖：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/13ecb74b-ad68-471c-a8ee-a3c87b2b656b.png)

如果您想深入了解测试覆盖了哪些语句，哪些没有，可以使用以下命令生成 HTML 覆盖报告：

```go
TABLE_NAME=movies go test -cover -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

如果在浏览器中打开`coverage.html`，您可以看到单元测试未覆盖的语句：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d234993b-c1bf-4817-9348-fdd985d708ec.png)

您可以通过利用 Go 的接口来改进单元测试，以模拟 DynamoDB 调用。这允许您模拟 DynamoDB 的实现，而不是直接使用具体的服务客户端（例如，[`aws.amazon.com/blogs/developer/mocking-out-then-aws-sdk-for-go-for-unit-testing/`](https://aws.amazon.com/blogs/developer/mocking-out-then-aws-sdk-for-go-for-unit-testing/)）。

# 自动化单元测试

拥有单元测试是很好的。然而，没有自动化的单元测试是没有用的，因此您的 CI/CD 流水线应该有一个测试阶段，以执行对代码存储库提交的每个更改的单元测试。这种机制有许多好处，例如确保您的代码库处于无错误状态，并允许开发人员持续检测和修复集成问题，从而避免在发布日期上出现最后一分钟的混乱。以下是我们在前几章中构建的自动部署 Lambda 函数的流水线的示例：

```go
version: 2
jobs:
 build:
 docker:
 - image: golang:1.8

 working_directory: /go/src/github.com/mlabouardy/lambda-circleci

 environment:
 S3_BUCKET: movies-api-deployment-packages
 TABLE_NAME: movies
 AWS_REGION: us-east-1

 steps:
 - checkout

 - run:
 name: Install AWS CLI & Zip
 command: |
 apt-get update
 apt-get install -y zip python-pip python-dev
 pip install awscli

 - run:
 name: Test
 command: |
 go get -u github.com/golang/lint/golint
 go get -t ./...
 golint -set_exit_status
 go vet .
 go test .

 - run:
 name: Build
 command: |
 GOOS=linux go build -o main main.go
 zip $CIRCLE_SHA1.zip main

 - run:
 name: Push
 command: aws s3 cp $CIRCLE_SHA1.zip s3://$S3_BUCKET

 - run:
 name: Deploy
 command: |
 aws lambda update-function-code --function-name InsertMovie \
 --s3-bucket $S3_BUCKET \
 --s3-key $CIRCLE_SHA1.zip --region us-east-1
```

对 Lambda 函数源代码的所有更改都将触发新的构建，并重新执行单元测试：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a2bdf032-5bb6-4535-82e6-9df0a6af07ce.png)

如果单击“Test”阶段，您将看到详细的`go test`命令结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/80ce3d49-f65b-4387-876c-b1992f325189.png)

# 集成测试

与单元测试不同，单元测试测试系统的一个单元，集成测试侧重于作为一个整体测试 Lambda 函数。那么，在不将它们部署到 AWS 的本地开发环境中如何测试 Lambda 函数呢？继续阅读以了解更多信息。

# RPC 通信

如果您阅读 AWS Lambda 的官方 Go 库（[`github.com/aws/aws-lambda-go`](https://github.com/aws/aws-lambda-go)）的底层代码，您会注意到基于 Go 的 Lambda 函数是使用`net/rpc`通过**TCP**调用的。每个 Go Lambda 函数都会在由`_LAMBDA_SERVER_PORT`环境变量定义的端口上启动服务器，并等待传入请求。为了与函数交互，使用了两个 RPC 方法：

+   `Ping`：用于检查函数是否仍然存活和运行

+   `Invoke`：用于执行请求

有了这些知识，我们可以模拟 Lambda 函数的执行，并执行集成测试或预部署测试，以减少将函数部署到 AWS 之前的等待时间。我们还可以在开发生命周期的早期阶段修复错误，然后再将新更改提交到代码存储库。

以下示例是一个简单的 Lambda 函数，用于计算给定数字的 Fibonacci 值。斐波那契数列是前两个数字的和。以下代码是使用递归实现的斐波那契数列：

```go
package main

import "github.com/aws/aws-lambda-go/lambda"

func fib(n int64) int64 {
  if n > 2 {
    return fib(n-1) + fib(n-2)
  }
  return 1
}

func handler(n int64) (int64, error) {
  return fib(n), nil
}

func main() {
  lambda.Start(handler)
}
```

Lambda 函数通过 TCP 监听端口，因此我们需要通过设置`_LAMBDA_SERVER_PORT`环境变量来定义端口：

```go
_LAMBDA_SERVER_PORT=3000 go run main.go
```

要调用函数，可以使用`net/rpc` go 包中的`invoke`方法，也可以安装一个将 RPC 通信抽象为单个方法的 Golang 库：

```go
go get -u github.com/djhworld/go-lambda-invoke 
```

然后，通过设置运行的端口和要计算其斐波那契数的数字来调用函数：

```go
package main

import (
  "fmt"
  "log"

  "github.com/djhworld/go-lambda-invoke/golambdainvoke"
)

func main() {
  response, err := golambdainvoke.Run(3000, 9)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(string(response))
}
```

使用以下命令调用 Fibonacci Lambda 函数：

```go
go run client.go
```

结果，`fib(9)=34`如预期返回：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/72d7a601-bd42-4d7f-a922-c34269b10d76.png)

另一种方法是使用`net/http`包构建 HTTP 服务器，模拟 Lambda 函数在 API Gateway 后面运行，并以与测试任何 HTTP 服务器相同的方式测试函数，以验证处理程序。

在下一节中，我们将看到如何使用 AWS 无服务器应用程序模型以更简单的方式在本地测试 Lambda 函数。

# 无服务器应用程序模型

**无服务器应用程序模型**（**SAM**）是一种在 AWS 中定义无服务器应用程序的方式。它是对**CloudFormation**的扩展，允许在模板文件中定义运行函数所需的所有资源。

请参阅第十四章，*基础设施即代码*，了解如何使用 SAM 从头开始构建无服务器应用程序的说明。

此外，AWS SAM 允许您创建一个开发环境，以便在本地测试、调试和部署函数。执行以下步骤：

1.  要开始，请使用`pip` Python 包管理器安装 SAM CLI：

```go
pip install aws-sam-cli
```

确保安装所有先决条件，并确保 Docker 引擎正在运行。有关更多详细信息，请查看官方文档[`docs.aws.amazon.com/lambda/latest/dg/sam-cli-requirements.html`](https://docs.aws.amazon.com/lambda/latest/dg/sam-cli-requirements.html)。

1.  安装后，运行`sam --version`。如果一切正常，它应该输出 SAM 版本（在撰写本书时为*v0.4.0*）。

1.  为 SAM CLI 创建`template.yml`，在其中我们将定义运行函数所需的运行时和资源：

```go
AWSTemplateFormatVersion : '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: List all movies.
Resources:
 FindAllMovies:
 Type: AWS::Serverless::Function
 Properties:
 Handler: main
 Runtime: go1.x
 Events:
 Vote:
 Type: Api
 Properties:
 Path: /movies
 Method: get
```

SAM 文件描述了运行时环境和包含代码的处理程序的名称，当调用时，Lambda 函数将执行该代码。此外，模板定义了将触发函数的事件；在本例中，它是 API Gateway 端点。

+   为 Linux 构建部署包：

```go
GOOS=linux go build -o main
```

+   在本地使用`sam local`命令运行函数：

```go
sam local start-api
```

HTTP 服务器将在端口`3000`上运行并侦听：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3a87d6d2-f4c5-4724-a0ca-f9773c53b1e1.png)

如果您导航到`http://localhost:3000/movies`，在返回响应之前可能需要几分钟，因为它需要获取一个 Docker 镜像：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7d01d552-40a9-4efc-88ea-0eb05322e4e0.png)

SAM 本地利用容器的强大功能在 Docker 容器中运行 Lambda 函数的代码。在前面的屏幕截图中，它正在从 DockerHub（一个镜像存储库）拉取`lambci/lambda:go1.x` Docker 镜像。您可以通过运行以下命令来列出机器上所有可用的镜像来确认：

```go
docker image ls
```

以下是前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5d6f0c47-6cdd-4a0f-a9a0-44a9af77c2dc.png)

一旦拉取了镜像，将基于您的`deployment`包创建一个新的容器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f0a93574-b2b8-468d-9eb0-eedc237b867c.png)

在浏览器中，将显示错误消息，因为我们忘记设置 DynamoDB 表的名称：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/263599b2-995d-4e38-9864-95fc3466c5bb.png)

我们可以通过创建一个`env.json`文件来解决这个问题，如下所示：

```go
{
    "FindAllMovies" : {
        "TABLE_NAME" : "movies"
    }
}
```

使用`--env-var`参数运行`sam`命令：

```go
sam local start-api --env-vars env.json
```

您还可以在同一 SAM 模板文件中使用`Environment`属性声明环境变量。

这次，您应该在 DynamoDB `movies`表中拥有所有电影，并且函数应该按预期工作：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5bf58d20-54a7-442c-b137-d7269c0322d0.png)

# 负载测试

我们已经看到了如何使用基准测试工具，例如 Apache Benchmark，以及如何测试测试工具。在本节中，我们将看看如何使用 Lambda 本身作为**无服务器测试**测试平台。

这个想法很简单：我们将编写一个 Lambda 函数，该函数将调用我们想要测试的 Lambda 函数，并将其结果写入 DynamoDB 表进行报告。幸运的是，这里不需要编码，因为 Lambda 函数已经在蓝图部分中可用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f89c5a72-804b-45f7-b944-0667cbc6abe0.png)

为函数命名并创建一个新的 IAM 角色，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/444ab0b3-a64e-4ab6-b70f-69490d9a6ab7.png)

单击“创建函数”，函数应该被创建，并授予执行以下操作的权限：

+   将日志推送到 CloudWatch。

+   调用其他 Lambda 函数。

+   向 DynamoDB 表写入数据。

以下截图展示了前面任务完成后的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5cf896bd-c523-4fb9-a3f0-f80760c8b124.png)

在启动负载测试之前，我们需要创建一个 DynamoDB 表，Lambda 将在其中记录测试的输出。该表必须具有`testId`的哈希键字符串和`iteration`的范围数字：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/003994a1-840e-4eda-9522-c116044eb434.png)

创建后，使用以下 JSON 模式调用 Lambda 函数。它将异步调用给定函数 100 次。指定一个唯一的`event.testId`来区分每个单元测试运行：

```go
{
    "operation": "load",
    "iterations": 100,
    "function": "HarnessTestFindAllMovies",
    "event": {
      "operation": "unit",
      "function": "FindAllMovies",
      "resultsTable": "load-test-results",
      "testId": "id",
      "event": {
        "options": {
          "host": "https://51cxzthvma.execute-api.us-east-1.amazonaws.com",
          "path": "/production/movies",
          "method": "GET"
        }
      }
    }
  }
```

结果将记录在 JSON 模式中给出的 DynamoDB 表中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/1379afc6-c4e7-4fee-81a7-23ff50929bdb.png)

您可能需要修改函数的代码以保存其他信息，例如运行时间、资源使用情况和响应时间。

# 摘要

在本章中，我们学习了如何为 Lambda 函数编写单元测试，以覆盖函数的所有边缘情况。我们还学习了如何使用 AWS SAM 设置本地开发环境，以在本地测试和部署函数，以确保其行为在部署到 AWS Lambda 之前正常工作。

在下一章中，我们将介绍如何使用 AWS 托管的服务（如 CloudWatch 和 X-Ray）来排除故障和调试无服务器应用程序。

# 问题

1.  为`UpdateMovie` Lambda 函数编写一个单元测试。

1.  为`DeleteMovie` Lambda 函数编写一个单元测试。

1.  修改前几章提供的`Jenkinsfile`，以包括自动化单元测试的执行。

1.  修改`buildspec.yml`定义文件，以在将部署包推送到 S3 之前，包括执行单元测试的执行。

1.  为前几章实现的每个 Lambda 函数编写一个 SAM 模板文件。
