# Go 无服务应用实用指南（三）

> 原文：[`zh.annas-archive.org/md5/862FBE1FF9A9C074341990A4C2200D42`](https://zh.annas-archive.org/md5/862FBE1FF9A9C074341990A4C2200D42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：监控和故障排除

Lambda 监控与传统应用程序监控不同，因为您不管理代码运行的基础基础设施。因此，无法访问 OS 指标。但是，您仍然需要函数级别的监控来优化函数性能，并在发生故障时进行调试。在本章中，您将学习如何实现这一点，以及如何在 AWS 中调试和故障排除无服务器应用程序。您将学习如何基于 CloudWatch 中的指标阈值设置警报，以便在可能出现问题时收到通知。您还将了解如何使用 AWS X-Ray 对应用程序进行分析，以检测异常行为。

# 使用 AWS CloudWatch 进行监控和调试

AWS CloudWatch 是监控 AWS 服务的最简单和最可靠的解决方案，包括 Lambda 函数。它是一个集中的监控服务，用于收集指标和日志，并根据它们创建警报。AWS Lambda 会自动代表您监视 Lambda 函数，并通过 CloudWatch 报告指标。

# CloudWatch 指标

默认情况下，每次通过 Lambda 控制台调用函数时，它都会报告有关函数资源使用情况、执行持续时间以及计费时间的关键信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6531421d-cf8f-4b9c-9e47-5909459dc47a.png)

单击“监控”选项卡可以快速实时了解情况。此页面将显示多个 CloudWatch 指标的图形表示。您可以在图形区域的右上角控制可观察时间段：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9c882ed5-6d46-4f98-abb9-551c134e0826.png)

这些指标包括：

+   函数被调用的次数

+   执行时间（毫秒）

+   错误率和由于并发预留和未处理事件（死信错误）而导致的节流计数

在 CloudWatch 中为 AWS Lambda 提供的所有可用指标列表可以在[`docs.aws.amazon.com/lambda/latest/dg/monitoring-functions-metrics.html`](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions-metrics.html)找到。

对于每个指标，您还可以单击“在指标中查看”直接查看 CloudWatch 指标：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/784ccac2-06a9-4ba2-9b6d-c9f37c061ee8.png)

前面的图表表示在过去 15 分钟内`production`和`staging`别名的`FindAllMovies`函数的调用次数。您可以进一步创建自定义图表。这使您可以为 Lambda 函数构建自定义仪表板。它将概述负载（您可能会遇到的任何问题）、成本和其他重要指标。

此外，您还可以使用 CloudWatch Golang SDK 创建自定义指标并将其发布到 CloudWatch。以下代码片段是使用 CloudWatch SDK 发布自定义指标的 Lambda 函数。该指标表示插入到 DynamoDB 中的`Action`电影的数量（为简洁起见，某些部分被省略）：

```go
svc := cloudwatch.New(cfg)
req := svc.PutMetricDataRequest(&cloudwatch.PutMetricDataInput{
  Namespace: aws.String("InsertMovie"),
  MetricData: []cloudwatch.MetricDatum{
    cloudwatch.MetricDatum{
      Dimensions: []cloudwatch.Dimension{
        cloudwatch.Dimension{
          Name: aws.String("Environment"),
          Value: aws.String("production"),
        },
      },
      MetricName: aws.String("ActionMovies"),
      Value: aws.Float64(1.0),
      Unit: cloudwatch.StandardUnitCount,
    },
  },
})
```

该指标由名称、命名空间、维度列表（名称-值对）、值和度量单位唯一定义。在您向 CloudWatch 发布了一些值之后，您可以使用 CloudWatch 控制台查看统计图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3c2095f7-f42f-4b20-bc76-e75a943caa13.png)

现在我们知道如何使用 AWS 提供的现成指标监视我们的 Lambda 函数，并将自定义指标插入到 CloudWatch 中以丰富它们的可观察性。让我们看看如何基于这些指标创建警报，以便在 Lambda 函数出现问题时实时通知我们。

# CloudWatch 警报

CloudWatch 允许您在发生意外行为时基于可用指标创建警报。在以下示例中，我们将基于`FindAllMovies`函数的错误率创建警报：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3fa0ab95-2e59-4eff-8d54-f6ac34dacb3c.png)

为了实现这一点，请点击“操作”列中的铃铛图标。然后，填写以下字段以设置一个警报，如果在五分钟内错误数量超过`10`，则会触发警报。一旦触发警报，将使用**简单通知服务**（**SNS**）发送电子邮件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ba1efb6b-99c5-4ad2-9481-b9bb7cbb3916.png)

CloudWatch 将通过 SNS 主题发送通知，您可以创建尽可能多的 SNS 主题订阅，以便将通知传递到您想要的位置（短信、HTTP、电子邮件）。

点击“创建警报”按钮；您应该收到一封确认订阅的电子邮件。您必须在通知发送之前确认订阅：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a4543244-f971-4e83-97be-1fca4344f1f8.png)

一旦确认，每当 Lambda 函数的错误率超过定义的阈值时，警报将从“正常”状态更改为“警报”状态：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ff1b8461-b283-472d-8eaa-f53e598639cb.png)

之后，将会向您发送一封电子邮件作为事件的响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6e702fd1-dbdf-4e02-a048-7073d732e443.png)

您可以通过使用此 AWS CLI 命令临时更改其状态来模拟警报：`aws cloudwatch set-alarm-state --alarm-name ALARM_NAME --state-value ALARM --state-reason demo`。

# CloudWatch 日志

在使用 AWS Lambda 时，当函数被调用时，您可能会遇到以下错误：

+   应用程序错误

+   权限被拒绝

+   超时

+   内存超限

除了第一个用例外，其余的都可以通过授予正确的 IAM 策略并增加 Lambda 函数的超时或内存使用量来轻松解决。然而，第一个错误需要更多的调试和故障排除，这需要在代码中添加日志记录语句来验证您的代码是否按预期工作。幸运的是，每当 Lambda 函数的代码响应事件执行时，它都会将日志条目写入与 Lambda 函数关联的 CloudWatch 日志组，即`/aws/lambda/FUNCTION_NAME`。

为了实现这一点，您的 Lambda 函数应被授予以下权限：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "1",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:CreateLogGroup",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

也就是说，您可以使用 Go 的内置日志记录库，称为`log`包。以下是如何使用`log`包的示例：

```go
package main

import (
  "log"

  "github.com/aws/aws-lambda-go/lambda"
)

func reverse(s string) string {
  runes := []rune(s)
  for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
    runes[i], runes[j] = runes[j], runes[i]
  }
  return string(runes)
}

func handler(input string) (string, error) {
  log.Println("Before:", input)
  output := reverse(input)
  log.Println("After:", output)
  return output, nil
}

func main() {
  lambda.Start(handler)
}
```

代码是不言自明的，它对给定字符串执行了一个反向操作。我已经使用`log.Println`方法在代码的各个部分周围添加了日志记录语句。

然后，您可以将函数部署到 AWS Lambda，并从 AWS 控制台或使用`invoke`命令调用它。Lambda 会自动集成到 Amazon CloudWatch 日志，并将代码中的所有日志推送到与 Lambda 函数关联的 CloudWatch 日志组：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e45bccab-f93d-4661-91d6-6c7fc2c0f4aa.png)

到目前为止，我们已经学会了如何通过日志和运行时数据来排除故障和分析每次调用。在接下来的部分中，我们将介绍如何在 Lambda 函数的代码中跟踪所有上游和下游对外部服务的调用，以便快速轻松地排除错误。为了跟踪所有这些调用，我们将在实际工作执行的不同代码段中使用 AWS X-Ray 添加代码仪器。

有许多第三方工具可用于监视无服务器应用程序，这些工具依赖于 CloudWatch。因此，它们在实时问题上也会失败。我们期望这在未来会得到解决，因为 AWS 正在以快速的速度推出新的服务和功能。

# 使用 AWS X-Ray 进行跟踪

AWS X-Ray 是 AWS 管理的服务，允许您跟踪 Lambda 函数发出的传入和传出请求。它将这些信息收集在段中，并使用元数据记录附加数据，以帮助您调试、分析和优化函数。

总的来说，X-Ray 可以帮助您识别性能瓶颈。然而，它可能需要在函数执行期间进行额外的网络调用，增加用户面对的延迟。

要开始，请从 Lambda 函数的配置页面启用主动跟踪：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d72406c2-c9cc-4434-9820-7652783e87b9.png)

要求以下 IAM 策略以使 Lambda 函数发布跟踪段到 X-Ray：

```go
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords"
    ],
    "Resource": [
      "*"
    ]
  }
}
```

接下来，转到 AWS X-Ray 控制台，单击“跟踪”，多次调用 Lambda 函数，并刷新页面。将在跟踪列表中添加新行。对于每个跟踪，您将获得代码响应和执行时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3e546688-f17e-4664-9dfe-e7ffc11bd21e.png)

这是`FindAllMovies`函数的跟踪；它包括 Lambda 初始化函数所需的时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bc9e0fc6-0e35-41f4-9db1-d5b24fbe4321.png)

您还可以通过单击“服务映射”项以图形格式可视化此信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ba0d574c-367a-4d44-a658-581e21d2b37f.png)

对于每个被跟踪的调用，Lambda 将发出 Lambda 服务段和其所有子段。此外，Lambda 将发出 Lambda 函数段和 init 子段。这些段将被发出，而无需对函数的运行时进行任何更改或需要任何其他库。如果要使 Lambda 函数的 X-Ray 跟踪包括用于下游调用的自定义段、注释或子段，可能需要安装以下 X-Ray Golang SDK：

```go
go get -u github.com/aws/aws-xray-sdk-go/...
```

更新`FindAllMovies`函数的代码以使用`Configure`方法配置 X-Ray：

```go
xray.Configure(xray.Config{
  LogLevel: "info",
  ServiceVersion: "1.2.3",
})
```

我们将通过使用`xray.AWS`调用包装 DynamoDB 客户端来在子段中跟踪对 DynamoDB 的调用，如下面的代码所示：

```go
func findAll(ctx context.Context) (events.APIGatewayProxyResponse, error) {
  xray.Configure(xray.Config{
    LogLevel: "info",
    ServiceVersion: "1.2.3",
  })

  sess := session.Must(session.NewSession())
  dynamo := dynamodb.New(sess)
  xray.AWS(dynamo.Client)

  res, err := dynamo.ScanWithContext(ctx, &dynamodb.ScanInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
  })

  ...
}
```

再次在 X-Ray“跟踪”页面上调用 Lambda 函数；将添加一个新的子段，显示它扫描`movies`表所花费的时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/79e37175-591c-4532-aeec-81479af31884.png)

DynamoDB 调用还将显示为 X-Ray 控制台中服务映射上的下游节点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b52caee3-57e6-4cb0-a121-bc4e416fcada.png)

现在我们已经熟悉了 X-Ray 的工作原理，让我们创建一些复杂的东西。考虑一个简单的 Lambda 函数，它以电影海报页面的 URL 作为输入。它解析 HTML 页面，提取数据，并将其保存到 DynamoDB 表中。此函数将在给定 URL 上执行`GET`方法：

```go
res, err := http.Get(url)
if err != nil {
  log.Fatal(err)
}
defer res.Body.Close()
```

然后，它使用`goquery`库（**JQuery** Go 的实现）从 HTML 页面中提取数据，使用 CSS 选择器：

```go
doc, err := goquery.NewDocumentFromReader(res.Body)
if err != nil {
  log.Fatal(err)
}

title := doc.Find(".header .title span a h2").Text()
description := doc.Find(".overview p").Text()
cover, _ := doc.Find(".poster .image_content img").Attr("src")

movie := Movie{
  ID: uuid.Must(uuid.NewV4()).String(),
  Name: title,
  Description: description,
  Cover: cover,
}
```

创建电影对象后，它使用`PutItem`方法将电影保存到 DynamoDB 表：

```go
sess := session.Must(session.NewSession())
dynamo := dynamodb.New(sess)
req, _ := dynamo.PutItemRequest(&dynamodb.PutItemInput{
  TableName: aws.String(os.Getenv("TABLE_NAME")),
  Item: map[string]*dynamodb.AttributeValue{
    "ID": &dynamodb.AttributeValue{
      S: aws.String(movie.ID),
    },
    "Name": &dynamodb.AttributeValue{
      S: aws.String(movie.Name),
    },
    "Cover": &dynamodb.AttributeValue{
      S: aws.String(movie.Cover),
    },
    "Description": &dynamodb.AttributeValue{
      S: aws.String(movie.Description),
    },
  },
})
err = req.Send()
if err != nil {
  log.Fatal(err)
}
```

现在我们的函数处理程序已定义，将其部署到 AWS Lambda，并通过将 URL 作为输入参数进行测试。结果，电影信息将以 JSON 格式显示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/23b29884-ec6a-473c-9fa0-34549d4de49e.png)

如果您将浏览器指向前几章构建的前端，新电影应该是页面上列出的电影之一：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/62cf19ea-b235-4dc3-a88b-4c286cfdf3a9.png)

现在我们的 Lambda 函数正在按预期工作；让我们为下游服务添加跟踪调用。首先，配置 X-Ray 并使用`ctxhttp.Get`方法将`GET`调用作为子段进行检测：

```go
xray.Configure(xray.Config{
  LogLevel: "info",
  ServiceVersion: "1.2.3",
})

// Get html page
res, err := ctxhttp.Get(ctx, xray.Client(nil), url)
if err != nil {
  log.Fatal(err)
}
defer res.Body.Close()
```

接下来，在解析逻辑周围创建一个子段。子段称为`Parsing`，并且使用`AddMetaData`方法记录有关子段的其他信息以进行故障排除：

```go
xray.Capture(ctx, "Parsing", func(ctx1 context.Context) error {
  doc, err := goquery.NewDocumentFromReader(res.Body)
  if err != nil {
    return err
  }

  title := doc.Find(".header .title span a h2").Text()
  description := doc.Find(".overview p").Text()
  cover, _ := doc.Find(".poster .image_content img").Attr("src")

  movie := Movie{
    ID: uuid.Must(uuid.NewV4()).String(),
    Name: title,
    Description: description,
    Cover: cover,
  }

  xray.AddMetadata(ctx1, "movie.title", title)
  xray.AddMetadata(ctx1, "movie.description", description)
  xray.AddMetadata(ctx1, "movie.cover", cover)

  return nil
})
```

最后，使用`xray.AWS()`调用包装 DynamoDB 客户端：

```go
sess := session.Must(session.NewSession())
dynamo := dynamodb.New(sess)
xray.AWS(dynamo.Client)
```

结果，`ParseMovies` Lambda 函数的以下子段将出现在跟踪中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ddbf2885-9baa-4f68-89ca-bd4d81657c3b.png)

如果单击“子段”-“解析”选项卡上的“元数据”，将显示电影属性如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bb70f98a-383f-4617-bf1d-2c99c5bedc80.png)

在服务映射上，将显示对 DynamoDB 的下游调用和出站 HTTP 调用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8f29cc75-e040-4644-82c6-3e7fb011e2ee.png)

到目前为止，您应该清楚如何轻松排除性能瓶颈、延迟峰值和其他影响基于 Lambda 的应用程序性能的问题。

当您跟踪 Lambda 函数时，X-Ray 守护程序将自动在 Lambda 环境中运行，收集跟踪数据并将其发送到 X-Ray。如果您想在将函数部署到 Lambda 之前测试函数，可以在本地运行 X-Ray 守护程序。安装指南可以在这里找到：[`docs.aws.amazon.com/xray/latest/devguide/xray-daemon-local.html`](https://docs.aws.amazon.com/xray/latest/devguide/xray-daemon-local.html)。

# 摘要

在本章中，您学习了如何使用 AWS CloudWatch 指标实时监控 Lambda 函数。您还学习了如何发布自定义指标，并使用警报和报告检测问题。此外，我们还介绍了如何将函数的代码日志流式传输到 CloudWatch。最后，我们看到了如何使用 AWS X-Ray 进行调试，如何跟踪上游和下游调用，以及如何在 Golang 中将 X-Ray SDK 与 Lambda 集成。

在下一章中，您将学习如何保护您的无服务器应用程序。


# 第十二章：保护您的无服务器应用程序

AWS Lambda 是终极的按需付费云计算服务。客户只需将他们的 Lambda 函数代码上传到云端，它就可以运行，而无需保护或修补底层基础设施。然而，根据 AWS 的共享责任模型，您仍然负责保护您的 Lambda 函数代码。本章专门讨论在 AWS Lambda 中可以遵循的最佳实践和建议，以使应用程序根据 AWS Well-Architected Framework 具有弹性和安全性。本章将涵盖以下主题：

+   身份验证和用户控制访问

+   加密环境变量

+   使用 CloudTrail 记录 AWS Lambda API 调用

+   扫描依赖项的漏洞

# 技术要求

为了遵循本章，您可以遵循 API Gateway 设置章节，或者基于 Lambda 和 API Gateway 的无服务器 RESTful API。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 身份验证和用户控制访问

到目前为止，我们构建的无服务器应用程序运行良好，并向公众开放。只要有 API Gateway 调用 URL，任何人都可以调用 Lambda 函数。幸运的是，AWS 提供了一个名为 Cognito 的托管服务。

**Amazon Cognito**是一个规模化的身份验证提供程序和管理服务，允许您轻松地向您的应用程序添加用户注册和登录。用户存储在一个可扩展的目录中，称为用户池。在即将到来的部分中，Amazon Cognito 将用于在允许他们请求 RESTful API 之前对用户进行身份验证。

要开始，请在 Amazon Cognito 中创建一个新的用户池并为其命名：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d64b1112-ed81-4cf4-bd8f-0395d33baa5e.png)

单击“审阅默认值”选项以使用默认设置创建池：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9a950ec8-a55f-42ae-80fe-bb7c1341db96.png)

从导航窗格中单击“属性”，并在“电子邮件地址或电话号码”下的“允许电子邮件地址”选项中选中以允许用户使用电子邮件地址登录：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/61b2d18f-bac9-4141-93d8-4598440cedaf.png)

返回到“审阅”并单击“创建池”。创建过程结束时应显示成功消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8d7b4995-faf5-43ad-b16b-5adad82721cf.png)

创建第一个用户池后，从“常规设置”下的应用程序客户端中注册您的无服务器 API，并选择“添加应用程序客户端”。给应用程序命名，并取消“生成客户端密钥”选项如下：身份验证将在客户端上完成。因此，出于安全目的，客户端密钥不应传递到 URL 上：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c7345bb0-aef1-47ca-b498-00796ba6a459.png)

选择“创建应用程序客户端”以注册应用程序，并将**应用程序客户端 ID**复制到剪贴板：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8ae8223e-3303-4afc-abea-a50732e92be3.png)

现在用户池已创建，我们可以配置 API Gateway 以在授予对 Lambda 函数的访问之前验证来自成功用户池身份验证的访问令牌。

# 保护 API 访问

要开始保护 API 访问，请转到 API Gateway 控制台，选择我们在前几章中构建的 RESTful API，并从导航栏中单击“授权者”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2bd40386-76ce-436d-9635-01efe30a58a9.png)

单击“创建新的授权者”按钮，然后选择 Cognito。然后，选择我们之前创建的用户池，并将令牌源字段设置为`Authorization`。这定义了包含 API 调用者身份令牌的传入请求标头的名称为`Authorization`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4019bf3f-c338-4cd7-8755-673abdce6987.png)

填写完表单后，单击“创建”以将 Cognito 用户池与 API Gateway 集成：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/dcd77acd-3df6-4ac7-9fab-0ce42b730c35.png)

现在，您可以保护所有端点，例如，为了保护负责列出所有电影的端点。点击`/movies`资源下的相应`GET`方法：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0e5002c8-6700-4773-9105-3e873cca9342.png)

点击 Method Request 框，然后点击 Authorization，并选择我们之前创建的用户池：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/76a3b295-45d7-44dd-ae21-d01da1d28f3c.png)

将 OAuth Scopes 选项保留为`None`，并为其余方法重复上述过程以保护它们：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8a5148dc-b017-4b4e-b5ad-bc63e7b3672c.png)

完成后，重新部署 API，并将浏览器指向 API Gateway 调用 URL：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ec588566-1148-4fab-bd68-c938c9ed5710.png)

这次，端点是受保护的，需要进行身份验证。您可以通过检查我们之前构建的前端来确认行为。如果检查网络请求，API Gateway 请求应返回 401 未经授权错误：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8dbb072f-7e1b-4e50-b8e5-877f150e006b.png)

为了修复此错误，我们需要更新客户端（Web 应用程序）执行以下操作：

+   使用 Cognito JavaScript SDK 登录用户池

+   从用户池中获取已登录用户的身份令牌

+   在 API Gateway 请求的 Authorization 标头中包含身份令牌

返回的身份令牌具有 1 小时的过期日期。一旦过期，您需要使用刷新令牌来刷新会话。

# 使用 AWS Cognito 进行用户管理

在客户端进行更改之前，我们需要在 Amazon Cognito 中创建一个测试用户。为此，您可以使用 AWS 管理控制台，也可以使用 AWS Golang SDK 以编程方式完成。

# 通过 AWS 管理控制台设置测试用户

点击用户和组，然后点击创建用户按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6166182e-436c-4ee7-a251-0701a396d16b.png)

设置用户名和密码。如果要收到确认电子邮件，可以取消选中“标记电子邮件为已验证？”框：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d936b90b-04b4-46ab-a506-65b1bba95a25.png)

# 使用 Cognito Golang SDK 进行设置

创建一个名为`main.go`的文件，内容如下。该代码使用`cognitoidentityprovider`包中的`SignUpRequest`方法来创建一个新用户。作为参数，它接受一个包含客户端 ID、用户名和密码的结构体：

```go
package main

import (
  "log"
  "os"

  "github.com/aws/aws-sdk-go-v2/aws/external"
  "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
  "github.com/aws/aws-sdk-go/aws"
)

func main() {
  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    log.Fatal(err)
  }

  cognito := cognitoidentityprovider.New(cfg)
  req := cognito.SignUpRequest(&cognitoidentityprovider.SignUpInput{
    ClientId: aws.String(os.Getenv("COGNITO_CLIENT_ID")),
    Username: aws.String("EMAIL"),
    Password: aws.String("PASSWORD"),
  })
  _, err = req.Send()
  if err != nil {
    log.Fatal(err)
  }
}
```

使用`go run main.go`命令运行上述命令。您将收到一封带有临时密码的电子邮件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b30d2818-cda2-4dd0-8d2c-51b41b1adf88.png)

注册后，用户必须通过输入通过电子邮件发送的代码来确认注册。要确认注册过程，必须收集用户收到的代码并使用如下方式：

```go
cognito := cognitoidentityprovider.New(cfg)
req := cognito.ConfirmSignUpRequest(&cognitoidentityprovider.ConfirmSignUpInput{
  ClientId: aws.String(os.Getenv("COGNITO_CLIENT_ID")),
  Username: aws.String("EMAIL"),
  ConfirmationCode: aws.String("CONFIRMATION_CODE"),
})
_, err = req.Send()
if err != nil {
  log.Fatal(err)
}
```

现在 Cognito 用户池中已创建了一个用户，我们准备更新客户端。首先创建一个登录表单如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bfb6749b-38ca-4334-84f9-4feacb9576ac.png)

接下来，使用 Node.js 包管理器安装 Cognito SDK for Javascript。该软件包包含与 Cognito 交互所需的 Angular 模块和提供程序：

```go
npm install --save amazon-cognito-identity-js
```

此外，我们还需要创建一个带有`auth`方法的 Angular 服务，该方法通过提供`UserPoolId`对象和`ClientId`创建一个`CognitoUserPool`对象，根据参数中给定的用户名和密码对用户进行身份验证。如果登录成功，将调用`onSuccess`回调。如果登录失败，将调用`onFailure`回调：

```go
import { Injectable } from '@angular/core';
import { CognitoUserPool, CognitoUser, AuthenticationDetails} from 'amazon-cognito-identity-js';
import { environment } from '../../environments/environment';

@Injectable()
export class CognitoService {

  public static CONFIG = {
    UserPoolId: environment.userPoolId,
    ClientId: environment.clientId
  }

  auth(username, password, callback){
    let user = new CognitoUser({
      Username: username,
      Pool: this.getUserPool()
    })

    let authDetails = new AuthenticationDetails({
      Username: username,
      Password: password
    })

    user.authenticateUser(authDetails, {
      onSuccess: res => {
        callback(null, res.getIdToken().getJwtToken())
      },
      onFailure: err => {
        callback(err, null)
      }
    })
  }

  getUserPool() {
    return new CognitoUserPool(CognitoService.CONFIG);
  }

  getCurrentUser() {
    return this.getUserPool().getCurrentUser();
  }

}
```

每次单击登录按钮时都会调用`auth`方法。如果用户输入了正确的凭据，将会与 Amazon Cognito 服务建立用户会话，并将用户身份令牌保存在浏览器的本地存储中。如果输入了错误的凭据，将向用户显示错误消息：

```go
signin(username, password){
    this.cognitoService.auth(username, password, (err, token) => {
      if(err){
        this.loginError = true
      }else{
        this.loginError = false
        this.storage.set("COGNITO_TOKEN", token)
        this.loginModal.close()
      }
    })
  }
```

最后，`MoviesAPI`服务应更新以在每个 API Gateway 请求调用的`Authorization`头中包含用户身份令牌（称为 JWT 令牌 - [`docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-id-token`](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-id-token)）。

```go
@Injectable()
export class MoviesApiService {

  constructor(private http: Http,
    @Inject(LOCAL_STORAGE) private storage: WebStorageService) {}

    findAll() {
      return this.http
          .get(environment.api, {
              headers: this.getHeaders()
          })
          .map(res => {
              return res.json()
          })
    }

    getHeaders() {
      let headers = new Headers()
      headers.append('Authorization', this.storage.get("COGNITO_TOKEN"))
      return headers
    }

}
```

先前的代码示例已经在 Angular 5 中进行了测试。此外，请确保根据自己的 Web 框架采用代码。

要测试它，请返回浏览器。登录表单应该弹出；使用我们之前创建的用户凭据填写字段。然后，单击“登录”按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/efb79861-ecf2-42da-ab30-295bd6e804b7.png)

用户身份将被返回，并且将使用请求头中包含的令牌调用 RESTful API。 API 网关将验证令牌，并将调用`FindAllMovies` Lambda 函数，该函数将从 DynamoDB 表返回电影：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4e06f787-ffe7-4840-a6ec-b98f993d2935.png)

对于 Web 开发人员，Cognito 的`getSession`方法可用于从本地存储中检索当前用户，因为 JavaScript SDK 配置为在正确进行身份验证后自动存储令牌，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fd735a23-f2b8-46d2-a44a-d643408938c3.png)

总之，到目前为止，我们已经完成了以下工作：

+   构建了多个 Lambda 函数来管理电影存储

+   在 DynamoDB 表中管理 Lambda 数据持久性

+   通过 API Gateway 公开这些 Lambda 函数

+   在 S3 中构建用于测试构建堆栈的 Web 客户端

+   通过 CloudFront 分发加速 Web 客户端资产

+   在 Route 53 中设置自定义域名

+   使用 AWS Cognito 保护 API

以下模式说明了我们迄今为止构建的无服务器架构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b2e88681-4a54-4ac7-b555-14d0cfb75711.png)

Amazon Cognito 可以配置多个身份提供者，如 Facebook、Twitter、Google 或开发人员认证的身份。

# 加密环境变量

在之前的章节中，我们看到如何使用 AWS Lambda 的环境变量动态传递数据到函数代码，而不更改任何代码。根据**Twelve Factor App**方法论（[`12factor.net/`](https://12factor.net/)），您应该始终将配置与代码分开，以避免将敏感凭据检查到存储库，并能够定义 Lambda 函数的多个发布版本（暂存、生产和沙盒）具有相同的源代码。此外，环境变量可用于根据不同设置更改函数行为**（A/B 测试）**。

如果要在多个 Lambda 函数之间共享秘密，可以使用 AWS 的**系统管理器参数存储**。

以下示例说明了如何使用环境变量将 MySQL 凭据传递给函数的代码：

```go
func handler() error {
  MYSQL_USERNAME := os.Getenv("MYSQL_USERNAME")
  MYSQL_PASSWORD := os.Getenv("MYSQL_PASSWORD")
  MYSQL_DATABASE := os.Getenv("MYSQL_DATABASE")
  MYSQL_PORT := os.Getenv("MYSQL_PORT")
  MYSQL_HOST := os.Getenv("MYSQL_HOST")

  uri := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", MYSQL_USERNAME, MYSQL_PASSWORD, MYSQL_HOST, MYSQL_PORT, MYSQL_DATABASE)
  db, err := sql.Open("mysql", uri)
  if err != nil {
    return err
  }
  defer db.Close()

  _, err = db.Query(`CREATE TABLE IF NOT EXISTS movies(id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50) NOT NULL)`)
  if err != nil {
    return err
  }

  for _, movie := range []string{"Iron Man", "Thor", "Avengers", "Wonder Woman"} {
    _, err := db.Query("INSERT INTO movies(name) VALUES(?)", movie)
    if err != nil {
      return err
    }
  }

  movies, err := db.Query("SELECT id, name FROM movies")
  if err != nil {
    return err
  }

  for movies.Next() {
    var name string
    var id int
    err = movies.Scan(&id, &name)
    if err != nil {
      return err
    }

    log.Printf("ID=%d\tName=%s\n", id, name)
  }
  return nil
}
```

一旦函数部署到 AWS Lambda 并设置环境变量，就可以调用该函数。它将输出插入到数据库中的电影列表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f4cceb41-12f3-4215-bcb2-aa454bc017fa.png)

到目前为止，一切都很好。但是，数据库凭据是明文！

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d42646b1-597a-4f6c-8e0d-26919861d601.png)

幸运的是，AWS Lambda 在两个级别提供加密：在传输和静态时，使用 AWS 密钥管理服务。

# 数据静态加密

AWS Lambda 在部署函数时加密所有环境变量，并在调用函数时解密它们（即时）。

如果展开“加密配置”部分，您会注意到默认情况下，AWS Lambda 使用默认的 Lambda 服务密钥对环境变量进行加密。此密钥在您在特定区域创建 Lambda 函数时会自动创建：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bc5c3a85-f548-4bfa-9d00-378a07d81c00.png)

您可以通过导航到身份和访问管理控制台来更改密钥并使用自己的密钥。然后，单击“加密密钥”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0ef2e744-13c3-4ff3-bb73-476fbb48bfdc.png)

单击“创建密钥”按钮创建新的客户主密钥：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/563e4e62-d659-444a-9648-a648d6647c4a.png)

选择一个 IAM 角色和帐户来通过**密钥管理服务**（**KMS**）API 管理密钥。然后，选择您在创建 Lambda 函数时使用的 IAM 角色。这允许 Lambda 函数使用**客户主密钥**（**CMK**）并成功请求`encrypt`和`decrypt`方法：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/511f7fad-6191-4a7e-b796-0d12736c6f52.png)

创建密钥后，返回 Lambda 函数配置页面，并将密钥更改为您刚刚创建的密钥：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/cd032e44-5ae4-4b8d-afc8-95a89d0c8dc6.png)

现在，当存储在 Amazon 中时，AWS Lambda 将使用您自己的密钥加密环境变量。

# 数据传输加密

建议在部署函数之前对环境变量（敏感信息）进行加密。AWS Lambda 在控制台上提供了加密助手，使此过程易于遵循。

为了通过在传输中加密（使用之前使用的 KMS），您需要通过选中“启用传输加密的帮助程序”复选框来启用此功能：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/825da2fe-8377-41e5-9e31-c90e9ca4d171.png)

通过单击适当的加密按钮对`MYSQL_USERNAME`和`MYSQL_PASSWORD`进行加密：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/92e642a0-f265-43c3-9dc1-a732bdaf46e3.png)

凭据将被加密，并且您将在控制台中看到它们作为`CipherText`。接下来，您需要更新函数的处理程序，使用 KMS SDK 解密环境变量：

```go
var encryptedMysqlUsername string = os.Getenv("MYSQL_USERNAME")
var encryptedMysqlPassword string = os.Getenv("MYSQL_PASSWORD")
var mysqlDatabase string = os.Getenv("MYSQL_DATABASE")
var mysqlPort string = os.Getenv("MYSQL_PORT")
var mysqlHost string = os.Getenv("MYSQL_HOST")
var decryptedMysqlUsername, decryptedMysqlPassword string

func decrypt(encrypted string) (string, error) {
  kmsClient := kms.New(session.New())
  decodedBytes, err := base64.StdEncoding.DecodeString(encrypted)
  if err != nil {
    return "", err
  }
  input := &kms.DecryptInput{
    CiphertextBlob: decodedBytes,
  }
  response, err := kmsClient.Decrypt(input)
  if err != nil {
    return "", err
  }
  return string(response.Plaintext[:]), nil
}

func init() {
  decryptedMysqlUsername, _ = decrypt(encryptedMysqlUsername)
  decryptedMysqlPassword, _ = decrypt(encryptedMysqlPassword)
}

func handler() error {
  uri := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", decryptedMysqlUsername, decryptedMysqlPassword, mysqlHost, mysqlPort, mysqlDatabase)
  db, err := sql.Open("mysql", uri)
  if err != nil {
    return err
  }
  ...
}
```

如果您使用自己的 KMS 密钥，您需要授予附加到 Lambda 函数的执行角色（IAM 角色）`kms:Decrypt`权限。还要确保增加默认执行超时时间，以允许足够的时间完成函数的代码。

# 使用 CloudTrail 记录 AWS Lambda API 调用

捕获 Lambda 函数发出的所有调用对于审计、安全和合规性非常重要。它为您提供了与其交互的 AWS 服务的全局概览。利用此功能的一个服务是**CloudTrail**。

CloudTrail 记录了 Lambda 函数发出的 API 调用。这很简单易用。您只需要从 AWS 管理控制台导航到 CloudTrail，并按事件源筛选事件，事件源应为`lambda.amazonaws.com`。

在那里，您应该看到每个 Lambda 函数发出的所有调用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3076bb70-b308-4002-9d3e-efed9619dd94.png)

除了公开事件历史记录，您还可以在每个 AWS 区域中创建一个跟踪，将 Lambda 函数的事件记录在单个 S3 存储桶中，然后使用**ELK**（Elasticsearch、Logstash 和 Kibana）堆栈实现日志分析管道，如下所示处理您的日志：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/34a908ea-63f5-4043-8909-39a441edfa46.png)

最后，您可以创建交互式和动态小部件，构建 Kibana 中的仪表板，以查看 Lambda 函数事件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8d853e00-8238-48c2-b162-2cb92cddfab2.png)

# 为您的依赖项进行漏洞扫描

由于大多数 Lambda 函数代码包含多个第三方 Go 依赖项（记住`go get`命令），因此对所有这些依赖项进行审计非常重要。因此，漏洞扫描您的 Golang 依赖项应该成为您的 CI/CD 的一部分。您必须使用第三方工具（如**S****nyk** ([`snyk.io/`](https://snyk.io/)）自动化安全分析，以持续扫描依赖项中已知的安全漏洞。以下截图描述了您可能选择为 Lambda 函数实施的完整端到端部署过程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/451dcc6d-173a-4db9-b34d-e12820aee7f2.png)

通过将漏洞扫描纳入工作流程，您将能够发现并修复软件包中已知的漏洞，这些漏洞可能导致数据丢失、服务中断和对敏感信息的未经授权访问。

此外，应用程序最佳实践仍然适用于无服务器架构，如代码审查和 git 分支等软件工程实践，以及安全性安全检查，如输入验证或净化，以避免 SQL 注入。

# 摘要

在本章中，您学习了一些构建基于 Lambda 函数的安全无服务器应用程序的最佳实践和建议。我们介绍了 Amazon Cognito 如何作为身份验证提供程序，并如何与 API Gateway 集成以保护 API 端点。然后，我们看了 Lambda 函数代码实践，如使用 AWS KMS 加密敏感数据和输入验证。此外，其他实践也可能非常有用和救命，例如应用配额和节流以防止消费者消耗所有 Lambda 函数容量，以及每个函数使用一个 IAM 角色以利用最小特权原则。

在下一章中，我们将讨论 Lambda 定价模型以及如何根据预期负载估算价格。

# 问题

1.  将用户池中的用户与身份池集成，以允许用户使用其 Facebook 帐户登录。

1.  将用户池中的用户与身份池集成，以允许用户使用其 Twitter 帐户登录。

1.  将用户池中的用户与身份池集成，以允许用户使用其 Google 帐户登录。

1.  实现一个表单，允许用户在 Web 应用程序上创建帐户，以便他们能够登录。

1.  为未经身份验证的用户实现忘记密码流程。


# 第十三章：设计成本效益的应用程序

在本章中，我们将讨论 AWS Lambda 的定价模型，并学习如何根据预期负载估算这个价格。我们还将介绍一些优化和降低无服务器应用成本的技巧，同时保持弹性和可用性。本章将涵盖以下主题：

+   Lambda 定价模型

+   最佳内存大小

+   代码优化

+   Lambda 成本和内存跟踪

# Lambda 定价模型

AWS Lambda 改变了运维团队配置和管理组织基础设施的方式。客户现在可以在不担心底层基础设施的情况下运行他们的代码，同时支付低廉的价格。每月的前 100 万次请求是免费的，之后每 100 万次请求收费 0.20 美元，因此您可能会无限期地使用 Lambda 的免费套餐。然而，如果您不额外关注函数的资源使用和代码优化，密集的使用情况和大量的工作负载应用可能会不必要地花费您数千美元。

为了控制 Lambda 成本，您必须了解 Lambda 定价模型的工作原理。有三个因素决定了函数的成本：

+   **执行次数**：调用次数；每次请求支付 0.0000002 美元。

+   **分配的内存**：为函数分配的 RAM 量（范围在 128 MB 和 3,008 MB 之间）。

+   **执行时间**：持续时间是从代码开始执行到返回响应或其他终止的时间。时间向最接近的 100 毫秒取整（Lambda 按 100 毫秒的增量计费），并且您可以设置的最大超时时间为 5 分钟。

+   **数据传输**：如果您的 Lambda 函数发起外部数据传输，将按照 EC2 数据传输速率收费（[`aws.amazon.com/ec2/pricing`](https://aws.amazon.com/ec2/pricing)）。

# Lambda 成本计算器

现在您已经熟悉了定价模型，让我们看看如何提前计算 Lambda 函数的成本。

在前几章中，我们为`FindAllMovies`函数分配了 128 MB 的内存，并将执行超时设置为 3 秒。假设函数每秒执行 10 次（一个月内执行 2500 万次）。您的费用将如下计算：

+   **每月计算费用**：每月计算价格为每 GB/s 0.00001667 美元，免费套餐提供 400,000 GB/s。总计算（秒）=25 百万*（1 秒）=25,000,000 秒。总计算（GB/s）=25,000,000*128 MB/1,024=3,125,000 GB/s。

总计算-免费套餐计算=每月应付费计算 GB/s

3,125,000 GB/s - 400,000 免费套餐 GB/s = 2,725,000 GB/s

每月计算费用=2,725,000 GB/s*$0.00001667=$45.42

+   **每月请求费用**：每月请求价格为每 100 万次请求 0.20 美元，免费套餐提供每月 100 万次请求。

总请求次数-免费套餐请求=每月应付费请求

25 百万次请求-1 百万免费套餐请求=24 百万次每月应付费请求

每月请求费用=24 百万*$0.2/百万=$4.8

因此，总月费用是计算和请求费用的总和，如下所示：

总费用=计算费用+请求费用=45.24 美元+4.8 美元=50.04 美元

# 最佳内存大小

正如我们在前一节中看到的，分配的 RAM 数量会影响计费。此外，它还会影响函数接收的 CPU 和网络带宽的数量。因此，您需要选择最佳的内存大小。为了找到函数的价格和性能的正确平衡和最佳水平，您必须使用不同的内存设置测试您的 Lambda 函数，并分析函数实际使用的内存。幸运的是，AWS Lambda 会在关联的日志组中写入日志条目。日志包含每个请求的函数分配和使用的内存量。以下是日志输出的示例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/1b845000-05a4-4f9e-a8c3-3ecd17d8b512.png)

通过比较内存大小和最大内存使用字段，您可以确定您的函数是否需要更多内存，或者您是否过度配置了函数的内存大小。如果您的函数需要更多内存，您可以随时从“基本设置”部分为其提供更多内存，具体如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bdbb004a-7775-4eea-ad7a-21666e517aa3.png)

点击“保存”，然后再次调用函数。在日志输出中，您会注意到内存大小会影响执行时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d5662e8d-fb13-47ff-b4c9-0ebdbfdf92d7.png)

增加函数内存设置将提供显著的性能提升。随着 Lambda 中内存设置的增加，成本将线性增加。同样，减少函数内存设置可能有助于降低成本，但这也会增加执行时间，并且在最坏的情况下可能导致超时或内存超限错误。

将最小内存设置分配给 Lambda 函数并不总是会提供最低总成本。由于内存不足，函数可能会失败和超时。此外，完成所需的时间可能会更长。因此，您将支付更多费用。

# 代码优化

在前面的部分中，我们看到了如何使用不同的内存设置在规模上测试函数会导致分配更多的 CPU 容量，这可能会影响 Lambda 函数的性能和成本。然而，在优化资源使用之前，您需要先优化函数的代码，以帮助减少需要执行的内存和 CPU 的数量。与传统应用程序相反，AWS Lambda 会为您管理和修补基础架构，这使开发人员可以专注于编写高质量、高效和世界级的代码，以便快速执行。

为函数分配更多资源可能会导致更快的执行，直到达到一定阈值，增加更多内存将不再提供更好的性能。

设计 AWS Lambda 函数时，要考虑以下几点，以便以成本效益的方式进行设计：

+   对于某些请求，可以使用热容器。有了这些知识，我们可以通过实施以下操作来改善 Lambda 函数的性能：

+   通过使用全局变量和单例模式，避免在每次调用时重新初始化变量。

+   保持数据库和 HTTP 连接的活动状态并重复使用，这些连接是在先前的调用期间建立的。在 Go 中，您可以使用 `init` 函数来设置所需的状态，并在加载函数处理程序时运行一次性计算。

+   设计您的架构为异步；解耦的组件可能需要更少的计算时间来完成其工作，而不是紧密耦合的组件。此外，避免花费 CPU 周期等待同步请求的响应。

+   使用监控和调试工具，如 AWS X-Ray，分析和排除性能瓶颈、延迟峰值和其他影响 Lambda 应用性能的问题。

+   使用并发预留来设置限制，以防止无限自动缩放、冷启动，并保护下游服务。您还可以通过在 Lambda 触发器和函数之间放置 **简单队列服务**（SQS）来限制执行次数，调整 Lambda 函数触发的频率。

# Lambda 成本和内存跟踪

在 AWS Lambda 中设计成本效益的无服务器应用的关键在于监控成本和资源使用情况。不幸的是，CloudWatch 并未提供有关资源使用或 Lambda 函数成本的开箱即用指标。幸运的是，对于每次执行，Lambda 函数都会将执行日志写入 CloudWatch，如下所示：

```go
REPORT RequestId: 147e72f8-5143-11e8-bba3-b5140c3dea53 Duration: 12.00 ms Billed Duration: 100 ms  Memory Size: 128 MB Max Memory Used: 21 MB 
```

前面的日志显示了给定请求分配和使用的内存。这些值可以通过简单的 CloudWatch 日志指标过滤器提取。此功能使您能够在日志中搜索特定关键字。

打开 AWS CloudWatch 控制台，并从导航窗格中选择“日志组”。接下来，搜索与您的 Lambda 函数关联的日志组。它的名称应该是：`/aws/lambda/FUNCTION_NAME`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8b313ac1-baaa-4996-94f5-ea1ac1f5704e.png)

接下来，点击“创建度量过滤器”按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/72633fb3-bd3c-49aa-873c-703c1beeabb4.png)

定义一个度量过滤器模式，解析以空格分隔的术语。度量过滤器模式必须指定以逗号分隔的名称字段，并用方括号括起整个模式，例如`[a,b,c]`。然后，点击“测试模式”以测试您的过滤器模式对日志中现有数据的结果。将打印以下记录：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6688061e-2169-4bd6-bea3-63ae62585a04.png)

如果您不知道自己有多少字段，可以使用方括号括起来的省略号：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e7294961-4c0c-4ea7-bffa-a8b4f0677295.png)

列`$13`将存储分配给函数的内存，`$18`表示实际使用的内存。接下来，点击“分配度量”以创建已分配内存的度量：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5e0d8104-b632-4f28-bc4f-5e7f8dc59dd7.png)

点击“创建过滤器”按钮保存。您现在应该看到新创建的过滤器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d0585e8c-c28b-4ae7-97e6-aa7019760560.png)

应用相同的步骤为内存使用创建另一个过滤器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2611714f-cc6d-4e29-906a-2dfe92ab57ed.png)

一旦定义了两个过滤器，请确保您的 Lambda 函数正在运行，并在函数填充新的 CloudWatch 指标值时等待几秒钟：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f83d8de0-1321-49f5-9792-2b5a75a4041c.png)

回到 CloudWatch，在我们之前创建的两个度量标准的基础上创建一个新的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ab2a597f-8820-46e2-a0f7-830434ab4c0c.png)

您还可以进一步进行，并创建一个几乎实时的 CloudWatch 警报，如果内存使用量超过某个阈值（例如，相对于您分配的内存的 80%）。此外，重要的是要关注函数的持续时间。您可以按照本节中描述的相同过程从 Lambda 执行日志中提取计费持续时间，并根据提取的值设置警报，以便在函数完成所需时间可疑地长时收到通知。

# 摘要

使用 AWS Lambda 非常简单-您不必预配和管理任何基础设施，并且在几秒钟内就可以轻松运行一些有用的东西。此外，AWS Lambda 相对于 EC2 的一个巨大优势是您不必为闲置资源付费。这非常强大，但也是 Lambda 最大的风险之一。在开发过程中忘记成本是非常常见的，但一旦您开始在生产中运行大量工作负载和多个函数，成本可能会很高。因此，在这成为问题之前，跟踪 Lambda 成本和使用情况非常重要。

最后一章将介绍**基础设施即代码**（IaC）的概念，以帮助您以自动化的方式设计和部署 N 层无服务器应用程序，以避免人为错误和可重复的任务。


# 第十四章：基础设施即代码

典型的基于 Lambda 的应用程序由多个函数组成，这些函数由事件触发，例如 S3 存储桶中的新对象，传入的 HTTP 请求或新的 SQS 消息。这些函数可以独立存在，也可以利用其他资源，例如 DynamoDB 表，Amazon S3 存储桶和其他 Lambda 函数。到目前为止，我们已经看到如何从 AWS 管理控制台或使用 AWS CLI 创建这些资源。在实际情况下，您希望花费更少的时间来提供所需的资源，并更多地专注于应用程序逻辑。最终，这就是无服务器的方法。

这最后一章将介绍基础设施即代码的概念，以帮助您以自动化的方式设计和部署 N-Tier 无服务器应用程序，以避免人为错误和可重复的任务。

# 技术要求

本书假设您对 AWS 无服务器应用程序模型有一些基本了解。如果您对 SAM 本身还不熟悉，请参阅第一章，*无服务器 Go*，直到第十章，*测试您的无服务器应用程序*。您将获得一个逐步指南，了解如何开始使用 SAM。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 使用 Terraform 部署 AWS Lambda

**Terraform**是 HashiCorp 构建的开源自动化工具。它用于通过声明性配置文件创建，管理和更新基础设施资源。它支持以下提供程序：

+   **云提供商**：AWS，Azure，Oracle Cloud 和 GCP

+   **基础设施软件**：

+   **Consul**：这是一个分布式，高可用的服务发现和配置系统。

+   **Docker**：这是一个旨在通过使用容器更轻松地创建，部署和运行应用程序的工具。

+   **Nomad**：这是一个易于使用的企业级集群调度程序。

+   **Vault**：这是一个提供安全，可靠的存储和分发机密的工具。

+   其他**SaaS**和**PaaS**

Terraform 不是配置管理工具（如 Ansible，Chef 和 Puppet＆Salt）。它是用来生成和销毁基础设施的，而配置管理工具用于在现有基础设施上安装东西。但是，Terraform 可以进行一些配置（[`www.terraform.io/docs/provisioners/index.html`](https://www.terraform.io/docs/provisioners/index.html)）。

这个指南将向您展示如何使用 Terraform 部署 AWS Lambda，因此您需要安装 Terraform。您可以找到适合您系统的包并下载它（[`www.terraform.io/downloads.html`](https://www.terraform.io/downloads.html)）。下载后，请确保`terraform`二进制文件在`PATH`变量中可用。配置您的凭据，以便 Terraform 能够代表您进行操作。以下是提供身份验证凭据的四种方法：

+   通过提供商直接提供 AWS `access_key`和`secret_key`。

+   AWS 环境变量。

+   共享凭据文件。

+   EC2 IAM 角色。

如果您遵循了第二章，*开始使用 AWS Lambda*，您应该已经安装并配置了 AWS CLI。因此，您无需采取任何行动。

# 创建 Lambda 函数

要开始创建 Lambda 函数，请按照以下步骤进行：

1.  使用以下结构创建一个新项目：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fd50ed4b-1380-47ea-b8cf-f65b91f15a5d.png)

1.  我们将使用最简单的 Hello world 示例。`function`文件夹包含一个基于 Go 的 Lambda 函数，显示一个简单的消息：

```go
package main

import "github.com/aws/aws-lambda-go/lambda"

func handler() (string, error) {
  return "First Lambda function with Terraform", nil
}
func main() {
  lambda.Start(handler)
}
```

1.  您可以构建基于 Linux 的二进制文件，并使用以下命令生成`deployment`包：

```go
GOOS=linux go build -o main main.go
zip deployment.zip main
```

1.  现在，函数代码已经定义，让我们使用 Terraform 创建我们的第一个 Lambda 函数。将以下内容复制到`main.tf`文件中：

```go
provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "role" {
  name = "PushCloudWatchLogsRole"
  assume_role_policy = "${file("assume-role-policy.json")}"
}

resource "aws_iam_policy" "policy" {
  name = "PushCloudWatchLogsPolicy"
  policy = "${file("policy.json")}"
}

resource "aws_iam_policy_attachment" "profile" {
  name = "cloudwatch-lambda-attachment"
  roles = ["${aws_iam_role.role.name}"]
  policy_arn = "${aws_iam_policy.policy.arn}"
}

resource "aws_lambda_function" "demo" {
  filename = "function/deployment.zip"
  function_name = "HelloWorld"
  role = "${aws_iam_role.role.arn}"
  handler = "main"
  runtime = "go1.x"
}
```

1.  这告诉 Terraform 我们将使用 AWS 提供程序，并默认为创建我们的资源使用`us-east-1`区域：

+   **IAM 角色**是在执行期间 Lambda 函数将要承担的执行角色。它定义了我们的 Lambda 函数可以访问的资源：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
```

+   **IAM 策略**是授予我们的 Lambda 函数权限的权限列表，以将其日志流式传输到 CloudWatch。以下策略将附加到 IAM 角色：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "1",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:CreateLogGroup",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

+   **Lambda 函数**是一个基于 Go 的 Lambda 函数。部署包可以直接指定为本地文件（使用`filename`属性）或通过 Amazon S3 存储桶。有关如何将 Lambda 函数部署到 AWS 的详细信息，请参阅第六章，*部署您的无服务器应用*。

1.  在终端上运行`terraform init`命令以下载和安装 AWS 提供程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/793cedcf-efd2-4df4-884b-2dcff8c945b3.png)

1.  使用`terraform plan`命令创建执行计划（模拟运行）。它会提前显示将要创建的内容，这对于调试和确保您没有做错任何事情非常有用，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ff77d443-7739-47c1-bf80-f60ebccac982.png)

1.  在将其部署到 AWS 之前，您将能够检查 Terraform 的执行计划。准备好后，通过发出以下命令应用更改：

```go
terraform apply
```

1.  确认配置，输入`yes`。将显示以下输出（为简洁起见，某些部分已被裁剪）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d87027bf-45ba-4bc0-b2bd-9c3134baadb6.png)

确保用于执行这些命令的 IAM 用户具有执行 IAM 和 Lambda 操作的权限。

1.  如果返回 AWS Lambda 控制台，应该创建一个新的 Lambda 函数。如果尝试调用它，应返回预期的消息，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f704065d-9e21-4134-93c4-4191896b72e4.png)

1.  到目前为止，我们在模板文件中定义了 AWS 区域和函数名称。但是，我们使用基础架构即代码工具的原因之一是可用性和自动化。因此，您应始终使用变量并避免硬编码值。幸运的是，Terraform 允许您定义自己的变量。为此，请创建一个`variables.tf`文件，如下所示：

```go
variable "aws_region" {
  default = "us-east-1"
  description = "AWS region"
}

variable "lambda_function_name" {
  default = "DemoFunction"
  description = "Lambda function's name"
}
```

1.  更新`main.tf`以使用变量而不是硬编码的值。注意使用`${var.variable_name}`关键字：

```go
provider "aws" {
  region = "${var.aws_region}"
}

resource "aws_lambda_function" "demo" {
  filename = "function/deployment.zip"
  function_name = "${var.lambda_function_name}"
  role = "${aws_iam_role.role.arn}"
  handler = "main"
  runtime = "go1.x"
}
```

1.  函数按预期工作后，使用 Terraform 创建我们迄今为止构建的无服务器 API。

1.  在一个新目录中，创建一个名为`main.tf`的文件，其中包含以下配置：

```go
resource "aws_iam_role" "role" {
 name = "FindAllMoviesRole"
 assume_role_policy = "${file("assume-role-policy.json")}"
}

resource "aws_iam_policy" "cloudwatch_policy" {
 name = "PushCloudWatchLogsPolicy"
 policy = "${file("cloudwatch-policy.json")}"
}

resource "aws_iam_policy" "dynamodb_policy" {
 name = "ScanDynamoDBPolicy"
 policy = "${file("dynamodb-policy.json")}"
}

resource "aws_iam_policy_attachment" "cloudwatch-attachment" {
 name = "cloudwatch-lambda-attchment"
 roles = ["${aws_iam_role.role.name}"]
 policy_arn = "${aws_iam_policy.cloudwatch_policy.arn}"
}

resource "aws_iam_policy_attachment" "dynamodb-attachment" {
 name = "dynamodb-lambda-attchment"
 roles = ["${aws_iam_role.role.name}"]
 policy_arn = "${aws_iam_policy.dynamodb_policy.arn}"
}
```

1.  上述代码片段创建了一个具有扫描 DynamoDB 表和将日志条目写入 CloudWatch 权限的 IAM 角色。使用 DynamoDB 表名作为环境变量配置一个基于 Go 的 Lambda 函数：

```go
resource "aws_lambda_function" "findall" {
  function_name = "FindAllMovies"
  handler = "main"
  filename = "function/deployment.zip"
  runtime = "go1.x"
  role = "${aws_iam_role.role.arn}"

  environment {
    variables {
      TABLE_NAME = "movies"
    }
  }
}
```

# 设置 DynamoDB 表

接下来，我们必须设置 DynamoDB 表。执行以下步骤：

1.  为表的分区键创建一个 DynamoDB 表：

```go
resource "aws_dynamodb_table" "movies" {
  name = "movies"
  read_capacity = 5
  write_capacity = 5
  hash_key = "ID"

  attribute {
      name = "ID"
      type = "S"
  }
}
```

1.  使用新项目初始化`movies`表：

```go
resource "aws_dynamodb_table_item" "items" {
  table_name = "${aws_dynamodb_table.movies.name}"
  hash_key = "${aws_dynamodb_table.movies.hash_key}"
  item = "${file("movie.json")}"
}
```

1.  项目属性在`movie.json`文件中定义：

```go
{
  "ID": {"S": "1"},
  "Name": {"S": "Ant-Man and the Wasp"},
  "Description": {"S": "A Marvel's movie"},
  "Cover": {"S": http://COVER_URL.jpg"}
}
```

# 配置 API Gateway

最后，我们需要通过 API Gateway 触发函数：

1.  在 REST API 上创建一个`movies`资源，并在其上公开一个`GET`方法。如果传入的请求与定义的资源匹配，它将调用之前定义的 Lambda 函数：

```go
resource "aws_api_gateway_rest_api" "api" {
  name = "MoviesAPI"
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  parent_id = "${aws_api_gateway_rest_api.api.root_resource_id}"
  path_part = "movies"
}

resource "aws_api_gateway_method" "proxy" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_resource.proxy.id}"
  http_method = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_method.proxy.resource_id}"
  http_method = "${aws_api_gateway_method.proxy.http_method}"

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = "${aws_lambda_function.findall.invoke_arn}"
}
```

1.  发出以下命令安装 AWS 插件，生成执行计划并应用更改：

```go
terraform init
terraform plan
terraform apply
```

1.  创建整个基础架构应该只需要几秒钟。创建步骤完成后，Lambda 函数应该已创建并正确配置，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d1897e2e-f42c-4e22-85a4-81d1b9f222fe.png)

1.  API Gateway 也是一样，应该定义一个新的 REST API，其中`/movies`资源上有一个`GET`方法，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6f59c9fa-c19d-4738-8a0a-c26d9cc75ab8.png)

1.  在 DynamoDB 控制台中，应创建一个新表，并在下一个屏幕截图中显示一个电影项目：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7c0ef84f-bef8-42c4-b050-753afab85f38.png)

1.  为了调用我们的 API Gateway，我们需要部署它。创建一个部署阶段，让我们称之为`staging`：

```go
resource "aws_api_gateway_deployment" "staging" {
  depends_on = ["aws_api_gateway_integration.lambda"]

  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  stage_name = "staging"
}
```

1.  我们将使用 Terraform 的输出功能来公开 API URL；创建一个`outputs.tf`文件，内容如下：

```go
output "API Invocation URL" {
  value = "${aws_api_gateway_deployment.staging.invoke_url}"
}
```

1.  再次运行`terraform apply`以创建这些新对象，它将检测到更改并要求您确认它应该执行的操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/cf53db32-5b7b-4831-9695-d12ed0177c8e.png)

1.  API Gateway URL 将显示在输出部分；将其复制到剪贴板：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/681877fa-8271-4164-a912-a941b72f6142.png)

1.  如果您将您喜欢的浏览器指向 API 调用 URL，将显示错误消息，如下一张截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/5de0d7f6-45c5-4d7d-ae2f-1ab45692a4d4.png)

1.  我们将通过授予 API Gateway 调用 Lambda 函数的执行权限来解决这个问题。更新`main.tf`文件以创建`aws_lambda_permission`资源：

```go
resource "aws_lambda_permission" "apigw" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.findall.arn}"
  principal = "apigateway.amazonaws.com"

  source_arn = "${aws_api_gateway_deployment.staging.execution_arn}/*/*"
}
```

1.  使用`terraform apply`命令应用最新更改。在 Lambda 控制台上，API Gateway 触发器应该显示如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b8921922-962d-4e9b-a955-f2f4a7b66b09.png)

1.  在您喜欢的网络浏览器中加载输出中给出的 URL。如果一切正常，您将以 JSON 格式在 DynamoDB 表中看到存储的电影，如下一张截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7d8b3b18-2817-4eea-bde5-b2163cd7af3e.png)

Terraform 将基础设施的状态存储在状态文件（`.tfstate`）中。状态包含资源 ID 和所有资源属性。如果您使用 Terraform 创建 RDS 实例，则数据库凭据将以明文形式存储在状态文件中。因此，您应该将文件保存在远程后端，例如 S3 存储桶中。

# 清理

最后，要删除所有资源（Lambda 函数、IAM 角色、IAM 策略、DynamoDB 表和 API Gateway），您可以发出`terraform destroy`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a90beaea-d753-4a9b-8518-4142389ae9f7.png)

如果您想删除特定资源，可以使用`--target`选项，如下所示：`terraform destroy --target=RESOURCE_NAME`。操作将仅限于资源及其依赖项。

到目前为止，我们已经使用模板文件定义了 AWS Lambda 函数及其依赖关系。因此，我们可以像任何其他代码一样对其进行版本控制。我们使用和配置的整个无服务器基础设施被视为源代码，使我们能够在团队成员之间共享它，在其他 AWS 区域中复制它，并在失败时回滚。

# 使用 CloudFormation 部署 AWS Lambda

**AWS CloudFormation**是一种基础设施即代码工具，用于以声明方式指定资源。您可以在蓝图文档（模板）中对您希望 AWS 启动的所有资源进行建模，AWS 会为您创建定义的资源。因此，您花费更少的时间管理这些资源，更多的时间专注于在 AWS 中运行的应用程序。

Terraform 几乎涵盖了 AWS 的所有服务和功能，并支持第三方提供商（平台无关），而 CloudFormation 是 AWS 特定的（供应商锁定）。

您可以使用 AWS CloudFormation 来指定、部署和配置无服务器应用程序。您创建一个描述无服务器应用程序依赖关系的模板（Lambda 函数、DynamoDB 表、API Gateway、IAM 角色等），AWS CloudFormation 负责为您提供和配置这些资源。您不需要单独创建和配置 AWS 资源，并弄清楚什么依赖于什么。

在我们深入了解 CloudFormation 之前，我们需要了解模板结构：

+   **AWSTemplateFormatVersion**：CloudFormation 模板版本。

+   **Description**：模板的简要描述。

+   **Mappings**：键和相关值的映射，可用于指定条件参数值。

+   **Parameters**：运行时传递给模板的值。

+   **Resources**：AWS 资源及其属性（Lambda、DynamoDB、S3 等）。

+   **输出**：描述每当查看堆栈属性时返回的值。

了解 AWS CloudFormation 模板的不同部分后，您可以将它们放在一起，并在`template.yml`文件中定义一个最小模板，如下所示：

```go
AWSTemplateFormatVersion: "2010-09-09"
Description: "Simple Lambda Function"
Parameters:
  FunctionName:
    Description: "Function name"
    Type: "String"
    Default: "HelloWorld"
  BucketName:
    Description: "S3 Bucket name"
    Type: "String"
Resources:
  ExecutionRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: "Allow"
            Principal:
              Service:
                - "lambda.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        - PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: "Allow"
              - Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
              - Resource: "*"
  HelloWorldFunction:
    Type: "AWS::Lambda::Function"
    Properties:
      Code:
        S3Bucket: !Ref BucketName
        S3Key: deployment.zip
      FunctionName: !Ref FunctionName
      Handler: "main"
      Runtime: "go1.x"
      Role: !GetAtt ExecutionRole.Arn
```

上述文件定义了两个资源：

+   `ExecutionRole`：分配给 Lambda 函数的 IAM 角色，它定义了 Lambda 运行时调用的代码的权限。

+   `HelloWorldFunction`：AWS Lambda 定义，我们已将运行时属性设置为使用 Go，并将函数的代码存储在 S3 上的 ZIP 文件中。该函数使用 CloudFormation 的内置`GetAtt`函数引用 IAM 角色；它还使用`Ref`关键字引用参数部分中定义的变量。

也可以使用 JSON 格式；在 GitHub 存储库中可以找到 JSON 版本（[`github.com/PacktPublishing/Hands-On-serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)）。

执行以下步骤开始：

1.  使用以下命令构建后，创建一个 S3 存储桶来存储部署包：

```go
aws s3 mb s3://hands-on-serverless-go-packt/
GOOS=linux go build -o main main.go
zip deployment.zip main
aws s3 cp deployment.zip s3://hands-on-serverless-go-packt/
```

1.  转到 AWS CloudFormation 控制台，然后选择“创建堆栈”，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0feeae8d-1e10-4f28-a4f4-3aaf49b8e73a.png)

1.  在“选择模板”页面上，选择模板文件，它将上传到 Amazon S3 存储桶，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c4b8d238-5224-4326-a5d1-3322e5aac1ed.png)

1.  单击“下一步”，定义堆栈名称，并根据需要覆盖默认参数，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9682d28e-043c-4206-978c-54277bc9adb6.png)

1.  单击“下一步”，将选项保留为默认值，然后单击“创建”，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/378aec0b-6713-4877-9cf7-a203509f0361.png)

1.  堆栈将开始创建模板文件中定义的所有资源。创建后，堆栈状态将从**CREATE_IN_PROGRESS**更改为**CREATE_COMPLETE**（如果出现问题，将自动执行回滚），如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6a932901-01dd-476c-a189-00a7a4cdbad7.png)

1.  因此，我们的 Lambda 函数应该如下屏幕截图所示创建：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4a2a75b1-0523-49df-8036-eb09c05a80f0.png)

1.  您始终可以更新您的 CloudFormation 模板文件。例如，让我们创建一个新的 DynamoDB 表：

```go
AWSTemplateFormatVersion: "2010-09-09"
Description: "Simple Lambda Function"
Parameters:
  FunctionName:
    Description: "Function name"
    Type: "String"
    Default: "HelloWorld"
  BucketName:
    Description: "S3 Bucket name"
    Type: "String"
  TableName:
    Description: "DynamoDB Table Name"
    Type: "String"
    Default: "movies"
Resources:
  ExecutionRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - 
            Effect: "Allow"
            Principal:
              Service:
                - "lambda.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        - 
          PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: "*"
        - 
          PolicyName: "ScanDynamoDBTablePolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - dynamodb:Scan
                Resource: "*"
  HelloWorldFunction:
    Type: "AWS::Lambda::Function"
    Properties:
      Code:
        S3Bucket: !Ref BucketName
        S3Key: deployment.zip
      FunctionName: !Ref FunctionName
      Handler: "main"
      Runtime: "go1.x"
      Role: !GetAtt ExecutionRole.Arn
      Environment:
        Variables:
          TABLE_NAME: !Ref TableName
  DynamoDBTable:
    Type: "AWS::DynamoDB::Table"
    Properties:
      TableName: !Ref TableName
      AttributeDefinitions:
        -
          AttributeName: "ID"
          AttributeType: "S"
      KeySchema:
        -
          AttributeName: "ID"
          KeyType: "HASH"
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
```

1.  在 CloudFormation 控制台上，选择我们之前创建的堆栈，然后从菜单中单击“更新堆栈”，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/cbd01613-eb12-4154-bc05-eb91302dba44.png)

1.  上传更新后的模板文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e9ffce4b-26db-44e2-ab9b-5358cdd81cfc.png)

1.  与 Terraform 类似，AWS CloudFormation 将检测更改并提前显示将更改的资源，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6b64c142-d567-4f82-b452-c5426fc57337.png)

1.  单击“更新”按钮以应用更改。堆栈状态将更改为 UPDATE_IN_PROGRESS，如下一个屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/aff2ab2c-6736-42f4-a8ea-55cb7db47223.png)

1.  应用更改后，将创建一个新的 DynamoDB 表，并向 Lambda 函数授予 DynamoDB 权限，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f01be3a6-0f19-4e9c-9304-212617986da1.png)

每当 CloudFormation 必须定义 IAM 角色、策略或相关资源时，`--capabilities CAPABILITY_IAM`选项是必需的。

1.  AWS CLI 也可以用来使用以下命令创建您的 CloudFormation 堆栈：

```go
aws cloudformation create-stack --stack-name=SimpleLambdaFunction \
 --template-body=file://template.yml \
 --capabilities CAPABILITY_IAM \
 --parameters ParameterKey=BucketName,ParameterValue=hands-on-serverless-go-packt 
 ParameterKey=FunctionName,ParameterValue=HelloWorld \
 ParameterKey=TableName,ParameterValue=movies
```

# CloudFormation 设计师

除了从头开始编写自己的模板外，还可以使用 CloudFormation 设计模板功能轻松创建您的堆栈。以下屏幕截图显示了如何查看到目前为止创建的堆栈的设计：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/53509c27-1e72-49ac-9539-882a4a98d329.png)

如果一切顺利，您应该看到以下组件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/eb2d5838-3e48-49e6-85de-7913d9c3e669.png)

现在，您可以通过从左侧菜单拖放组件来创建复杂的 CloudFormation 模板。

# 使用 SAM 部署 AWS Lambda

**AWS 无服务器应用程序模型**（**AWS SAM**）是定义无服务器应用程序的模型。AWS SAM 受到 AWS CloudFormation 的本地支持，并定义了一种简化的语法来表达无服务器资源。您只需在模板文件中定义应用程序中所需的资源，并使用 SAM 部署命令创建一个 CloudFormation 堆栈。

之前，我们看到了如何使用 AWS SAM 来本地测试 Lambda 函数。此外，SAM 还可以用于设计和部署函数到 AWS Lambda。您可以使用以下命令初始化一个快速的基于 Go 的无服务器项目（样板）：

```go
sam init --name api --runtime go1.x
```

上述命令将创建一个具有以下结构的文件夹：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0b5d1241-e25c-46a6-aa2b-cad64a26be94.png)

`sam init`命令提供了一种快速创建无服务器应用程序的方法。它生成一个简单的带有关联单元测试的 Go Lambda 函数。此外，将生成一个包含构建和生成部署包步骤列表的 Makefile。最后，将创建一个模板文件，称为 SAM 文件，其中描述了部署函数到 AWS Lambda 所需的所有 AWS 资源。

现在我们知道了如何使用 SAM 生成样板，让我们从头开始编写自己的模板。创建一个名为`findall`的文件夹，在其中创建一个`main.go`文件，其中包含`FindAllMovies`函数的代码内容：

```go
// Movie entity
type Movie struct {
  ID string `json:"id"`
  Name string `json:"name"`
  Cover string `json:"cover"`
  Description string `json:"description"`
}

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

  movies := make([]Movie, 0)
  for _, item := range res.Items {
    movies = append(movies, Movie{
      ID: *item["ID"].S,
      Name: *item["Name"].S,
      Cover: *item["Cover"].S,
      Description: *item["Description"].S,
    })
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

func main() {
  lambda.Start(findAll)
}
```

接下来，在`template.yaml`文件中创建一个无服务器应用程序定义。以下示例说明了如何创建一个带有 DynamoDB 表的 Lambda 函数：

```go
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::serverless-2016-10-31
Resources:
  FindAllFunction:
    Type: AWS::serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Policies: AmazonDynamoDBFullAccess 
      Environment:
        Variables: 
          TABLE_NAME: !Ref MoviesTable
  MoviesTable: 
     Type: AWS::serverless::SimpleTable
     Properties:
       PrimaryKey:
         Name: ID
         Type: String
       ProvisionedThroughput:
         ReadCapacityUnits: 5
         WriteCapacityUnits: 5
```

该模板类似于我们之前编写的 CloudFormation 模板。SAM 扩展了 CloudFormation 并简化了表达无服务器资源的语法。

使用`package`命令将部署包上传到*CloudFormation*部分中创建的 S3 存储桶：

```go
sam package --template-file template.yaml --output-template-file serverless.yaml \
    --s3-bucket hands-on-serverless-go-packt
```

上述命令将部署页面上传到 S3 存储桶，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8bfd86bd-6cd4-407a-82d4-4f837e7cc92a.png)

此外，将基于您提供的定义文件生成一个名为`serverless.yaml`的 SAM 模板文件。它应该包含指向您指定的 Amazon S3 存储桶中的`deployment` ZIP 的`CodeUri`属性：

```go
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  FindAllFunction:
    Properties:
      CodeUri: s3://hands-on-serverless-go-packt/764cf76832f79ca7f29c6397fe7ccd91
      Environment:
        Variables:
          TABLE_NAME:
            Ref: MoviesTable
      Handler: main
      Policies: AmazonDynamoDBFullAccess
      Runtime: go1.x
    Type: AWS::serverless::Function
  MoviesTable:
    Properties:
      PrimaryKey:
        Name: ID
        Type: String
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
    Type: AWS::serverless::SimpleTable
Transform: AWS::serverless-2016-10-31
```

最后，使用以下命令将函数部署到 AWS Lambda：

```go
sam deploy --template-file serverless.yaml --stack-name APIStack \
 --capabilities CAPABILITY_IAM

```

`CAPABILITY_IAM`用于明确确认 AWS CloudFormation 被允许代表您为 Lambda 函数创建 IAM 角色。

当您运行`sam deploy`命令时，它将创建一个名为 APIStack 的 AWS CloudFormation 堆栈，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/33f5c604-5883-4c0c-9f17-c13f094a2a34.png)

资源创建后，函数应该部署到 AWS Lambda，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7a65c8f6-52b6-472f-859d-5e1718705e77.png)

SAM 范围仅限于无服务器资源（支持的 AWS 服务列表可在以下网址找到：[`docs.aws.amazon.com/serverlessrepo/latest/devguide/using-aws-sam.html`](https://docs.aws.amazon.com/serverlessrepo/latest/devguide/using-aws-sam.html)）。

# 导出无服务器应用程序

AWS Lambda 允许您为现有函数导出 SAM 模板文件。选择目标函数，然后从操作菜单中单击“导出函数”，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3807cd11-1678-4917-b8e8-dc14dc4d60d6.png)

单击“下载 AWS SAM 文件”以下载模板文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/83cc9b85-60af-4865-a357-6e17562ba2af.png)

模板将包含函数的定义、必要的权限和触发器：

```go
AWSTemplateFormatVersion: '2010-09-09'
Transform: 'AWS::serverless-2016-10-31'
Description: An AWS serverless Specification template describing your function.
Resources:
  FindAllMovies:
    Type: 'AWS::serverless::Function'
    Properties:
      Handler: main
      Runtime: go1.x
      CodeUri: .
      Description: ''
      MemorySize: 128
      Timeout: 3
      Role: 'arn:aws:iam::ACCOUNT_ID:role/FindAllMoviesRole'
      Events:
        Api1:
          Type: Api
          Properties:
            Path: /MyResource
            Method: ANY
        Api2:
          Type: Api
          Properties:
            Path: /movies
            Method: GET
      Environment:
        Variables:
          TABLE_NAME: movies
      Tracing: Active
      ReservedConcurrentExecutions: 10
```

现在，您可以使用`sam package`和`sam deploy`命令将函数导入到不同的 AWS 区域或 AWS 账户中。

# 总结

管理无服务器应用程序资源可以是非常手动的，或者您可以自动化工作流程。但是，如果您有一个复杂的基础架构，自动化流程可能会很棘手。这就是 AWS CloudFormation、SAM 和 Terraform 等工具发挥作用的地方。

在本章中，我们学习了如何使用基础设施即代码工具来自动化创建 AWS 中无服务器应用程序资源和依赖关系。我们看到了一些特定于云的工具，以及松散耦合的工具，可以在多个平台上运行。然后，我们看到了这些工具如何用于部署基于 Lambda 的应用程序到 AWS。

到目前为止，您可以编写一次无服务器基础设施代码，然后多次使用它。定义基础设施的代码可以进行版本控制、分叉、回滚（回到过去）并用于审计基础设施更改，就像任何其他代码一样。此外，它可以以编程方式发现和解决。换句话说，如果基础设施已经被手动修改，您可以销毁该基础设施并重新生成一个干净的副本——不可变基础设施。

# 问题

1.  编写一个 Terraform 模板来创建`InsertMovie` Lambda 函数资源。

1.  更新 CloudFormation 模板，以便在收到传入的 HTTP 请求时通过 API Gateway 触发定义的 Lambda 函数。

1.  编写一个 SAM 文件来建模和定义构建本书中一直使用的无服务器 API 所需的所有资源。

1.  配置 Terraform 以将生成的状态文件存储在远程 S3 后端。

1.  为我们在本书中构建的无服务器 API 创建一个 CloudFormation 模板。

1.  为我们在本书中构建的无服务器 API 创建一个 Terraform 模板。


# 第十五章：评估

# 第一章：无服务器

1.  使用无服务器方法的优势是什么？

**答案**：

+   +   NoOps：没有管理或配置开销，上市时间更快。

+   自动缩放和 HA：根据负载增强的可伸缩性和弹性。

+   成本优化：只为您消耗的计算时间付费。

+   Polygot：利用纳米服务架构的力量。

1.  Lambda 是一种节省时间的方法的原因是什么？

**答案**：您按执行次数付费，不会为闲置资源付费，而使用 EC2 实例时，您还会为未使用的资源付费。

1.  无服务器架构如何实现微服务？

**答案**：微服务是将单片应用程序分解为一组较小和模块化服务的方法。无服务器计算是微服务应用程序的关键启用。它使基础设施变得事件驱动，并完全由构成应用程序的每个服务的需求控制。此外，无服务器意味着函数，而微服务是一组函数。

1.  AWS Lambda 函数的最长时间限制是多少？

**答案**：默认情况下，每个 Lambda 函数的超时时间为 3 秒；您可以设置的最长持续时间为 5 分钟。

1.  以下哪些是 AWS Lambda 支持的事件源？

+   亚马逊 Kinesis 数据流

+   亚马逊 RDS

+   AWS CodeCommit

+   AWS 云形成

**答案**：亚马逊 Kinesis 数据流、AWS CodeCommit 和 CloudFormation 是 AWS Lambda 支持的事件源。所有支持的事件源列表可以在以下网址找到：[`docs.aws.amazon.com/lambda/latest/dg/invoking-lambda-function.html`](https://docs.aws.amazon.com/lambda/latest/dg/invoking-lambda-function.html)

1.  解释 Go 中的 goroutine 是什么。如何停止 goroutines？

**答案**：goroutine 是轻量级线程；它使用一种称为**通道**的资源进行通信。通道通过设计，防止了在使用 goroutines 访问共享内存时发生竞态条件。要停止 goroutine，我们传递信号通道。该信号通道用于推送一个值。goroutine 定期轮询该通道。一旦检测到信号，它就会退出。

1.  AWS 中的 Lambda@Edge 是什么？

**答案**：Lambda@Edge 允许您在 CloudFront 的边缘位置运行 Lambda 函数，以便自定义返回给最终用户的内容，延迟最低。

1.  功能即服务和平台即服务之间有什么区别？

**答案**：PaaS 和 FaaS 都允许您轻松部署应用程序并在不担心基础架构的情况下进行扩展。但是，FaaS 可以节省您的资金，因为您只需为处理传入请求所使用的计算时间付费。

1.  什么是 AWS Lambda 冷启动？

**答案**：当触发新事件时会发生冷启动；AWS Lambda 创建和初始化一个新实例或容器来处理请求，这比热启动需要更长的时间（启动延迟），在热启动中，容器是从先前的事件中重用的。

1.  AWS Lambda 函数可以是无状态的还是有状态的？

**答案**：Lambda 函数必须是无状态的，以利用由于传入事件速率增加而导致的自动扩展的能力。

# 第二章：开始使用 AWS Lambda

1.  AWS CLI 不支持哪种格式？

+   JSON

+   表

+   XML

+   文本

**答案**：支持的值为 JSON、表和文本。默认输出为 JSON。

1.  是否建议使用 AWS 根帐户进行日常与 AWS 的交互？如果是的话，为什么？

**答案**：AWS 根帐户具有创建和删除 AWS 资源、更改计费甚至关闭 AWS 帐户的最终权限。因此，强烈建议为日常任务创建一个仅具有所需权限的 IAM 用户。

1.  您需要设置哪些环境变量才能使用 AWS CLI？

**答案**：以下是配置 AWS CLI 所需的环境变量：

+   +   `AWS_ACCESS_KEY_ID`

+   `AWS_SECRET_ACCESS_KEY`

+   `AWS_DEFAULT_REGION`

1.  如何使用具有命名配置文件的 AWS CLI？

**回答**：`AWS_PROFILE`可用于设置要使用的 CLI 配置文件。配置文件存储在凭据文件中。默认情况下，AWS CLI 使用`default`配置文件。

1.  解释 GOPATH 环境变量。

**回答**：`GOPATH`环境变量指定 Go 工作区的位置。默认值为`$HOME/go`。

1.  哪个命令行命令编译 Go 程序？

+   `go build`

+   `go run`

+   `go fmt`

+   `go doc`

**回答**：上述命令执行以下操作：

+   +   `build`：它是一个编译包和依赖项并生成单个二进制文件。

+   `run`：它是一个编译和运行 Go 程序。

+   `fmt`：它是一个重新格式化包资源。

+   `doc`：它是一个显示包或函数文档的包。

1.  什么是 Go 工作区？

**回答**：Go 工作区是一个您将加载和处理 Go 代码的目录。该目录必须具有以下层次结构：

+   +   `src`：它包含 Go 源文件。

+   `bin`：它包含可执行文件。

+   `pkg`：它包含包对象。

# 第三章：使用 Lambda 开发无服务器函数

1.  创建 AWS Lambda 函数的 IAM 角色的命令行命令是什么？

**回答**：使用以下命令创建一个 IAM 角色；它允许 Lambda 函数调用您帐户下的 AWS 服务：

```go
aws iam create-role ROLE_NAME --assume-role-policy-document file://assume-role-lambda.json
```

`assume-role-lambda.json`文件包含以下内容：

```go
{  
 "Version":"2012-10-17",
 "Statement":[  
  {  
  "Effect":"Allow",
  "Principal":{  
   "AWS":"*"
  },
  "Action":"sts:AssumeRole"
  }
 ]
} 
```

1.  在弗吉尼亚地区（`us-east-1`）创建一个新的 S3 存储桶并将 Lambda 部署包上传到其中的命令行命令是什么？

**回答**：以下命令可用于创建一个 S3 存储桶：

```go
aws s3 mb s3://BUCKET_NAME --region us-east-1
```

要将部署包上传到存储桶，发出以下命令：

```go
aws s3 cp deployment.zip s3://BUCKET_NAME --region us-east-1
```

1.  Lambda 包大小限制是多少？

+   10 MB

+   50 MB

+   250 MB

**回答**：AWS Lambda 部署包的总最大限制为 50MB 压缩和 250MB 未压缩。

1.  AWS Lambda 控制台支持编辑 Go 源代码。

+   真

+   假

**回答**：错误；Go 是最近添加的语言，其开发人员尚未添加内联编辑器的功能。因此，您必须提供一个 ZIP 文件格式的可执行二进制文件或引用一个 S3 存储桶和对象键，您已经上传了部署包。

1.  AWS Lambda 执行环境的基础是什么？

+   亚马逊 Linux 镜像

+   微软 Windows 服务器

**回答**：AWS Lambda 执行环境基于亚马逊 Linux AMI。

1.  AWS Lambda 中如何表示事件？

**回答**：AWS Lambda 中的事件以 JSON 格式表示。

# 第五章：使用 DynamoDB 管理数据持久性

1.  实现更新处理程序以更新现有的电影项目。

**回答**：处理程序期望以 JSON 格式的电影项目；输入将被编码为`Movie`结构。使用`PutItem`方法将电影插入表中，如下所示：

```go
func update(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  var movie Movie
  err := json.Unmarshal([]byte(request.Body), &movie)
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: 400,
      Body: "Invalid payload",
    }, nil
  }

  ...

  svc := dynamodb.New(cfg)
  req := svc.PutItemRequest(&dynamodb.PutItemInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
    Item: map[string]dynamodb.AttributeValue{
      "ID": dynamodb.AttributeValue{
        S: aws.String(movie.ID),
      },
      "Name": dynamodb.AttributeValue{
        S: aws.String(movie.Name),
      },
    },
  })
  _, err = req.Send()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while updating the movie",
    }, nil
  }

  response, err := json.Marshal(movie)
  ...

  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Body: string(response),
    Headers: map[string]string{
      "Content-Type": "application/json",
    },
  }, nil
}

```

1.  在 API Gateway 中创建一个新的 PUT 方法来触发`update` Lambda 函数。

**回答**：在`/movies`资源上公开一个`PUT`方法，并配置目标为之前定义的 Lambda 函数。以下截图展示了结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d4defec5-5386-4f7b-bbbd-3a1e12cb4449.png)

1.  实现一个单一的 Lambda 函数来处理所有类型的事件（GET、POST、DELETE、PUT）。

**回答**：

```go
func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
 switch request.HTTPMethod {
 case http.MethodGet:
 // get all movies handler
 break
 case http.MethodPost:
 // insert movie handler
 break
 case http.MethodDelete:
 // delete movie handler
 break
 case http.MethodPut:
 // update movie handler
 break
 default:
 return events.APIGatewayProxyResponse{
 StatusCode: http.StatusMethodNotAllowed,
 Body: "Unsupported HTTP method",
 }, nil
 }
}
```

1.  更新`findOne`处理程序以返回对于有效请求但空数据（例如，所请求的 ID 没有电影）的适当响应代码。

**回答**：在处理用户输入（在我们的情况下是电影 ID）时，验证是强制性的。因此，您需要编写一个正则表达式来确保参数中给定的 ID 格式正确。以下是用于验证 ID 的正则表达式示例：

+   +   包含字母数字 ID 的模式：`[a-zA-Z0-9]+`

+   仅数字 ID 的模式：`[0-9]+`

1.  使用`Range`标头和`Query`字符串在`findAll`端点上实现分页系统。

**回答**：在`ScanRequest`方法中使用 Limit 选项来限制返回的项目数：

```go
dynamodbClient := dynamodb.New(cfg)
req := dynamodbClient.ScanRequest(&dynamodb.ScanInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
    Limit: aws.Int64(int64(size)),
})
```

可以从请求标头中读取要返回的项目数：

```go
size, err := strconv.Atoi(request.Headers["Size"])
```

# 第七章：实施 CI/CD 流水线

1.  使用 CodeBuild 和 CodePipeline 为其他 Lambda 函数实现 CI/CD 流水线。

**回答**：`FindAllMovies` Lambda 函数的 CI/CD 流水线可以按以下方式实现：

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

`InsertMovie` Lambda 函数的 CI/CD 流水线可以按以下方式实现：

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
      - aws lambda update-function-code --function-name InsertMovie --s3-bucket $S3_BUCKET --s3-key $CODEBUILD_RESOLVED_SOURCE_VERSION.zip
```

`Updatemovie` Lambda 函数的 CI/CD 流水线可以按以下方式实现：

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
      - aws lambda update-function-code --function-name UpdateMovie --s3-bucket $S3_BUCKET --s3-key $CODEBUILD_RESOLVED_SOURCE_VERSION.zip
```

`DeleteMovie` Lambda 函数的 CI/CD 流水线可以按以下方式实现：

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
      - aws lambda update-function-code --function-name DeleteMovie --s3-bucket $S3_BUCKET --s3-key $CODEBUILD_RESOLVED_SOURCE_VERSION.zip
```

1.  使用 Jenkins Pipeline 实现类似的工作流程。

**回答**：我们可以使用 Jenkins 并行阶段功能并行运行代码块，如下所示：

```go
def bucket = 'movies-api-deployment-packages'

node('slave-golang'){
    stage('Checkout'){
        checkout scm
        sh 'go get -u github.com/golang/lint/golint'
        sh 'go get -t ./...'
    }

    stage('Test'){
        parallel {
            stage('FindAllMovies') {
                sh 'cd findAll'
                sh 'golint -set_exit_status'
                sh 'go vet .'
                sh 'go test .'
            }
            stage('DeleteMovie') {
                sh 'cd delete'
                sh 'golint -set_exit_status'
                sh 'go vet .'
                sh 'go test .'
            }
            stage('UpdateMovie') {
                sh 'cd update'
                sh 'golint -set_exit_status'
                sh 'go vet .'
                sh 'go test .'
            }
            stage('InsertMovie') {
                sh 'cd insert'
                sh 'golint -set_exit_status'
                sh 'go vet .'
                sh 'go test .'
            }
        }
    }

    stage('Build'){
        parallel {
            stage('FindAllMovies') {
                sh 'cd findAll'
                sh 'GOOS=linux go build -o main main.go'
                sh "zip findAll-${commitID()}.zip main"
            }
            stage('DeleteMovie') {
                sh 'cd delete'
                sh 'GOOS=linux go build -o main main.go'
                sh "zip delete-${commitID()}.zip main"
            }
            stage('UpdateMovie') {
                sh 'cd update'
                sh 'GOOS=linux go build -o main main.go'
                sh "zip update-${commitID()}.zip main"
            }
            stage('InsertMovie') {
                sh 'cd insert'
                sh 'GOOS=linux go build -o main main.go'
                sh "zip insert-${commitID()}.zip main"
            }
        }
    }

    stage('Push'){
        parallel {
            stage('FindAllMovies') {
                sh 'cd findAll'
                sh "aws s3 cp findAll-${commitID()}.zip s3://${bucket}"
            }
            stage('DeleteMovie') {
                sh 'cd delete'
                sh "aws s3 cp delete-${commitID()}.zip s3://${bucket}"
            }
            stage('UpdateMovie') {
                sh 'cd update'
                sh "aws s3 cp update-${commitID()}.zip s3://${bucket}"
            }
            stage('InsertMovie') {
                sh 'cd insert'
                sh "aws s3 cp insert-${commitID()}.zip s3://${bucket}"
            }
        }
    }

    stage('Deploy'){
        parallel {
            stage('FindAllMovies') {
                sh 'cd findAll'
                sh "aws lambda update-function-code --function-name FindAllMovies \
                --s3-bucket ${bucket} \
                --s3-key findAll-${commitID()}.zip \
                --region us-east-1"
            }
            stage('DeleteMovie') {
                sh 'cd delete'
                sh "aws lambda update-function-code --function-name DeleteMovie \
                --s3-bucket ${bucket} \
                --s3-key delete-${commitID()}.zip \
                --region us-east-1"
            }
            stage('UpdateMovie') {
                sh 'cd update'
                sh "aws lambda update-function-code --function-name UpdateMovie \
                --s3-bucket ${bucket} \
                --s3-key update-${commitID()}.zip \
                --region us-east-1"
            }
            stage('InsertMovie') {
                sh 'cd insert'
                sh "aws lambda update-function-code --function-name InsertMovie \
                --s3-bucket ${bucket} \
                --s3-key insert-${commitID()}.zip \
                --region us-east-1"
            }
        }
    }
}

def commitID() {
    sh 'git rev-parse HEAD > .git/commitID'
    def commitID = readFile('.git/commitID').trim()
    sh 'rm .git/commitID'
    commitID
}
```

1.  使用 CircleCI 实现相同的流水线。

**回答**：CircleCI 工作流选项可用于定义一组构建作业：

```go
version: 2
jobs:
  build_findall:
    docker:
      - image: golang:1.8

    working_directory: /go/src/github.com/mlabouardy/lambda-circleci

    build_dir: findAll

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

  build_insert:
    docker:
      - image: golang:1.8

    working_directory: /go/src/github.com/mlabouardy/lambda-circleci

    build_dir: insert

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
            aws lambda update-function-code --function-name InsertMovie \
                --s3-bucket $S3_BUCKET \
                --s3-key $CIRCLE_SHA1.zip --region us-east-1

  build_update:
    ...

  build_delete:
    ...

workflows:
  version: 2
  build_api:
    jobs:
      - build_findall
      - build_insert
      - build_update
      - build_delete
```

1.  在现有流水线中添加新阶段，如果当前的 git 分支是主分支，则发布新版本。

**回答**：

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
         ...

      - run:
          name: Test
          ...

      - run:
         name: Build
         ...

      - run:
          name: Push
          ...

      - run:
          name: Deploy
          ...

      - run:
          name: Publish
          command: |
            if [ $CIRCLE_BRANCH = 'master' ]; then 
              aws lambda publish-version --function-name FindAllMovies \
                --description $GIT_COMMIT_DESC --region us-east-1
            fi
          environment:
            GIT_COMMIT_DESC: git log --format=%B -n 1 $CIRCLE_SHA1
```

1.  配置流水线，每次部署或更新 Lambda 函数时都在 Slack 频道上发送通知。

**回答**：您可以使用 Slack API 在部署步骤结束时向 Slack 频道发布消息：

```go
- run:
    name: Deploy
    command: |
      aws lambda update-function-code --function-name FindAllMovies \
          --s3-bucket $S3_BUCKET \
          --s3-key $CIRCLE_SHA1.zip --region us-east-1
      curl -X POST -d '{"token":"$TOKEN", "channel":"$CHANNEL", "text":"FindAllMovies has been updated"}' \
           http://slack.com/api/chat.postMessage
```

# 第九章：使用 S3 构建前端

1.  实现一个 Lambda 函数，该函数以电影类别作为输入，并返回与该类别对应的电影列表。

**回答**：

```go
func filter(category string)(events.APIGatewayProxyResponse, error) {
    ...

    filter: = expression.Name("category").Equal(expression.Value(category))
    projection: = expression.NamesList(expression.Name("id"), expression.Name("name"), expression.Name("description"))
    expr, err: = expression.NewBuilder().WithFilter(filter).WithProjection(projection).Build()
    if err != nil {
        return events.APIGatewayProxyResponse {
            StatusCode: http.StatusInternalServerError,
            Body: "Error while building DynamoDB expression",
        }, nil
    }

    svc: = dynamodb.New(cfg)
    req: = svc.ScanRequest( & dynamodb.ScanInput {
        TableName: aws.String(os.Getenv("TABLE_NAME")),
        ExpressionAttributeNames: expr.Names(),
        ExpressionAttributeValues: expr.Values(),
        FilterExpression: expr.Filter(),
        ProjectionExpression: expr.Projection(),
    })

    ...
}
```

1.  实现一个 Lambda 函数，该函数以电影的标题作为输入，并返回所有标题中包含关键字的电影。

**回答**：

```go
func filter(keyword string) (events.APIGatewayProxyResponse, error) {
  ...

  filter := expression.Name("name").Contains(keyword)
  projection := expression.NamesList(expression.Name("id"), expression.Name("name"), expression.Name("description"))
  expr, err := expression.NewBuilder().WithFilter(filter).WithProjection(projection).Build()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while building DynamoDB expression",
    }, nil
  }

  svc := dynamodb.New(cfg)
  req := svc.ScanRequest(&dynamodb.ScanInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
    ExpressionAttributeNames: expr.Names(),
    ExpressionAttributeValues: expr.Values(),
    FilterExpression: expr.Filter(),
    ProjectionExpression: expr.Projection(),
  })
  ... 
}
```

1.  在 Web 应用程序上实现删除按钮，通过调用 API Gateway 中的 `DeleteMovie` Lambda 函数来删除电影。

**回答**：更新 MoviesAPI 服务以包括以下函数：

```go
delete(id: string){
    return this.http
      .delete(`${environment.api}/${id}`, {headers: this.getHeaders()})
      .map(res => {
        return res
      })
}
```

1.  在 Web 应用程序上实现编辑按钮，允许用户更新电影属性。

**回答**：

```go
update(movie: Movie){
    return this.http
      .put(environment.api, JSON.stringify(movie), {headers: this.getHeaders()})
      .map(res => {
        return res
      })
}
```

1.  使用 CircleCI、Jenkins 或 CodePipeline 实现 CI/CD 工作流，自动化生成和部署 API Gateway 文档。

**回答**：

```go
def bucket = 'movies-api-documentation'
def api_id = ''

node('slaves'){
  stage('Generate'){
    if (env.BRANCH_NAME == 'master') {
      sh "aws apigateway get-export --rest-api-id ${api_id} \
        --stage-name production \
        --export-type swagger swagger.json"
    }
    else if (env.BRANCH_NAME == 'preprod') {
      sh "aws apigateway get-export --rest-api-id ${api_id} \
        --stage-name staging \
        --export-type swagger swagger.json"
    } else {
      sh "aws apigateway get-export --rest-api-id ${api_id} \
        --stage-name sandbox \
        --export-type swagger swagger.json"
    }
  }

  stage('Publish'){
    sh "aws s3 cp swagger.json s3://${bucket}"
  }
}
```

# 第十章：测试您的无服务器应用程序

1.  为 `UpdateMovie` Lambda 函数编写一个单元测试。

**回答**：

```go
package main

import (
  "testing"

  "github.com/stretchr/testify/assert"

  "github.com/aws/aws-lambda-go/events"
)

func TestUpdate_InvalidPayLoad(t *testing.T) {
  input := events.APIGatewayProxyRequest{
    Body: "{'name': 'avengers'}",
  }
  expected := events.APIGatewayProxyResponse{
    StatusCode: 400,
    Body: "Invalid payload",
  }
  response, _ := update(input)
  assert.Equal(t, expected, response)
}

func TestUpdate_ValidPayload(t *testing.T) {
  input := events.APIGatewayProxyRequest{
    Body: "{\"id\":\"40\", \"name\":\"Thor\", \"description\":\"Marvel movie\", \"cover\":\"poster url\"}",
  }
  expected := events.APIGatewayProxyResponse{
    Body: "{\"id\":\"40\", \"name\":\"Thor\", \"description\":\"Marvel movie\", \"cover\":\"poster url\"}",
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  }
  response, _ := update(input)
  assert.Equal(t, expected, response)
}
```

1.  为 `DeleteMovie` Lambda 函数编写一个单元测试。

**回答**：

```go
package main

import (
  "testing"

  "github.com/stretchr/testify/assert"

  "github.com/aws/aws-lambda-go/events"
)

func TestDelete_InvalidPayLoad(t *testing.T) {
  input := events.APIGatewayProxyRequest{
    Body: "{'name': 'avengers'}",
  }
  expected := events.APIGatewayProxyResponse{
    StatusCode: 400,
    Body: "Invalid payload",
  }
  response, _ := delete(input)
  assert.Equal(t, expected, response)
}

func TestDelete_ValidPayload(t *testing.T) {
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
  response, _ := delete(input)
  assert.Equal(t, expected, response)
}
```

1.  修改之前章节中提供的 `Jenkinsfile`，包括执行自动化单元测试的步骤。

**回答**：请注意在 **测试** 阶段中使用 `go test` 命令：

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

1.  修改 `buildspec.yml` 定义文件，包括在将部署包推送到 S3 之前执行单元测试的步骤。

**回答**：

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

1.  为在之前章节中实现的每个 Lambda 函数编写一个 SAM 模板文件。

**回答**：以下是 `FindAllMovies` Lambda 函数的 SAM 模板文件；可以使用相同的资源来创建其他函数：

```go
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  StageName:
    Type: String
    Default: staging
    Description: The API Gateway deployment stage

Resources:
  FindAllMovies:
    Type: AWS::Serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Role: !GetAtt FindAllMoviesRole.Arn 
      CodeUri: ./findall/deployment.zip
      Environment:
        Variables: 
          TABLE_NAME: !Ref MoviesTable
      Events:
        AnyRequest:
          Type: Api
          Properties:
            Path: /movies
            Method: GET
            RestApiId:
              Ref: MoviesAPI

  FindAllMoviesRole:
   Type: "AWS::IAM::Role"
   Properties:
     Path: "/"
     ManagedPolicyArns:
         - "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
     AssumeRolePolicyDocument:
       Version: "2012-10-17"
       Statement:
         -
           Effect: "Allow"
           Action:
             - "sts:AssumeRole"
           Principal:
             Service:
               - "lambda.amazonaws.com"
     Policies: 
        - 
          PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: "*"
        - 
          PolicyName: "ScanDynamoDBTablePolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - dynamodb:Scan
                Resource: "*"

  MoviesTable: 
     Type: AWS::Serverless::SimpleTable
     Properties:
       PrimaryKey:
         Name: ID
         Type: String
       ProvisionedThroughput:
         ReadCapacityUnits: 5
         WriteCapacityUnits: 5

  MoviesAPI:
    Type: 'AWS::Serverless::Api'
    Properties:
      StageName: !Ref StageName
      DefinitionBody:
        swagger: 2.0
        info:
          title: !Sub API-${StageName}
        paths:
          /movies:
            x-amazon-apigateway-any-method:
              produces:
                - application/json
              x-amazon-apigateway-integration:
                uri:
                  !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${FindAllMovies.Arn}:current/invocations"
                passthroughBehavior: when_no_match
                httpMethod: POST
                type: aws_proxy
```

# 第十二章：保护您的无服务器应用程序

1.  将用户池中的用户与身份池集成，允许用户使用其 Facebook 帐户登录。

**回答**：为了将 Facebook 与 Amazon Cognito 身份池集成，您必须遵循给定的步骤：

+   +   从 Facebook 开发者门户（[`developers.facebook.com/`](https://developers.facebook.com/)）创建 Facebook 应用程序。

+   复制应用程序 ID 和密钥。

+   在 Amazon Cognito 控制台中配置 Facebook 作为提供者：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/864936ac-5f65-4091-a8c1-232c253e4be6.png)

+   +   按照 Facebook 指南（[`developers.facebook.com/docs/facebook-login/login-flow-for-web/v2.3`](https://developers.facebook.com/docs/facebook-login/login-flow-for-web/v2.3)）在 Web 应用程序中添加 Facebook 登录按钮。

+   用户经过身份验证后，将返回一个 Facebook 会话令牌；必须将此令牌添加到 Amazon Cognito 凭据提供程序中以获取 JWT 令牌。

+   最后，将 JWT 令牌添加到 API Gateway 请求的 `Authorization` 标头中。

1.  将用户池中的用户与身份池集成，允许用户使用其 Twitter 帐户登录。

**回答**：Amazon Cognito 不支持 Twitter 作为默认的身份验证提供者。因此，您需要使用 **OpenID Connect** 来扩展 Amazon Cognito：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e1757cff-eb06-4cd3-92e4-013582ded7e8.png)

1.  将用户池中的用户与身份池集成，允许用户使用其 Google 帐户登录。

+   +   要启用 Google 登录，您需要从 Google 开发者控制台创建一个新项目（[`console.developers.google.com/`](https://console.developers.google.com/)）

+   在 API 和身份验证下启用 Google API，然后创建 OAuth 2.0 客户端 ID。

+   在 Amazon Cognito 控制台中配置 Google：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/17e34035-a524-48f4-8340-7827d5cd4be1.png)

+   +   按照 Google Web 文档（[`developers.google.com/identity/sign-in/web/sign-in`](https://developers.google.com/identity/sign-in/web/sign-in)）添加 Google 登录按钮。

+   一旦用户经过身份验证，将生成一个身份验证令牌，该令牌可用于检索 JWT 令牌。

1.  实现一个表单，允许用户在 Web 应用程序上创建帐户，以便他们能够登录。

**答案**：可以创建一个基于 Go 的 Lambda 函数来处理帐户创建工作流程。函数的入口点如下所示：

```go
package main

import (
  "os"

  "github.com/aws/aws-lambda-go/lambda"
  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/aws/external"
  "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type Account struct {
  Username string `json:"username"`
  Password string `json:"password"`
}

func signUp(account Account) error {
  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    return err
  }

  cognito := cognitoidentityprovider.New(cfg)
  req := cognito.SignUpRequest(&cognitoidentityprovider.SignUpInput{
    ClientId: aws.String(os.Getenv("COGNITO_CLIENT_ID")),
    Username: aws.String(account.Username),
    Password: aws.String(account.Password),
  })
  _, err = req.Send()
  if err != nil {
    return err
  }
  return nil
}

func main() {
  lambda.Start(signUp)
}
```

1.  为未经身份验证的用户实现忘记密码流程。

**答案**：可以创建一个基于 Go 的 Lambda 函数来重置用户密码。函数的入口点如下所示：

```go
package main

import (
  "os"

  "github.com/aws/aws-lambda-go/lambda"
  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/aws/external"
  "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type Account struct {
  Username string `json:"username"`
}

func forgotPassword(account Account) error {
  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    return err
  }

  cognito := cognitoidentityprovider.New(cfg)
  req := cognito.ForgotPasswordRequest(&cognitoidentityprovider.ForgotPasswordInput{
    ClientId: aws.String(os.Getenv("COGNITO_CLIENT_ID")),
    Username: aws.String(account.Username),
  })
  _, err = req.Send()
  if err != nil {
    return err
  }

  return nil
}

func main() {
  lambda.Start(forgotPassword)
}
```

# 第十四章：

1.  编写一个 Terraform 模板来创建`InsertMovie` Lambda 函数资源。

**答案**：为 Lambda 函数设置执行角色：

```go
resource "aws_iam_role" "role" {
  name = "InsertMovieRole"
  assume_role_policy = "${file("assume-role-policy.json")}"
}

resource "aws_iam_policy" "cloudwatch_policy" {
  name = "PushCloudWatchLogsPolicy"
  policy = "${file("cloudwatch-policy.json")}"
}

resource "aws_iam_policy" "dynamodb_policy" {
  name = "ScanDynamoDBPolicy"
  policy = "${file("dynamodb-policy.json")}"
}

resource "aws_iam_policy_attachment" "cloudwatch-attachment" {
  name = "cloudwatch-lambda-attchment"
  roles = ["${aws_iam_role.role.name}"]
  policy_arn = "${aws_iam_policy.cloudwatch_policy.arn}"
}

resource "aws_iam_policy_attachment" "dynamodb-attachment" {
  name = "dynamodb-lambda-attchment"
  roles = ["${aws_iam_role.role.name}"]
  policy_arn = "${aws_iam_policy.dynamodb_policy.arn}"
}
```

接下来，创建 Lambda 函数：

```go
resource "aws_lambda_function" "insert" {
  function_name = "InsertMovie"
  handler = "main"
  filename = "function/deployment.zip"
  runtime = "go1.x"
  role = "${aws_iam_role.role.arn}"

  environment {
    variables {
      TABLE_NAME = "movies"
    }
  }
}
```

在 REST API 的`/movies`资源上公开一个`POST`方法：

```go
resource "aws_api_gateway_method" "proxy" {
  rest_api_id = "${var.rest_api_id}"
  resource_id = "${var.resource_id}"
  http_method = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id = "${var.rest_api_id}"
  resource_id = "${var.resource_id}"
  http_method = "${aws_api_gateway_method.proxy.http_method}"

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = "${aws_lambda_function.insert.invoke_arn}"
}

resource "aws_lambda_permission" "apigw" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.insert.arn}"
  principal = "apigateway.amazonaws.com"

  source_arn = "${var.execution_arn}/*/*"
}
```

1.  更新 CloudFormation 模板，以响应传入的 HTTP 请求，触发已定义的 Lambda 函数与 API Gateway。

**答案**：将以下属性添加到“资源”部分：

```go
API:
    Type: 'AWS::ApiGateway::RestApi'
    Properties:
        Name: API
        FailOnWarnings: 'true'
DemoResource:
    Type: 'AWS::ApiGateway::Resource'
    Properties:
        ParentId:
            'Fn::GetAtt': [API, RootResourceId]
        PathPart: demo
        RestApiId:
            Ref: API
DisplayMessageMethod:
    Type: 'AWS::ApiGateway::Method'
    Properties:
        HttpMethod: GET
        AuthorizationType: NONE
        ResourceId:
            Ref: DemoResource
        RestApiId:
            Ref: API
        Integration:
            Type: AWS
            Uri: {'Fn::Join': ["", "- \"arn:aws:apigateway:\"\n- !Ref \"AWS::Region\"\n- \":lambda:path/\"\n- \"/2015-03-31/functions/\"\n- Fn::GetAtt:\n - HelloWorldFunction\n - Arn\n- \"/invocations\""]}
            IntegrationHttpMethod: GET
```

1.  编写 SAM 文件，对构建通过本书构建的无服务器 API 所需的所有资源进行建模和定义。

**答案**：

```go
Resources:
  FindAllMovies:
    Type: AWS::Serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Role: !GetAtt FindAllMoviesRole.Arn 
      CodeUri: ./findall/deployment.zip
      Environment:
        Variables: 
          TABLE_NAME: !Ref MoviesTable
      Events:
        AnyRequest:
          Type: Api
          Properties:
            Path: /movies
            Method: GET
            RestApiId:
              Ref: MoviesAPI

  InsertMovie:
    Type: AWS::Serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Role: !GetAtt InsertMovieRole.Arn 
      CodeUri: ./insert/deployment.zip
      Environment:
        Variables: 
          TABLE_NAME: !Ref MoviesTable
      Events:
        AnyRequest:
          Type: Api
          Properties:
            Path: /movies
            Method: POST
            RestApiId:
              Ref: MoviesAPI

  DeleteMovie:
    Type: AWS::Serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Role: !GetAtt DeleteMovieRole.Arn 
      CodeUri: ./delete/deployment.zip
      Environment:
        Variables: 
          TABLE_NAME: !Ref MoviesTable
      Events:
        AnyRequest:
          Type: Api
          Properties:
            Path: /movies
            Method: DELETE
            RestApiId:
              Ref: MoviesAPI

  UpdateMovie:
    Type: AWS::Serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Role: !GetAtt UpdateMovieRole.Arn 
      CodeUri: ./update/deployment.zip
      Environment:
        Variables: 
          TABLE_NAME: !Ref MoviesTable
      Events:
        AnyRequest:
          Type: Api
          Properties:
            Path: /movies
            Method: PUT
            RestApiId:
              Ref: MoviesAPI
```

1.  配置 Terraform 以将生成的状态文件存储在远程 S3 后端。

**答案**：使用以下 AWS CLI 命令创建一个 S3 存储桶：

```go
aws s3 mb s3://terraform-state-files --region us-east-1
```

在存储桶上启用服务器端加密：

```go
aws s3api put-bucket-encryption --bucket terraform-state-files \
    --server-side-encryption-configuration file://config.json
```

加密机制设置为 AES-256：

```go
{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }
  ]
}
```

配置 Terraform 以使用先前定义的存储桶：

```go
terraform {
  backend "s3" {
    bucket = "terraform-state-files"
    key = "KEY_NAME"
    region = "us-east-1"
  }
}
```

1.  为通过本书构建的无服务器 API 创建 CloudFormation 模板。

**答案**：

```go
AWSTemplateFormatVersion: "2010-09-09"
Description: "Simple Lambda Function"
Parameters:
  BucketName:
    Description: "S3 Bucket name"
    Type: "String"
  TableName:
    Description: "DynamoDB Table Name"
    Type: "String"
    Default: "movies"
Resources:
  FindAllMoviesRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - 
            Effect: "Allow"
            Principal:
              Service:
                - "lambda.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        - 
          PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: "*"
        - 
          PolicyName: "ScanDynamoDBTablePolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - dynamodb:Scan
                Resource: "*"
  FindAllMovies:
    Type: "AWS::Lambda::Function"
    Properties:
      Code:
        S3Bucket: !Ref BucketName
        S3Key: findall-deployment.zip
      FunctionName: "FindAllMovies"
      Handler: "main"
      Runtime: "go1.x"
      Role: !GetAtt FindAllMoviesRole.Arn
      Environment:
        Variables:
          TABLE_NAME: !Ref TableName

  InsertMovieRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - 
            Effect: "Allow"
            Principal:
              Service:
                - "lambda.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        - 
          PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: "*"
        - 
          PolicyName: "PutItemDynamoDBTablePolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - dynamodb:PutItem
                Resource: "*"
  InsertMovie:
    Type: "AWS::Lambda::Function"
    Properties:
      Code:
        S3Bucket: !Ref BucketName
        S3Key: insert-deployment.zip
      FunctionName: "InsertMovie"
      Handler: "main"
      Runtime: "go1.x"
      Role: !GetAtt InsertMovieRole.Arn
      Environment:
        Variables:
          TABLE_NAME: !Ref TableName

  UpdateMovieRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - 
            Effect: "Allow"
            Principal:
              Service:
                - "lambda.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        - 
          PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: "*"
        - 
          PolicyName: "PutItemDynamoDBTablePolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - dynamodb:PutItem
                Resource: "*"
  UpdateMovie:
    Type: "AWS::Lambda::Function"
    Properties:
      Code:
        S3Bucket: !Ref BucketName
        S3Key: update-deployment.zip
      FunctionName: "UpdateMovie"
      Handler: "main"
      Runtime: "go1.x"
      Role: !GetAtt UpdateMovieRole.Arn
      Environment:
        Variables:
          TABLE_NAME: !Ref TableName

  DeleteMovieRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - 
            Effect: "Allow"
            Principal:
              Service:
                - "lambda.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        - 
          PolicyName: "PushCloudWatchLogsPolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: "*"
        - 
          PolicyName: "DeleteItemDynamoDBTablePolicy"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                - dynamodb:DeleteItem
                Resource: "*"
  DeleteMovie:
    Type: "AWS::Lambda::Function"
    Properties:
      Code:
        S3Bucket: !Ref BucketName
        S3Key: update-deployment.zip
      FunctionName: "DeleteMovie"
      Handler: "main"
      Runtime: "go1.x"
      Role: !GetAtt DeleteMovieRole.Arn
      Environment:
        Variables:
          TABLE_NAME: !Ref TableName

  MoviesApi:
    Type: "AWS::ApiGateway::RestApi"
    Properties:
      Name: "MoviesApi"
      FailOnWarnings: "true"
  MoviesResource:
    Type: "AWS::ApiGateway::Resource"
    Properties:
      ParentId:
        Fn::GetAtt:
          - "MoviesApi"
          - "RootResourceId"
      PathPart: "movies"
      RestApiId:
        Ref: MoviesApi
  CreateMovieMethod:
    Type: "AWS::ApiGateway::Method"
    Properties:
      HttpMethod: "POST"
      AuthorizationType: "NONE"
      ResourceId:
        Ref: MoviesResource
      RestApiId:
        Ref: MoviesApi
      Integration:
        Type: "AWS"
        Uri:
          Fn::Join:
            - ""
            - - "arn:aws:apigateway:"
              - !Ref "AWS::Region"
              - ":lambda:path/"
              - "/2015-03-31/functions/"
              - Fn::GetAtt:
                - InsertMovie
                - Arn
              - "/invocations"
        IntegrationHttpMethod: "POST"
  DeleteMovieMethod:
    Type: "AWS::ApiGateway::Method"
    Properties:
      HttpMethod: "DELETE"
      AuthorizationType: "NONE"
      ResourceId:
        Ref: MoviesResource
      RestApiId:
        Ref: MoviesApi
      Integration:
        Type: "AWS"
        Uri:
          Fn::Join:
            - ""
            - - "arn:aws:apigateway:"
              - !Ref "AWS::Region"
              - ":lambda:path/"
              - "/2015-03-31/functions/"
              - Fn::GetAtt:
                - DeleteMovie
                - Arn
              - "/invocations"
        IntegrationHttpMethod: "DELETE"
  UpdateMovieMethod:
    Type: "AWS::ApiGateway::Method"
    Properties:
      HttpMethod: "PUT"
      AuthorizationType: "NONE"
      ResourceId:
        Ref: MoviesResource
      RestApiId:
        Ref: MoviesApi
      Integration:
        Type: "AWS"
        Uri:
          Fn::Join:
            - ""
            - - "arn:aws:apigateway:"
              - !Ref "AWS::Region"
              - ":lambda:path/"
              - "/2015-03-31/functions/"
              - Fn::GetAtt:
                - UpdateMovie
                - Arn
              - "/invocations"
        IntegrationHttpMethod: "PUT"
  ListMoviesMethod:
    Type: "AWS::ApiGateway::Method"
    Properties:
      HttpMethod: "GET"
      AuthorizationType: "NONE"
      ResourceId:
        Ref: MoviesResource
      RestApiId:
        Ref: MoviesApi
      Integration:
        Type: "AWS"
        Uri:
          Fn::Join:
            - ""
            - - "arn:aws:apigateway:"
              - !Ref "AWS::Region"
              - ":lambda:path/"
              - "/2015-03-31/functions/"
              - Fn::GetAtt:
                - FindAllMovies
                - Arn
              - "/invocations"
        IntegrationHttpMethod: "GET"

  DynamoDBTable:
    Type: "AWS::DynamoDB::Table"
    Properties:
      TableName: !Ref TableName
      AttributeDefinitions:
        -
          AttributeName: "ID"
          AttributeType: "S"
      KeySchema:
        -
          AttributeName: "ID"
          KeyType: "HASH"
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
```

1.  为通过本书构建的无服务器 API 创建 Terraform 模板。

**答案**：为了避免代码重复，并保持模板文件的清晰和易于遵循和维护，可以使用“循环”，“条件”，“映射”和“列表”来创建已定义的 Lambda 函数的 IAM 角色：

```go
resource "aws_iam_role" "roles" {
  count = "${length(var.functions)}"
  name = "${element(var.functions, count.index)}Role"
  assume_role_policy = "${file("policies/assume-role-policy.json")}"
}

resource "aws_iam_policy" "policies" {
  count = "${length(var.functions)}"
  name = "${element(var.functions, count.index)}Policy"
  policy = "${file("policies/${element(var.functions, count.index)}-policy.json")}"
}

resource "aws_iam_policy_attachment" "policy-attachments" {
  count = "${length(var.functions)}"
  name = "${element(var.functions, count.index)}Attachment"
  roles = ["${element(aws_iam_role.roles.*.name, count.index)}"]
  policy_arn = "${element(aws_iam_policy.policies.*.arn, count.index)}"
}
```

可以应用相同的方法来创建所需的 Lambda 函数：

```go
resource "aws_lambda_function" "functions" {
  count = "${length(var.functions)}"
  function_name = "${element(var.functions, count.index)}"
  handler = "main"
  filename = "functions/${element(var.functions, count.index)}.zip"
  runtime = "go1.x"
  role = "${element(aws_iam_role.roles.*.arn, count.index)}"

  environment {
    variables {
      TABLE_NAME = "${var.table_name}"
    }
  }
}
```

最后，可以按以下方式创建 RESTful API：

```go
resource "aws_api_gateway_rest_api" "api" {
  name = "MoviesAPI"
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  parent_id = "${aws_api_gateway_rest_api.api.root_resource_id}"
  path_part = "movies"
}

resource "aws_api_gateway_deployment" "staging" {
  depends_on = ["aws_api_gateway_integration.integrations"]

  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  stage_name = "staging"
}

resource "aws_api_gateway_method" "proxies" {
  count = "${length(var.functions)}"
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_resource.proxy.id}"
  http_method = "${lookup(var.methods, element(var.functions, count.index))}"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "integrations" {
  count = "${length(var.functions)}"
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${element(aws_api_gateway_method.proxies.*.resource_id, count.index)}"
  http_method = "${element(aws_api_gateway_method.proxies.*.http_method, count.index)}"

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = "${element(aws_lambda_function.functions.*.invoke_arn, count.index)}"
}

resource "aws_lambda_permission" "permissions" {
  count = "${length(var.functions)}"
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = "${element(aws_lambda_function.functions.*.arn, count.index)}"
  principal = "apigateway.amazonaws.com"

  source_arn = "${aws_api_gateway_deployment.staging.execution_arn}/*/*"
}
```
