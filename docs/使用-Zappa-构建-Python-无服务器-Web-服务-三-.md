# 使用 Zappa 构建 Python 无服务器 Web 服务（三）

> 原文：[`zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09`](https://zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：带 SSL 的自定义域

在本章中，我们将为上一章开发的报价应用程序配置自定义域。配置自定义域是将应用程序移动到生产环境的重要部分，因为它是无服务器的。这个过程涉及多个操作，与传统的 Apache 或 NGINX 配置不同。我们将查看已部署在无服务器基础架构中的报价应用程序。

本章我们将涵盖的主题包括：

+   使用 AWS Route53 配置自定义域

+   使用 Amazon 证书管理器生成 SSL 证书

+   使用 Zappa 集成自定义域

# 技术要求

在开始本章之前，有一些先决条件需要满足。我们将使用一些 AWS 服务和一个真实的域名。因此，您将需要以下内容：

+   Ubuntu 16.04/Windows/macOS

+   Pipenv 工具

+   Zappa 和其他 Python 开发包

+   注册域名

+   AWS 账户

我们将使用一些 Python 包，这些包在后面的部分中提到。除了开发环境，您还需要拥有自己注册的域名和更新其默认域名服务器的权限。让我们转到下一节，在那里我们将探索与 AWS Route 53 的域名服务器配置。

# 使用 AWS Route 53 配置自定义域

为我们的应用程序创建自定义域需要拥有一个域。域名可以从域名注册商那里购买。在我们的情况下，我从**GoDaddy**([`in.godaddy.com/`](https://in.godaddy.com/))，这个**域名系统**(**DNS**)服务提供商那里购买了一个名为`abdulwahid.info`的域名。

每个域通过 DNS 服务提供商管理的域名服务器在互联网上提供服务。有许多服务提供商提供服务，可以从他们的端口管理和托管网站。我们将使用 AWS Route 53 服务。

# 什么是 AWS Route 53？

AWS Route 53 是一种可扩展的云 DNS 网络服务。Route 53 在配置与任何 AWS 服务的域名方面非常有效。它连接到在 AWS 上运行的基础架构以及 AWS 之外的基础架构。Route 53 提供各种路由，如基于延迟的路由、地理 DNS、地理近似和加权轮询。所有这些路由可以组合在一起，以提供低延迟带宽。Route 53 还提供域名注册服务。如果我们在 AWS Route 53 上注册域名，那么我们就不需要管理 DNS 配置。所有 DNS 配置将自动使用 AWS 服务。

但我们没有在 Route 53 上注册我们的域，所以我们需要用 Route 53 替换默认的 GoDaddy 域名服务器。在下一节中，我们将讨论如何更改域名服务器。

# 将域名服务器更改为 Route 53

我们将把现有域的控制权转移到 Route 53。这个过程需要将域名`abdulwhaid.info`的默认域名服务器更改为 Route 53 创建的新域名服务器。

参考 AWS 官方文档([`docs.aws.amazon.com/Route53/latest/DeveloperGuide/CreatingHostedZone.html`](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/CreatingHostedZone.html))关于在不同的注册商上为 Route 53 配置现有域名创建托管区域，执行以下步骤：

1.  登录 AWS 控制台，在[`console.aws.amazon.com/route53/.`](https://console.aws.amazon.com/route53/)打开 Route 53 控制台

1.  如果您是 Route 53 的新用户，请在 DNS 管理下选择立即开始**。**

1.  如果您已经使用 Route 53，请在左侧导航窗格中选择托管区域，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00076.jpeg)

1.  现在，从托管区域页面，点击使用域`abdulwahid.info`创建托管区域，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00077.jpeg)

1.  一旦您为域名 `abdulwahid.info` 创建了托管区域，Route 53 将创建两个记录，**域名服务器** (**NS**) 和 **授权起始** (**SOA**)，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00078.jpeg)

1.  现在，我们需要使用 NS 记录并替换在域名注册商（即 GoDaddy）生成的默认 NS 记录，在那里我们创建了域名 `abdulwahid.info`。以下是默认 NS 记录的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00079.jpeg)

1.  将默认 NS 更改为自定义，并输入在 Route 53 生成的 NS 记录，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00080.jpeg)

1.  单击保存，我们完成了。现在需要一些时间由域名注册商处理。您将收到来自域名注册商的确认电子邮件。

Route 53 通过特定域名的托管区域管理路由流量。托管区域就像一个容器，包含有关域名的信息，并知道如何在互联网上路由流量。

一旦您收到确认电子邮件，域名 `abdulwahid.info` 将由 Route 53 管理。让我们转到下一节，了解如何使用 AWS 证书管理器配置 SSL 证书。

# 使用 AWS 证书管理器生成 SSL 证书

SSL 为您的 Web 服务器和应用程序用户提供安全性。借助 SSL，您可以防止黑客对在 Web 服务器和浏览器之间通信的数据进行攻击。在将 SSL 安全性应用到我们的应用程序之前，让我们了解一些关于 SSL 的基本方法。

# SSL 是什么？

**SSL** (**安全套接字层**) 是一种标准的安全协议，用于通过加密数据保护 Web 服务器和浏览器之间的通信。SSL 将确保从浏览器传输到您的 Web 服务器的数据是加密的。为了创建 SSL 连接，我们需要生成 SSL 证书并配置我们的 Web 服务器以在 SSL 层下提供服务。下一节将讨论 SSL 证书。

# 什么是 SSL 证书？

为了创建 SSL 连接，我们需要一个 SSL 证书。SSL 证书可以从 **证书颁发机构** (**CA**) 生成。在生成证书之前，我们需要提供有关我们的网站和业务详细信息。根据这些信息，将生成两个加密密钥：公钥和私钥。

现在，使用公钥和业务详细信息，我们需要与 CA 处理一个 **证书签名请求** (**CSR**)。一旦 CA 成功授权我们的详细信息，它将颁发与我们的私钥匹配的 SSL 证书。

现在，我们准备为我们的应用程序配置 SSL 证书。这是生成 SSL 证书的传统方式。但是我们将使用 Amazon 证书管理器来生成 SSL 证书。

# 使用 Amazon 证书管理器 (ACM) 生成 SSL 证书

有几种生成 SSL 证书的方法。以下是一些获取应用程序的 SSL/TSL 证书的方法：

+   您可以从 SSL 证书颁发机构购买 SSL 证书。

+   您可以通过使用 **Let's Encrypt** ([`letsencrypt.org/`](https://letsencrypt.org/)) 自行生成免费的 SSL/TSL 证书。Let's Encrypt 是一个提供免费 SSL/TSL 证书的开放式证书颁发机构。

+   您可以使用 **AWS 证书管理器** (**ACM**) 生成 SSL。我们将使用 ACM 为我们的应用程序生成 SSL 证书。

ACM 是一个管理和创建 AWS 服务和应用程序的 SSL/TSL 证书的服务。ACM 证书适用于多个域名和子域名。您还可以使用 ACM 创建通配符 SSL。

ACM 严格与 **AWS 证书管理器私有证书颁发机构** (**ACM PCA**) 相关联。ACM PCA 负责验证域名授权并颁发证书。

现在，我们将为我们的域和子域生成一个 ACM 证书。按照以下步骤创建 ACM 证书：

请注意，API Gateway 仅支持来自一个地区的 ACM 证书。因此，我们将使用**US East**地区。您可以在[`github.com/Miserlou/Zappa/pull/1142`](https://github.com/Miserlou/Zappa/pull/1142)上阅读更多信息。

1.  登录 AWS 控制台，在[`ap-south-1.console.aws.amazon.com/acm`](https://ap-south-1.console.aws.amazon.com/acm)打开 ACM 控制台。

1.  如果您是 AWS ACM 的新用户，请在“Provision certificates”下点击“Get Started”，如果您已经在使用 AWS ACM，请选择“Request a certificate”，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00081.jpeg)

在这里，我们将选择请求公共证书。

您可以在[`docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html`](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html)上阅读更多关于公共证书的信息。

1.  在下一页，您需要提供您的域名的详细信息。我们将使用通配符(*)作为子域名来针对我们的域请求一个通配符证书。因此，这个证书可以用来保护同一域名下的多个站点。以下是添加域名的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00082.jpeg)

1.  在下一页，您需要选择验证方法。有两种类型的方法可用，如下所示：

+   **DNS 验证：**此方法需要修改证书中域的 DNS 记录的权限，以便它可以直接验证记录集。

+   **电子邮件验证：**如果您没有权限修改 DNS 记录，则可以使用此方法。因此，您可以使用与域名注册商记录的注册电子邮件来验证域。

我们将使用 DNS 验证方法。这是因为我们拥有 Route 53 托管区中的 DNS 访问权限，这是因为在域名注册商处有映射的域名服务器。DNS 验证很简单。请看下面的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00083.jpeg)

1.  现在，我们已经准备好了。点击“Review”将显示所选的配置，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00084.jpeg)

1.  一旦您从“Review”页面点击“确认并请求”，您需要完成验证过程。下面的截图显示验证状态为待定，因此我们需要通过展开域部分来执行验证：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00085.jpeg)

1.  展开域部分后，您将看到一些完成验证过程的说明。我们选择了 DNS 验证方法。因此，这种方法需要向 DNS 配置添加一个 CNAME 记录。根据下面的截图，您可以通过点击“在 Route 53 中创建记录”按钮来执行更新 DNS 配置的操作，以给定的 CNAME：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00086.jpeg)

1.  一旦您点击了在 Route 53 中创建记录，它将弹出一个确认弹窗，显示 CNAME 记录，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00087.jpeg)

1.  点击“创建”按钮后，它会自动使用给定的 CNAME 记录更新 Route 53 中的 DNS 配置。您将看到成功消息，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00088.jpeg)

1.  点击“继续”，我们完成了。您将被重定向到证书仪表板页面，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00089.jpeg)

ACM CA 已成功为您的域颁发了 SSL 证书。正如您所看到的，绿色状态中显示了“已颁发”。现在，是时候配置域和证书与我们的应用程序了。在下一节中，我们将使用我们的报价 API 应用程序配置一个子域与已颁发的 SSL 证书。

# 使用 Zappa 集成自定义域

Zappa 支持自定义域名和子域集成与 SSL 证书。我们已经在前几节中讨论了 SSL/TSL 证书生成的来源。Zappa 可以使用以下 CA 部署域：

+   您自己从证书颁发机构提供商购买的 SSL

+   Let's Encrypt

+   AWS

您可以在以下链接中阅读有关使用上述 CA 部署域的更多详细信息：[`github.com/Miserlou/Zappa#ssl-certification`](https://github.com/Miserlou/Zappa#ssl-certification)。

我们将使用 AWS 证书颁发机构 SSL 证书。我们已经在上一节中生成了 ACM 证书。现在是时候将 ACM 证书与我们的应用程序的子域集成了。

让我们转到下一节，在那里我们将使用子域和 ACM 证书配置我们的报价 API 应用程序。

# 使用 ACM 证书部署到域

由于我们已经颁发了 ACM 证书，现在让我们将应用程序配置到所需的域并执行部署过程。Zappa 提供了一个`domain`属性来配置应用程序的域名和`certificate_arn`用于 ACM 证书。您需要在`zappa_settings.json`中配置这两个属性。

在此之前，我们需要获取`certificate_arn`的值，因为它是 ACM 为我们颁发证书的域生成的**ARN**（**Amazon 资源名称**）。您可以从 ACM 仪表板中展开域部分获取 ARN 的值，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00090.jpeg)

```py
zappa_settings.json.
```

文件—`zappa_settings.json`:

```py
{
    "dev": {
        "app_function": "resources.api",
        "aws_region": "ap-south-1",
        "profile_name": "default",
        "project_name": "chapter-8",
        "runtime": "python3.6",
        "s3_bucket": "zappa-0edixmwpd",
        "remote_env": "s3://book-configs/chapter-7-config.json",
        "cache_cluster_enabled": false,
        "cache_cluster_size": 0.5,
        "cache_cluster_ttl": 300,
        "cache_cluster_encrypted": false,
        "events": [{
           "function": "schedulers.set_quote_of_the_day",
           "expression": "cron(0 12 * * ? *)"
       }],
       "domain": "quote.abdulwahid.info",
 "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784"
    }
}
```

在这里，我们将域配置为`quote.abdulwahid.info`并设置`certificate_arn`。现在，让我们使用`zappa deploy <stage_name>`命令部署应用程序，因为我们是第一次部署应用程序。看一下以下代码：

```py
$ zappa deploy dev
Important! A new version of Zappa is available!
Upgrade with: pip install zappa --upgrade
Visit the project page on GitHub to see the latest changes: https://github.com/Miserlou/Zappa
Calling deploy for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter-7-dev-1529679507.zip (5.9MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 6.17M/6.17M [00:02<00:00, 2.27MB/s]
Scheduling..
Scheduled chapter-7-dev-schedulers.set_quote_of_the_day with expression cron(0 12 * * ? *)!
Scheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Uploading chapter-7-dev-template-1529679513.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 4.76KB/s]
Waiting for stack chapter-7-dev to create (this can take a bit)..
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00, 2.66s/res]
Deploying API Gateway..
Deployment complete!: https://5phr2bp4id.execute-api.ap-south-1.amazonaws.com/dev
```

如您所见，应用程序已部署在随机生成的 API 端点上。但是，为了配置应用程序，我们需要使用`zappa certify`命令将 API 网关与 ACM 证书关联起来，如下日志片段所示：

```py
$ zappa certify
Calling certify for stage dev..
Are you sure you want to certify? [y/n] y
Certifying domain quote.abdulwahid.info..
Created a new domain name with supplied certificate. Please note that it can take up to 40 minutes for this domain to be created and propagated through AWS, but it requires no further work on your part.
Certificate updated!
```

一旦运行`zappa certify`命令，它将创建并将 API 网关与配置的证书关联起来。

现在，让我们再次更新部署，使用`zappa update <stage_name>`命令，如下所示。

```py
$ zappa update dev
Important! A new version of Zappa is available!
Upgrade with: pip install zappa --upgrade
Visit the project page on GitHub to see the latest changes: https://github.com/Miserlou/Zappa
Calling update for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter-7-dev-1529679710.zip (5.9MiB)..
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 6.17M/6.17M [00:03<00:00, 863KB/s]
Updating Lambda function code..
Updating Lambda function configuration..
Uploading chapter-7-dev-template-1529679717.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 6.97KB/s]
Deploying API Gateway..
Scheduling..
Unscheduled chapter-7-dev-schedulers.set_quote_of_the_day.
Unscheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled chapter-7-dev-schedulers.set_quote_of_the_day with expression cron(0 12 * * ? *)!
Scheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://quote.abdulwahid.info (https://5phr2bp4id.execute-api.ap-south-1.amazonaws.com/dev)
```

就是这样。正如您所看到的，我们的应用程序现在在`https://quote.abdulwahid.info`上运行。现在，让我们在下一节中查看执行情况。

# 使用配置的域执行应用程序

我们已经在无服务器基础架构上部署和配置了我们的报价 API 应用程序。让我们使用 Postman API 客户端查看 API 执行。

# 每日报价 API

我们设计了这个 API（`https://quote.abdulwahid.info/quote?type=daily`）以每天返回一条报价。我们配置的调度程序将每天更新 UTC 时间表。看一下以下 cURL 日志片段：

```py
$ curl https://quote.abdulwahid.info/quote?type=daily
{"quote": "Many wealthy people are little more than janitors of their possessions.", "author": "Frank Lloyd Wright", "category": "Famous"}
```

# 随机报价 API

随机报价 API（`https://quote.abdulwahid.info/quote?type=random`）将在每次请求时返回一条随机报价。看一下以下 cURL 日志片段：

```py
$ curl https://quote.abdulwahid.info/quote?type=random
{"quote": "My mother thanks you. My father thanks you. My sister thanks you. And I thank you.", "author": "Yankee Doodle Dandy", "category": "Movies"}
```

就是这样。我们已成功在无服务器架构上部署了我们的应用程序。我们还配置了自定义域与我们的应用程序。这将用于测试目的。

# 总结

在本章中，我们学习了如何创建自定义域并配置域与 Route 53 集成。使用 Route 53，我们管理了域 DNS 配置。为了生成 SSL 证书，我们使用了 ACM，这很容易且直接。随后，我们使用生成的 ACM 证书的 ARN 配置了 Zappa 与域的集成。希望本章能帮助您了解为应用程序配置自定义域的机制。

现在我们要学习更多关于在 AWS Lambda 上安排任务和异步执行方法的知识。我们将进一步完善报价 API 应用程序，加入移动订阅模型。让我们为下一章做好准备，深入探讨使用 AWS Lambda 进行异步操作的世界。

# 问题

1.  AWS Route 53 是什么？

1.  域名服务器是什么意思？

1.  ACM 如何保护在 AWS Lambda 上托管的 API？


# 第九章：AWS Lambda 上的异步任务执行

在本章中，我们将介绍 AWS Lambda 上的异步任务执行。AWS Lambda 使自动缩放和异步执行变得非常容易实现。Zappa 可以帮助我们配置任务，以便它们在 AWS Lambda 上以异步方式执行。Zappa 实现了管理异步任务响应的功能。

本章我们将涵盖以下主题：

+   异步执行

+   使用 Zappa 进行 AWS Lambda 异步调用

+   使用异步功能配置 Quote API 应用程序

+   使用 Zappa 部署和执行 Quote API

# 技术要求

在开始本章之前，请确保满足应用程序的先决条件。以下是您需要满足的技术要求：

+   Ubuntu 16.04/Windows/macOS

+   Python3.6

+   Pipenv 工具

+   猎鹰框架

+   Zappa

+   注册域名

+   AWS 账户

本章增强了第八章中开发的应用程序，*带 SSL 的自定义域*。因此，一些要求可以从先前配置的先决条件中使用。让我们继续学习 AWS Lambda 中的异步执行。

# 异步执行

异步执行在开发高性能和优化的应用程序中起着重要作用。AWS Lambda 支持异步执行。有不同的方法来以异步模式执行 AWS Lambda 函数。

# 理解异步执行

**异步执行** 是在不阻塞用户干预的情况下执行特定代码块的过程。为了更好地理解它，考虑 jQuery Ajax 机制发送异步请求到服务器，而不会阻塞用户，并在回调方法中捕获成功响应或错误响应。看一下以下图表，以更好地理解：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00091.gif)

现在，您可以看到，一旦服务器从客户端获得异步请求，服务器立即返回确认的响应。一旦请求处理完成，将返回成功或失败的响应；否则，将不返回任何内容。

异步方法是否返回响应取决于要求。我们可能需要或不需要返回响应。如果我们希望返回响应，那么应该有一种机制来处理或捕获客户端端的响应。

类似地，AWS Lambda 函数可以以异步方式执行，这样我们就不会阻塞用户干预等待返回响应。有一些用例需要捕获以异步方式执行的 AWS Lambda 函数的响应。我们将在接下来的部分讨论捕获响应。

让我们看看 AWS Lambda 如何异步执行。

# 使用 Boto3 进行 AWS Lambda 异步执行

AWS Lambda 函数实际上就是云中的一个函数（一段代码）。函数可以同步或异步调用。为了在任何编程语言中实现异步执行，我们可以在单独的线程或进程中执行函数。例如，在 Python 中，有各种库可用于实现异步执行。同样，AWS Lambda 很好地支持异步执行。

让我们看一下以下代码片段：

```py
client = boto3.client('lambda')
response = client.invoke(
    FunctionName='string',
    InvocationType='Event'|'RequestResponse'|'DryRun',
    LogType='None'|'Tail',
    ClientContext='string',
    Payload=b'bytes'|file,
    Qualifier='string'
)
```

我们可以使用 Boto3 库调用 AWS Lambda 函数。上面的代码是 Lambda 客户端 `invoke` 方法的语法。您可以在 Boto3 的官方文档中了解更多关于 `invoke` 方法机制的信息：[`boto3.readthedocs.io/en/latest/reference/services/lambda.html#Lambda.Client.invoke`](http://boto3.readthedocs.io/en/latest/reference/services/lambda.html#Lambda.Client.invoke)。

Boto3 是一个组织良好、维护良好的 Python AWS SDK。它帮助开发人员使用 Python 与 AWS 服务进行交互。Zappa 也使用 Boto3 与 AWS 服务进行交互。

让我们简要解释一下`InvocationType`，它用于决定是以同步模式还是异步模式执行函数。如果您想以同步模式调用现有的 AWS Lambda 函数，那么可以选择`InvocationType`为`RequestResponse`，对于异步模式，可以选择`InvocationType`为`Event`。

以下代码是 Lambda 函数的异步执行示例：

```py
client = boto3.client('lambda')
response = client.invoke(
    FunctionName='MyFunction',
    InvocationType='Event'
)
```

就是这样。这将以异步模式调用 Lambda 函数。借助 Boto3，您可以异步执行 AWS Lambda 函数。现在让我们看看如何使用 Zappa 执行异步执行。

# AWS Lambda 使用 Zappa 进行异步调用

AWS Lambda 函数只是部署在 AWS Lambda 容器中的函数。因此，执行它只是调用一个函数。AWS 提供了各种调用方法。如何集成和配置调用以实现异步执行完全取决于您。我们已经在上一节中看到了如何使用 Boto3 SDK 进行异步执行。现在，我们将探索 Zappa 提供的各种调用方式。

# 使用任务装饰器进行异步 AWS Lambda 调用

Zappa 提供了一种超级简单的方式来配置 Lambda 执行为异步模式。Zappa 使用名为`zappa.async.task`的装饰器方法实现了异步执行。这个装饰器可以用于我们想要以异步模式执行的任何函数。以下是来自 Zappa 官方 GitHub 页面的示例（[`github.com/Miserlou/Zappa#asynchronous-task-execution`](https://github.com/Miserlou/Zappa#asynchronous-task-execution)）：

```py
from flask import Flask
from zappa.async import task
app = Flask(__name__)

@task
def make_pie():
    """ This takes a long time! """
    ingredients = get_ingredients()
    pie = bake(ingredients)
    deliver(pie)

@app.route('/api/order/pie')
def order_pie():
    """ This returns immediately! """
    make_pie()
    return "Your pie is being made!"
```

正如您所看到的，我们在`make_pie`方法上使用了`task`装饰器。现在，当您调用 API 时，它将立即返回响应，并以异步模式执行`make_pie`方法。以异步方式执行`make_pie`只是实例化具有`make_pie`方法执行上下文的 AWS Lambda 实例。这就是您可以异步执行函数的方式。现在，另一个挑战是收集异步执行函数的响应。我们将在接下来的部分讨论这个问题。

# Amazon SNS 作为任务来源

**Amazon Simple Notification Service**（**SNS**）是一种托管的发布/订阅消息服务。它支持各种协议，如 HTTP、HTTPS、电子邮件、电子邮件-JSON、Amazon SQS、应用程序、AWS Lambda 和短信。我们可以通过任何这些协议创建主题和订阅，尽管我们可以使用 AWS SNS 通过其 Web 控制台执行发布/订阅操作。

我们已经通过 API Gateway 调用了 AWS Lambda，这是我们所有实现的 API 都在工作的方式。同样，我们可以订阅我们的 AWS Lambda 与 Amazon SNS 的特定主题。现在，每当在该主题上发布任何消息时，它也会调用订阅的 AWS Lambda。

```py
task_sns decorator binding:
```

```py
from zappa.asycn import task_sns

@task_sns
def method_to_invoke_from_sns_event():
    pass

```

您还需要在`zappa_settings.json`文件中更新以下设置：

```py
{
  "dev": {
    ..
      "async_source": "sns",
      "async_resources": true,
    ..
    }
}
```

当您调用`zappa schedule`命令时，它将自动创建并订阅 SNS。通过 SNS 主题发布的任何消息都会创建一个唯一的消息 ID。因此，您可以使用生成的消息 ID 在 CloudWatch 日志中跟踪消息响应。

此功能使您能够使用 Lambda 调用来执行基于 SNS 事件的操作。例如，您可以使用它来开发一个**一次性密码**（**OTP**）生成应用程序，其中您不需要持久化 OTP 数据。相反，它将被发布到特定主题，订阅者将获得该信息。最后，AWS Lambda 和手机号码可以订阅 AWS SNS 主题。这将调用 AWS Lambda 方法，并使用 SNS 主题上发布的消息上下文。

让我们在下一节中看一下直接调用方法。

# 直接调用

Zappa 提供了另一种执行 Lambda 函数的直接调用的机制。以前，我们一直在使用`task`和`task_sns`装饰器，但现在我们将使用`zappa.async.run`方法来执行直接调用。

```py
zappa.async.run method being used:
```

```py
from zappa.async import run

# Invoking a method in async mode using Lambda
run(method_name_to_invoke, args, kwargs)

# Invoking a method in async mode using SNS
run(method_name_to_invoke, args, kwargs, service="sns")
```

此功能将帮助您根据您的要求动态配置`async`调用。装饰器任务方法从编译中固定，但此方法语句可以在运行时有条件地调用。

# 远程调用

默认情况下，Zappa 执行当前 Lambda 实例的直接调用方法。但是，如果您希望在不同区域上将 Lambda 调用作为单独的 Lambda 函数执行，则可以更新您的任务装饰器，如下面的代码片段所示：

```py
@task(remote_aws_lambda_function_name='subscribe-mobile-prod', remote_aws_region='us-east-1')
def subscribe_mobile_number(*args, **kwargs):
   """ This may take a long time! """
   validate(kwargs.get("mobile"))
   add_subscription(mobile=kwargs.get("mobile"))
```

我们正在使用`task`装饰器，但带有额外的参数，例如**`remote_aws_lambda_function_name`**和**`remote_aws_region`**。这些参数说明在特定区域执行特定 Lambda 函数。这就是您可以执行**远程调用**的方式。

让我们通过这些不同类型的调用来增强 Quote API 应用程序，以实现异步执行。

# 配置带有异步功能的 Quote API 应用程序

在上一章中，我们创建了一个 Quote API 并配置了自定义域。现在我们将增强和优化现有的应用程序。我们将添加一些新功能到应用程序中，以演示不同类型的调用。

我们将使用现有的代码库作为一个不同的项目，因此最好将现有的代码库复制到一个新目录中；在我们的情况下，我们将`Chapter08`代码库复制为`Chapter09`；但是，您需要更新`zappa_settings.json`文件。在即将到来的部分中，我们将介绍 Zappa 设置更改。

# 使用 Amazon SNS 进行每日报价的短信订阅

我们将添加每日接收报价的短信订阅的新功能。这将要求我们使用 Boto3 库配置 Amazon SNS。Boto3 是一个完整的 Python SDK 库，使我们能够以编程方式与 AWS 服务进行交互。让我们继续并在下一节中配置 Amazon SNS。

# 使用 Boto3 配置 Amazon SNS

您需要满足先决条件并遵循上一章中详细说明的安装说明，其中我们使用 Boto3 和其他所需的库配置了环境。假设您已经配置了环境，我现在将继续探索配置。

让我们来看一下以下代码片段：

```py
client = boto3.client('sns',
            aws_access_key_id= os.environ['aws_access_key_id'],
            aws_secret_access_key= os.environ['aws_secret_access_key'],
            region_name= 'us-east-1')
```

正如您所看到的，我们正在使用 Boto3 创建 Amazon SNS 的客户端对象。我们需要访问密钥凭据以便以编程方式获取访问权限。

这是与 Amazon SNS 连接时的重要步骤。一旦成功创建了`client`对象，您可以执行各种操作，例如创建主题，使用协议订阅服务以及在主题上发布消息。

让我们朝着使用 Amazon SNS 实现短信订阅的实际实现迈进。

# 实现短信订阅功能

```py
models.py class with along with OTPModel class:
```

```py
import os
import datetime
from shutil import copyfile
from peewee import *

# Copy our working DB to /tmp..
db_name = 'quote_database.db'
src = os.path.abspath(db_name)
dst = "/tmp/{}".format(db_name)
copyfile(src, dst)

db = SqliteDatabase(dst)

class QuoteModel(Model):

    class Meta:
        database = db

    id = IntegerField(primary_key= True)
    quote = TextField()
    author = CharField()
    category = CharField()
    created_at = DateTimeField(default= datetime.date.today())

class OTPModel(Model):

    class Meta:
        database = db

    id = IntegerField(primary_key= True)
    mobile_number = CharField()
    otp = IntegerField()
    is_verified = BooleanField(default=False)
    created_at = DateTimeField(default= datetime.date.today())

db.connect()
db.create_tables([QuoteModel, OTPModel])
QuoteSubscription class.
```

文件-`sns.py`：

```py
import os
import re
import boto3

class QuoteSubscription:

    def __init__(self):
        """
        Class constructor to initialize the boto3 configuration with Amazon SNS.
        """
        self.client = boto3.client(
            'sns',
            aws_access_key_id=os.environ['aws_access_key_id'],
            aws_secret_access_key=os.environ['aws_secret_access_key'],
            region_name='us-east-1')
        topic = self.client.create_topic(Name="DailyQuoteSubscription")
        self.topic_arn = topic['TopicArn']

    def subscribe(self, mobile):
        """
        This method is used to subscribe a mobile number to the Amazon SNS topic.
        Required parameters:
            :param mobile: A mobile number along with country code.
            Syntax - <country_code><mobile_number>
            Example - 919028XXXXXX
        """
        assert(bool(re.match("^(\+\d{1,3}?)?\d{10}$", mobile))), 'Invalid mobile number'
        self.client.subscribe(
            TopicArn=self.topic_arn,
            Protocol='sms',
            Endpoint=mobile,
        )

    def unsubscribe(self, mobile):
        """
        This method is used to unsubscribe a mobile number from the Amazon SNS topic.
        Required parameters:
            :param mobile: A mobile number along with country code.
            Syntax - <country_code><mobile_number>
            Example - 919028XXXXXX
        """
        assert(bool(re.match("^(\+\d{1,3}?)?\d{10}$", mobile))), 'Invalid mobile number'
        try:
            subscriptions = self.client.list_subscriptions_by_topic(TopicArn=self.topic_arn)
            subscription = list(filter(lambda x: x['Endpoint']==mobile, subscriptions['Subscriptions']))[0]
            self.client.unsubscribe(
                SubscriptionArn= subscription['SubscriptionArn']
            )
        except IndexError:
            raise ValueError('Mobile {} is not subscribed.'.format(mobile))

    def publish(self, message):
        """
        This method is used to publish a quote message on Amazon SNS topic.
        Required parameters:
            :param message: string formated data.
        """
        self.client.publish(Message=message, TopicArn=self.topic_arn)

    def send_sms(self, mobile_number, message):
        """
        This method is used to send a SMS to a mobile number.
        Required parameters:
            :param mobile_number: string formated data.
            :param message: string formated data.
        """
        self.client.publish(
            PhoneNumber=mobile_number,
            Message=message
        )
```

这个类有一个用于执行移动号码订阅功能的方法。为了演示异步执行，我们将明确编写一些函数，这些函数将使用`QuoteSubscription`功能。

让我们创建一个名为`async.py`的文件，其中包含以下代码片段：

```py
import random
from zappa.async import task
from sns import QuoteSubscription
from models import OTPModel

@task
def async_subscribe(mobile_number):
    quote_subscription = QuoteSubscription()
    quote_subscription.subscribe(mobile=mobile_number)

@task
def async_unsubscribe(mobile_number):
    quote_subscription = QuoteSubscription()
    quote_subscription.unsubscribe(mobile=mobile_number)

@task
def async_publish(message):
    quote_subscription = QuoteSubscription()
    quote_subscription.publish(message=message)

@task
def async_send_otp(mobile_number):
    otp = None
    quote_subscription = QuoteSubscription()
    data = OTPModel.select().where(OTPModel.mobile_number == mobile_number, OTPModel.is_verified == False)
    if data.exists():
        data = data.get()
        otp = data.otp
    else:
        otp = random.randint(1000,9999)
        OTPModel.create(**{'mobile_number': mobile_number, 'otp': otp})
    message = "One Time Password (OTP) is {} to verify the Daily Quote subscription.".format(otp)
    quote_subscription.send_sms(mobile_number=mobile_number, message=message)
```

正如您所看到的，我们定义了这些方法并添加了`@task`装饰器。在本地环境中，它将以正常方法执行，但在 AWS Lambda 上下文中，它将以异步模式执行。

让我们移动到资源 API 实现。我们将稍微修改现有资源。将会有一些与短信订阅相关的新 API。

文件-`resources.py`：

```py
import os
import re
import datetime
import requests
import falcon
import boto3

from models import QuoteModel, OTPModel
from mashape import fetch_quote
from async import async_subscribe, async_unsubscribe, async_send_otp

class DailyQuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        try:
            data = QuoteModel.select().where(QuoteModel.created_at == datetime.date.today())
            if data.exists():
                data = data.get()
                resp.media = {'quote': data.quote, 'author': data.author, 'category': data.category}
            else:
                quote = fetch_quote()
                QuoteModel.create(**quote)
                resp.media = quote
        except Exception as e:
            raise falcon.HTTPError(falcon.HTTP_500, str(e))

class SubscribeQuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        try:
            mobile_number = '+{}'.format(req.get_param('mobile'))
            otp = req.get_param('otp')
            otp_data = OTPModel.select().where(OTPModel.mobile_number == mobile_number, OTPModel.otp == otp, OTPModel.is_verified == False)
            if mobile_number and otp_data.exists():
                otp_data = otp_data.get()
                otp_data.is_verified = True
                otp_data.save()
                async_subscribe(mobile_number)
                resp.media = {"message": "Congratulations!!! You have successfully subscribed for daily famous quote."}
            elif mobile_number and not otp_data.exists():
                async_send_otp(mobile_number)
                resp.media = {"message": "An OTP verification has been sent on mobile {0}. To complete the subscription, Use OTP with this URL pattern https://quote-api.abdulwahid.info/subscribe?mobile={0}&otp=xxxx.".format(mobile_number)}
            else:
                raise falcon.HTTPError(falcon.HTTP_500, 'Require a valid mobile number as a query parameter. e.g https://<API_ENDPOINT>/subscribe?mobile=XXXXXXX')
        except Exception as e:
            raise falcon.HTTPError(falcon.HTTP_500, str(e))

class UnSubscribeQuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        try:
            mobile_number = '+{}'.format(req.get_param('mobile'))
            if mobile_number:
                async_unsubscribe(mobile_number)
                resp.media = {"message": "You have successfully unsubscribed from daily famous quote. See you again."}
        except Exception as e:
            raise falcon.HTTPError(falcon.HTTP_500, str(e))

api = falcon.API()
api.add_route('/daily', DailyQuoteResource())
api.add_route('/subscribe', SubscribeQuoteResource())
api.add_route('/unsubscribe', UnSubscribeQuoteResource())
```

在这里，我们使用了资源类创建了一些 API，如前面的代码片段中所述。每个资源类代表一个单独的 API 端点。因此，我们创建了三个 API 端点，每个端点都有自己的工作流执行和用法。

让我们按照以下方式探索每个 API 端点的用法：

+   `/daily`：此 API 端点旨在返回每日报价数据。

+   `/subscribe`：此 API 端点旨在订阅任何手机号以获取每日报价短信。在订阅任何手机号之前，它实现了一种 OTP 验证。因此，它遵循执行订阅操作的 URL 模式。订阅需要两个步骤，例如生成订阅的 OTP，然后验证 OTP 以确认订阅。要生成订阅的 OTP，您需要使用带有`mobile`查询参数的 API，例如`http://localhost:8000/subscribe?mobile=919028XXXX`，要进行订阅确认，您需要使用带有`mobile`和`otp`参数的 API，例如`http://localhost:8000/subscribe?mobile=919028790411&otp=XXXX`。

+   `/unsubscribe`：此 API 端点旨在取消现有订阅的手机号。

API 查询参数已定义模式，因此您需要使用这些模式进行有效参数。对于 mobile 参数，您应该以`<country_code><mobile_number>`的格式发送手机号码。对于`opt`参数，您应该发送 4 位整数。

```py
SubscribeQuoteResource and UnSubscribeQuoteResource classes are using async methods to perform the mobile number subscription and unsubscription operations. This would all be executed in asynchronous mode on AWS Lamda.
```

现在让我们继续部署应用程序，然后我们将了解其执行过程。

# 使用 Zappa 部署和执行 Quote API

部署是任何 Web 应用程序的重要部分。我们有幸拥有 Zappa 和 AWS Lambda，它们为我们提供了无服务器的本质。由于我们正在增强上一章中创建的 Quote API 应用程序，因此根据我们当前的需求，将进行一些修改。

在接下来的部分中，我们将讨论 Zappa 设置的一些更改。

# 设置虚拟环境

如前所述，我们正在使用`Chapter08`代码库。在`zappa_settings.json`文件中需要进行一些修改，例如将`project_name`更改为`Chapter09`，如下面的代码片段所示：

```py
{
...
"project_name": "chapter-9"
...
}
```

一旦您更改了`project_name`，您需要使用`pipenv install`命令来配置虚拟环境。这将创建一个带有更改的`project_name`的新虚拟环境。

我们正在使用 Boto3 库与 Amazon SNS 进行交互。因此，我们还需要使用`pipenv install boto3`命令安装 Boto3。

# 设置环境变量

除了虚拟环境之外，我们还需要配置一些环境变量。我们正在使用 Mashape API（第三方 API 市场）和 Boto3 库。因此，我们将使用 Mashape API 密钥和我们的 AWS 访问凭据配置环境变量。

Zappa 提供了几种配置环境变量的机制。我们将使用`"remote_env"`。这种方法需要在 S3 存储桶上上传一个 JSON 文件。

以下是配置的 JSON 文件的代码片段：

```py
{
    "Mashape_API_Endpoint" : "https://XXXXXXXXXXXXXX",
    "X_Mashape_Key": "XXXXXXXXXXXXXXXXXXXXXXXXX",
    "aws_access_key_id" : "XXXXXXXXXXXXX",
    "aws_secret_access_key" :"XXXXXXXXXXXXXXXXXXXXXXXXXXXx"
}
```

一旦您将此文件上传到 S3 存储桶，您可以将此文件的 S3 路径用作`"remote_env"`的值，如下面的代码片段所示：

```py
{
...
"remote_env": "s3://book-configs/chapter-9-config.json",
...
}
```

Zappa 将根据此 JSON 文件自动设置环境变量。

AWS 和其他 API 凭据是机密和敏感数据；因此，您必须避免在公共 Git 存储库中提交这些数据。借助`remove_env`，您可以将凭据设置为 AWS Lambda 上的环境变量，并将其全部安全地保存在 S3 上。

# 添加具有 SSL 的自定义域

是时候为 Quote API 应用程序的增强版本配置特定的域了。Zappa 提供了一个名为`domain`的关键字，用于在文件设置中设置您的域名。

以下是配置域的代码片段：

```py
{
    ...
    "domain": "quote-api.abdulwahid.info",
    ...
}
```

一旦您配置了域名，就需要使用 SSL 证书对其进行认证。我们已经使用**Amazon Certificate Manager** (**ACM**)生成了通配符 SSL 证书。因此，我们将使用相同的 ACM ARN，如下面的代码所示：

```py
{
    ...
    "domain": "quote-api.abdulwahid.info",
    "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784"
    ...
}
```

现在您需要运行`zappa certify`命令，以创建子域并配置证书。看一下以下日志片段：

```py
$ zappa certify
Calling certify for stage dev..
Are you sure you want to certify? [y/n] y
Certifying domain quote-api.abdulwahid.info..
Created a new domain name with supplied certificate. Please note that it can take up to 40 minutes for this domain to be created and propagated through AWS, but it requires no further work on your part.
Certificate updated!
```

如前面的日志片段所示，这个域名可能需要 40 分钟才能在 AWS 中创建和传播，但您无需再做任何工作。

让我们转到下一部分，在那里我们将为所有手机订阅者配置一个发布报价短信的事件。

# 安排事件发布短信

我们将每天向所有短信订阅者发送报价短信。短信订阅功能已经使用 Amazon SNS 和`QuoteSubscription`类实现。我们将在接下来的部分详细解释订阅工作流程。但在执行订阅之前，我们应该有一个配置和计划的事件，将在 SNS 主题上发布报价。

我们已经在`QuoteSubscription`构造函数中创建了 SNS 主题。此外，我们在`async.py`文件中编写了一个`async`方法`async_publish`。现在我们将使用这个方法异步发送报价消息。

为了保持模块化的代码库，我们创建了一个`schedulers.py`文件，将所有调度方法放在一个地方。

```py
schedulers.py:
```

```py
from models import QuoteModel
from mashape import fetch_quote
from sns import QuoteSubscription
from async import async_publish

def set_quote_of_the_day(event, context):
    QuoteModel.create(**fetch_quote())

def publish_quote_of_the_day(event, context):
    quote = fetch_quote()
    async_publish(message=quote['quote'])
```

正如我们在上一章中已经创建了一个调度方法`set_quote_of_the_day`，现在我们需要创建一个名为`publish_quote_of_the_day`的方法，负责在 Amazon SNS 主题上发布报价消息。

```py
zappa_settings.json file:
```

```py
{
    ...
    "events": [
       ...,
       {
 "function": "schedulers.publish_quote_of_the_day",
 "expression": "cron(0 12 * * ? *)"
 }],
    ...
}
```

我们配置了调度方法，使用`cron`表达式每天在 UTC 时间的凌晨 2:00 执行（**协调世界时**），这将是 IST 时间的上午 7:30（**印度标准时间**）。因此，印度的所有订阅者将在早晨收到短信。您可以根据自己的需求安排`cron`表达式。

当我们创建`QuoteSubscription`类的实例时，它会创建一个 SNS 主题，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00092.jpeg)

您的手机上可能已启用**免打扰**（**DND**）。DND 适用于促销短信。因此，在这种情况下，您可以更改文本消息首选项部分中的默认消息类型，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00093.jpeg)

```py
zappa_settings.json file:
```

```py
{
    "dev": {
        "app_function": "resources.api",
        "aws_region": "ap-south-1",
        "profile_name": "default",
        "project_name": "chapter-9",
        "runtime": "python3.6",
        "s3_bucket": "zappa-0edixmwpd",
        "remote_env": "s3://book-configs/chapter-9-config.json",
        "cache_cluster_enabled": false,
        "cache_cluster_size": 0.5,
        "cache_cluster_ttl": 300,
        "cache_cluster_encrypted": false,
        "events": [{
           "function": "schedulers.set_quote_of_the_day",
           "expression": "cron(0 12 * * ? *)"
       },
       {
        "function": "schedulers.publish_quote_of_the_day",
        "expression": "cron(0 2 * * ? *)"
        }],
       "domain": "quote-api.abdulwahid.info",
       "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784"
    }
}
```

就这样，我们已经完成了配置域名与 Quote API 应用程序！现在我们将使用配置的域名来访问 API。

# 部署

Zappa 部署需要`zappa_settings.json`文件，该文件生成`zappa init`命令。但我们已经有了`zappa_setttings.json`文件，所以不需要再次运行此命令。

如果您是第一次部署应用程序，您需要使用`zappa deploy <stage_name>`，如果应用程序已经部署，则需要使用`zappa update <stage_name>`。

```py
zappa update command:
```

```py
$ zappa update dev
Important! A new version of Zappa is available!
Upgrade with: pip install zappa --upgrade
Visit the project page on GitHub to see the latest changes: https://github.com/Miserlou/Zappa
Calling update for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter-9-dev-1528709561.zip (5.9MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 6.17M/6.17M [00:02<00:00, 2.21MB/s]
Updating Lambda function code..
Updating Lambda function configuration..
Uploading chapter-9-dev-template-1528709612.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 17.0KB/s]
Deploying API Gateway..
Scheduling..
Unscheduled chapter-9-dev-schedulers.set_quote_of_the_day.
Unscheduled chapter-9-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled chapter-9-dev-schedulers.set_quote_of_the_day with expression cron(0 12 * * ? *)!
Scheduled chapter-9-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://quote-api.abdulwahid.info (https://5ldrsesbc4.execute-api.ap-south-1.amazonaws.com/dev)
```

哇！我们成功部署了 Quote API 应用程序！现在您可以看到配置的域名已经与 Quote API 应用程序一起运行。

让我们转到下一部分，在那里我们将看到 Quote API 应用程序的执行情况。

# 报价 API 执行

我们将使用`curl`命令行工具（[`curl.haxx.se/`](https://curl.haxx.se/)）。它使得从命令行与任何 HTTP/HTTPS 链接进行交互变得非常容易。（尽管开发人员更倾向于在编写 Shell 脚本时更多地使用它。）让我们看看每个 API 的执行情况。

# 每日报价 API

```py
curl command execution:
```

```py
$ curl https://quote-api.abdulwahid.info/daily
{"quote": "May the Force be with you.", "author": "Star Wars", "category": "Movies"}
```

# 每日报价短信订阅

我们已经集成了 Amazon SNS 来实现短信订阅功能。我们设计了 API `/subscribe?mobile=<mobile_number>&otp=<otp_code>` 用于在注册的手机上获取每日报价消息的订阅。

以下是日志片段，显示了订阅 API 的执行情况：

```py
$ curl https://quote-api.abdulwahid.info/subscribe?mobile=919028XXXXXX
{"message": "An OTP verification has been sent on mobile +919028XXXXXX. To complete the subscription, Use OTP with this URL pattern https://quote-api.abdulwahid.info/subscribe?mobile=+919028XXXXXX&otp=XXXX."}

$ curl https://quote-api.abdulwahid.info/subscribe?mobile=919028XXXXXX&otp=XXXX
{"message": "Congratulations!!! You have successfully subscribed for daily famous quote."}
```

就是这样！我们已经安排了一个事件来发布每日报价消息到相关的 SNS 主题，这将广播到所有订阅。因此，订阅者现在将每天收到一条报价短信。一旦你调用这个 API，它就会创建一个 SNS 订阅。以下是亚马逊 SNS 网络控制台的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00094.jpeg)

你可以看到已经创建了一个订阅记录。现在在每条发布的消息上，这个订阅将接收到已发布的消息。

# 每日报价短信取消订阅

取消订阅 API 将负责移除任何已订阅的手机号码。这个 API 的工作流程类似于`/subscribe` API，使用了非常接近`/subscribe?mobile=<mobile_number>`的东西。

```py
/unsubscribe API being executed:
```

```py
$ curl https://quote-api.abdulwahid.info/unsubscribe?mobile=919028XXXXxx
{"message": "You have successfully unsubscribed from daily famous quote. See you again."}
```

这将从亚马逊 SNS 订阅中移除相关的订阅。以下是取消订阅 API 执行后亚马逊 SNS 网络控制台的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00095.jpeg)

你可以看到原来的订阅已经被移除了，所以我们已经实现了短信订阅/取消订阅以及异步执行机制。

# 摘要

在本章中，我们学习了关于异步工作流及其用法。我们还详细探讨了使用 Zappa 异步调用 AWS Lambda 函数。为了演示异步 Lambda 函数的执行，我们实现了报价 API 应用程序以及短信订阅功能。希望你喜欢本章，并且对你有所帮助！

现在我们将看到一些高级的 Zappa 配置，以便利用 Zappa 的自动化流程来维护应用程序部署的能力。让我们为下一章做好准备，开始你的新冒险之旅。

# 问题

1.  什么是 AWS SNS？

1.  AWS Lambda 如何调用 SNS 主题？


# 第十章：高级 Zappa 设置

在本章中，我们将探索 Zappa 提供的各种设置和配置。这真的可以帮助您以高效的方式部署应用程序。因此，有各种设置来配置您的应用程序。这些设置与一些 AWS 服务及其功能和功能相关。我们将通过将它们应用到我们在第九章中开发的现有报价 API 应用程序来探索这些设置，*AWS Lambda 上的异步任务执行*。

在本章中，我们将涵盖以下主题：

+   保持服务器热

+   启用 CORS

+   处理更大的项目

+   启用 bash 编译

+   缓存未处理的异常

# 技术要求

在继续之前，有一些先决条件需要满足。为了满足先决条件，需要满足以下要求：

+   Ubuntu 16.04/Windows/macOS

+   Python 3.6

+   Pipenv 工具

+   Zappa

+   Falcon API

+   Python 包

+   注册域名

+   AWS 账户

一些先前配置的先决条件可以从第九章中使用，*AWS Lambda 上的异步任务执行*。这意味着您可以继续使用配置的域和 AWS 服务。您可能需要更新本章的 Zappa 设置文件。

让我们继续探索与报价 API 应用程序一起使用的其他设置。

# 保持服务器热

Zappa 启用了一个保持 AWS Lambda 处于热状态的功能。由于容器化，AWS Lambda 存在冷启动，因此 Lambda 需要您设置环境以执行函数。每当 AWS Lambda 收到请求时，它会实例化 Lambda 函数及其所需的环境，最终在完成请求后销毁实例。

这就是 AWS Lambda 的工作原理。因此，Zappa 使用 AWS CloudWatch 事件调度功能来实现此机制，以保持实例化的 Lambda 实例处于热状态。保持 Lambda 处于热状态就是每四分钟触发 CloudWatch 事件作为 ping 请求，以防止 Lambda 实例的销毁。

此功能默认启用，但如果要禁用此功能，则可以在 Zappa 设置的 JSON 文件中将`keep_warm`标志设置为`false`。

以下代码片段用于禁用保持热功能：

```py
{
    "dev": {
             ...
             "keep_warm": true/false
             ...
     }
}
```

在我们的情况下，我们希望保持默认设置不变，以便我们的应用程序始终处于热状态。让我们继续下一节，我们将探索其他有用的设置。

# 启用 CORS

**跨源资源共享**（**CORS**）是在相同域或不同托管域上提供 API 的重要部分。AWS API Gateway 提供了启用 CORS 功能的功能。一旦您在 API Gateway 上配置了 API 资源，您必须使用 API Gateway Web 控制台启用 CORS。在 API Gateway 资源上启用 CORS 需要您设置`OPTION`方法以及一些响应头，例如以下内容：

+   Access-Control-Allow-Methods

+   Access-Control-Allow-Headers

+   Access-Control-Allow-Origin

您可以查看 AWS 官方文档中有关在 API Gateway 中配置 CORS 的手动过程（[`docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html`](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html)）。

Zappa 通过使用名为`cors`的设置属性自动配置 API Gateway 资源的 CORS 过程，如下面的代码片段所述：

```py
{
    "dev": {
             ...
             "cors": true/false
             ...
     }
}
```

Zappa 将`cors`的默认值设置为`false`。如果要为 API 资源启用 CORS，则可以将其设置为`true`。它还支持添加响应头。

`"cors": true`与`"binary_support": true`不兼容。因此，您可以禁用 API 网关级别的 CORS，或者您可以添加应用程序级别的 CORS 功能。

如前所述，您也可以使用应用程序级别的 CORS。有许多库可用于集成 CORS，一些框架有很好的库，比如`django-cors-headers` ([`github.com/ottoyiu/django-cors-headers`](https://github.com/ottoyiu/django-cors-headers)) 和 Flask-CORS ([`github.com/corydolphin/flask-cors`](https://github.com/corydolphin/flask-cors))。

这就是配置 CORS 功能的全部内容。我更喜欢在应用程序级别启用 CORS，因为这样您可以更好地控制它。

# 处理更大的项目

在这一部分，我们将讨论如何处理 AWS Lamda 上的大型项目的过程。AWS Lambda 默认支持不同的代码输入类型。现在，我们将更详细地讨论这个功能，因为我们将向您展示如何通过 AWS Lambda 控制台和使用 Zappa 库来处理这个功能。

# 使用 AWS Lambda 控制台处理更大的项目

AWS Lambda 支持三种不同的代码输入类型——内联编辑代码、上传 ZIP 文件和从 Amazon S3 上传文件，如下面的 AWS Lambda 函数 Web 控制台的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00096.jpeg)

这种输入类型允许用户将他们的代码库放在 AWS Lambda 上。让我们详细说明一下：

+   使用这种输入类型，您可以通过 AWS Lambda 的 Web 控制台直接放置代码，就像前面的截图中提到的那样。借助其在线编辑器，您可以编写和执行代码。这可以用于小型代码库。

+   **上传 ZIP 文件**：AWS Lambda 支持上传代码库的.zip 文件。我们在第一章中讨论了代码库的构建打包，*Amazon Web Services for Serverless*。这个功能有一个关于文件大小的限制，因为它只支持 50MB 大小的文件上传，但对于大型项目有另一个选项。

+   **从 Amazon S3 上传文件**：这个功能允许用户将构建包上传到 Amazon S3 存储，无论大小。这意味着您可以通过其 S3 链接引用在 Amazon S3 上上传的构建包。

# 使用 Zappa 处理更大的项目

Zappa 在处理部署时考虑构建包大小。Zappa 只支持两种代码输入类型，即直接在 AWS Lambda 上上传.zip 文件和在 Amazon S3 上上传.zip 文件。

```py
zappa_settings.json file:
```

```py
{
    "dev": {
             ...
             "slim_handler": true/false
             ...
     }
}
```

如果项目大小超过 50MB，请将`"slim_handler"`设置为`true`。一旦设置了这个属性，Zappa 将自动将构建包上传到 Amazon S3 存储桶，并配置 AWS Lambda 处理程序函数以考虑来自 Amazon S3 存储桶的构建包。

# 启用 bash 标签编译

Bash 标签编译是命令行环境中的一个功能。通过按下*Tab*键，它将显示自动完成建议列表。Zappa 有许多命令，如果您将`Zappa`模块与 Python `argcomplete`模块注册，`zappa`命令将支持标签编译功能。

为了获得这个功能，您需要在系统或虚拟环境中安装`argcomplete` ([`github.com/kislyuk/argcomplete`](https://github.com/kislyuk/argcomplete)) 模块：

+   系统级安装：

```py
$ sudo apt update
$ sudo apt install python-argcomplete
```

+   虚拟环境安装：

```py
$ pip install argcomplete
```

一旦您配置了模块，那么您需要在全局级别激活 Python 的`argcomplete`模块。以下是激活全局 Python `argcomplete`模块的命令：

```py
$ activate-global-python-argcomplete
```

为了将`Zappa`模块与`argcomplete`注册，您需要在`~/.bashrc`文件中添加以下行：

```py
eval "$(register-python-argcomplete zappa)"
```

通过执行以下命令在当前终端上再次源化以立即生效：

```py
$ source ~/.bashrc
```

现在，一旦您将`Zappa`模块与`argcomplete`注册，Zappa 命令将在编译中可用。以下是 Zappa 命令编译的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00097.jpeg)

这就是您可以使用`argcomplete`来进行 Zappa 命令。然而，在部署过程中更加高效将会很有帮助。让我们继续下一节，我们将讨论捕获未处理异常。

# 捕获未处理异常

Zappa 提供了一个捕获未处理异常的功能。这将允许您处理未处理的异常，通过电子邮件、SNS 或其他来源发出警报通知。这取决于您的要求，但您可以选择任何来源来发出通知。这将非常有帮助，这样您就可以跟踪任何部署环境中出现的故障。

例如，如果我们想要向所有开发人员和 QA 工程师发送关于任何部署环境的批量电子邮件通知，Zappa 提供了一种简单的方法来配置捕获未处理异常的机制。借助`exception_handler`属性的帮助，您可以绑定一个异常处理程序方法，从中可以处理异常以发送批量电子邮件通知。

以下是 Zappa 设置文件的代码片段：

```py
{
    "dev": {
        ...
        "exception_handler": "your_module.unhandled_exceptions",
    },
    ...
}
```

在这里，异常处理程序是在一个模块中定义的方法。因此，让我们修改我们现有的项目，从第九章，*在 AWS Lambda 上执行异步任务*，添加异常处理程序。

```py
unhandled_exception method that we created in the Quote API application of  Chapter 9, *Asynchronous Task Execution on AWS Lambda.*
```

文件-`notify.py`：

```py
import os
import boto3

def unhandled_exceptions(e, event, context):
    client = boto3.client('sns', aws_access_key_id=os.environ['aws_access_key_id'],
                            aws_secret_access_key=os.environ['aws_secret_access_key'],
                            region_name='us-east-1')
    topic = client.create_topic(Name="UnhandledException")
    client.publish(Message={'exception': e, 'event': event}, TopicArn=topic['TopicArn'])
    return True # Prevent invocation retry
```

在这里，我们将异常和事件数据发布到订阅的电子邮件中的`"UnhandledException"`主题。

我们可以增强订阅以管理开发人员和 QA 工程师的电子邮件订阅列表。这就是这个功能在追踪未处理异常方面的真正帮助。我们希望这对于管理您的部署是有益的。

# 总结

在本章中，我们了解了 Zappa 的一些附加功能。这些功能使我们能够以非常高效的方式管理 DevOps 操作。我们还探讨了处理大型项目、实现 CORS 和管理未处理异常。希望您喜欢本章，并在应用程序中开始使用这些功能。

# 问题

1.  保持 AWS Lambda 处于热状态有什么用？

1.  CORS 是什么？

1.  大型项目的部署流程是什么？


# 第十一章：使用 Zappa 保护无服务器应用程序

在本章中，我们将学习如何保护部署在 AWS Lambda 上的基于 Python 的应用程序。在之前的章节中，我们学习了如何开发一个应用程序并将其部署到无服务器基础设施上使用 Zappa。Zappa 还支持多种机制，使您能够为应用程序实现安全层。保护应用程序免受未经授权的访问是任何 Web 应用程序的重要过程，但能够在无服务器基础设施上保护 Web 应用程序将更加有趣。

因此，我们将开发一个基于 API 的应用程序，并演示一些机制来保护它免受未经授权的访问。让我们继续并探索有关设置开发环境的详细信息。

在本章中，我们将涵盖以下主题：

+   实现随机引用 API

+   在 API Gateway 上启用安全端点

+   使用死信队列跟踪 AWS Lambda 的失败

+   使用 AWS X-Ray 分析 Zappa 应用程序

+   使用 AWS VPC 保护您的 Zappa 应用程序

# 技术要求

在本章中，我们将涵盖更多的 AWS 功能，以增强使用 Zappa 的安全层。在深入研究本章之前，请确保您已满足以下先决条件：

+   Ubuntu 16.04/macOS/Windows

+   Python 3.6

+   Pipenv 工具

+   AWS 账户

+   Gunicorn

+   Zappa

+   其他 Python 包

一旦您启用了开发环境，我们就可以继续并开发一个简单的基于 Falcon 的 API，以便在请求时生成一个随机引用。在接下来的章节中，我们将使用 Zappa 使用不同的机制和方法来保护这个 API。

# 实现随机引用 API

在这一部分，我们将创建一个 RESTful API，用于生成随机引用。这将包括基于 Falcon 的 API 实现与 Mashape API 集成，就像我们在第九章中所做的那样，*在 AWS Lambda 上执行异步任务*。这一次，我们不打算集成数据库，因为我们不想保留任何信息。这将是一个简单的 HTTP `GET` 请求到我们的 API，然后我们将使用 Mashape API 返回一个随机生成的引用的 JSON 响应。让我们在下一节中看一下先决条件。

# 先决条件

我希望您已经满足了先前提到的技术要求，并使用 pipenv 工具设置了开发环境。现在，您需要在**Mashape** API 市场（[`market.mashape.com/`](https://market.mashape.com/)）注册，我们将使用**Random Famous Quote** API（[`market.mashape.com/andruxnet/random-famous-quotes`](https://market.mashape.com/andruxnet/random-famous-quotes)）。一旦您获得了使用此 API 的凭据，我们就需要在我们的应用程序中对其进行配置。

我们将使用 Zappa 的`remote_env`功能从 AWS S3 文件中将这些凭据作为环境变量共享，因此您需要在 AWS S3 上上传一个 JSON 文件。

文件—`book-config`/`chapter-11-config.json`：

```py
{
    "Mashape_API_Endpoint" : "https://andruxnet-random-famous-quotes.p.mashape.com/",
    "X_Mashape_Key": "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}
```

一旦您将此文件上传到 S3 存储中，您可以在`zappa_settings.json`文件中使用`remote_env`功能。以下是带有`remote_env`配置的`zappa_settings.json`的示例：

```py
{
    "dev": {
        ...
        "remote_env": "s3://book-configs/chapter-11-config.json"
        ...
    }
}
```

一旦我们初始化 Zappa 进行部署，我们将添加这个设置。目前，您可以手动将这些凭据设置为环境变量，就像我们在这里所做的那样：

```py
$ export Mashape_API_Endpoint=https://andruxnet-random-famous-quotes.p.mashape.com/
$ export X_Mashape_Key=XXXXXXXXXXXXXXXXXX
```

现在，让我们继续下一节，在那里我们将实现用于生成随机引用数据的 RESTful API。

# 开发随机引用 API

既然我们已经讨论了 Mashape API 的配置，让我们编写一个代码片段来实现获取随机引用数据的功能。请看以下代码片段：

文件—`mashape.py`：

```py
import os
import requests

def fetch_quote():
    response = requests.get(
        os.environ.get('Mashape_API_Endpoint'),
        headers={
            'X-Mashape-Key': os.environ.get('X_Mashape_Key'),
            'Accept': 'application/json'
        }
    )
    if response.status_code == 200:
        return response.json()[0]
    return response.json() 
```

正如您所看到的，我们编写了一个名为`fetch_quote`的方法，负责从 Mashape API 获取随机引用数据。我们将在进一步的实现中使用这个方法。

现在，让我们为我们的用户编写一个资源 API，他们将使用我们的 API 来获取随机引用。以下是资源 API 的代码片段。

文件-`resource.py`：

```py
import falcon
from mashape import fetch_quote

class RandomQuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        try:
            resp.media = fetch_quote()
        except Exception as e:
            raise falcon.HTTPError(falcon.HTTP_500, str(e))

api = falcon.API()
api.add_route('/', RandomQuoteResource())
```

在这里，我们使用 Falcon 框架实现了一个 RESTful API。此 API 与根 URL 映射，即`"/"`。我们使用`on_get`方法仅接受 HTTP `GET`请求；其他请求将被拒绝访问。一旦用户发起`GET`请求，此 API 将返回随机引用数据。

你可以在本地环境上通过在本地主机上使用`gunicorn`运行此 API 来执行此 API：

```py
$ gunicorn resources:api
[2018-07-11 13:59:28 +0530] [3562] [INFO] Starting gunicorn 19.9.0
[2018-07-11 13:59:28 +0530] [3562] [INFO] Listening at: http://127.0.0.1:8000 (3562)
[2018-07-11 13:59:28 +0530] [3562] [INFO] Using worker: sync
[2018-07-11 13:59:28 +0530] [3565] [INFO] Booting worker with pid: 3565
```

一旦运行`gunicorn resources:api`命令，API 将在本地使用`8000`端口可用。让我们使用`curl`命令执行 API：

```py
$ curl http://localhost:8000
{"quote": "Whenever I climb I am followed by a dog called 'Ego'.", "author": "Friedrich Nietzsche", "category": "Famous"}
```

就是这样。我们已经完成了实施。现在，是时候使用 Zappa 在 AWS Lambda 上部署应用程序了。让我们继续下一节，我们将进一步讨论部署过程。

# 使用 Zappa 部署

要配置 Zappa，您应该运行`zappa init`命令并按照自动生成的问卷进行操作。我遵循了默认建议的设置，因此以下是自动生成的`zappa_settings.json`文件。

文件-`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r"
    }
}
```

就是这样。现在，借助这个配置，您可以执行以下日志片段中提到的部署：

```py
$ zappa deploy dev
Calling deploy for stage dev..
Creating chapter11-dev-ZappaLambdaExecutionRole IAM Role..
Creating zappa-permissions policy on chapter11-dev-ZappaLambdaExecutionRole IAM Role.
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter11-dev-1531293742.zip (5.6MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 5.92M/5.92M [00:02<00:00, 1.16MB/s]
Scheduling..
Scheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Uploading chapter11-dev-template-1531293760.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 2.32KB/s]
Waiting for stack chapter11-dev to create (this can take a bit)..
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00, 2.67s/res]
Deploying API Gateway..
Scheduling..
Unscheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://u1pao12esc.execute-api.ap-south-1.amazonaws.com/dev

```

在继续之前，让我们针对此应用程序集成一个自定义域。我们学习了如何使用 ACM 创建 SSL 证书并在第八章中配置自定义域，*带 SSL 的自定义域*。因此，我们将使用先前创建的通配符 SSL 证书。只需从 Zappa 设置中轻松创建新的自定义域。

我们将在`zappa_settings.json`文件中添加以下设置。

文件-`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
 "domain": "random-quote.abdulwahid.info",
 "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784"
    }
}
```

```py
zappa update command:
```

```py
$ zappa update dev
Calling update for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter11-dev-1531294072.zip (5.6MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 5.92M/5.92M [00:02<00:00, 2.19MB/s]
Updating Lambda function code..
Updating Lambda function configuration..
Uploading chapter11-dev-template-1531294078.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 8.55KB/s]
Deploying API Gateway..
Scheduling..
Unscheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://random-quote.abdulwahid.info (https://u1pao12esc.execute-api.ap-south-1.amazonaws.com/dev)
```

现在，应用程序已更新到 AWS Lambda，但我们仍然需要执行域认证任务以使域名上线。借助`zappa certify`命令，我们可以实现这一点。

```py
zappa certify command:
```

```py
$ zappa certify dev
Calling certify for stage dev..
Are you sure you want to certify? [y/n] y
Certifying domain random-quote.abdulwahid.info..
Created a new domain name with supplied certificate. Please note that it can take up to 40 minutes for this domain to be created and propagated through AWS, but it requires no further work on your part.
Certificate updated!
```

如前面的日志所述，我们的应用程序已经使用给定的自定义域名（[`random-quote.abdulwahid.info`](https://random-quote.abdulwahid.info)）上线，但可能需要长达 40 分钟才能创建域名并通过 AWS 传播，尽管这不需要您进一步的工作。让我们继续下一节，我们将执行已部署的应用程序。

# 执行 API

一旦应用程序上线，您可以使用 cURL 工具检查 API 的执行情况。以下是 API 执行的日志片段：

```py
$ curl https://random-quote.abdulwahid.info
{"quote": "The significant problems we face cannot be solved at the same level of thinking we were at when we created them.", "author": "Albert Einstein", "category": "Famous"}
```

这就是全部关于无服务器的内容。现在，我们需要探索一些重要的步骤，以保护我们的应用程序免受未经授权的访问。让我们继续下一节，我们将讨论并实施一些解决方案来保护应用程序。

# 在 API Gateway 上启用安全端点

保护 API 访问是一个重要的标准。您可以限制和限制将要使用 API 的客户的访问。Amazon API Gateway 确实支持多种机制来保护、限制和限制 API 的使用。这将有助于根据您的客户群维护 API 的使用情况。以下是 API Gateway 支持的三种实现类型：

+   API 密钥

+   IAM 策略

+   API 网关 Lambda 授权者

让我们更详细地看看每个实现。

# 启用 API 密钥

正如我们在第一章中描述的，*Amazon Web Services for Serverless,*关于 Zappa 的部署工作流程，Zappa 配置 API 网关以使用代理传递机制调用 AWS Lambda，这在 API 网关接口上创建了一个 API。每个 API 都支持各种阶段。在我们的情况下，我们在部署应用程序时创建了一个`dev`阶段。因此，以下屏幕截图显示了 API 网关控制台的状态：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00098.jpeg)

API Gateway 支持 API 密钥机制，您可以创建一个 API 密钥以及使用计划。借助这个 API 密钥，您可以限制客户的访问。任何客户都可以在 API 中设置`x-api-key`头与 API 密钥值来访问 API。API 密钥可以映射到任何 API 或阶段。

以下截图显示了创建 API 密钥的手动过程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00099.jpeg)

使用 Zappa 可以消除创建 API 密钥的手动过程。这就是 Zappa 发挥重要作用的地方，因为它将通过配置 Zappa 设置自动化整个过程。

Zappa 提供了一个布尔值的`api_key_required`属性。`api_key_required`默认设置为`false`，但如果您想生成 API 密钥，则需要将其设置为`true`。一旦将此属性设置为`true`，则需要重新部署应用程序。

`api_key_required`设置不适用于`zappa update`命令；它只适用于`zappa deploy`命令。因此，您需要取消部署应用程序，并从 Route 53 中删除已部署的自定义域的`CNAME`，然后从 API Gateway 控制台中删除自定义域。一旦删除了这些，就可以再次部署应用程序。

```py
zappa_settings.json file with the "api_key_required" attribute.
```

文件-`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "domain": "random-quote.abdulwahid.info",
        "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784",
 "api_key_required": true
    }
}
```

现在，您可以再次使用`zappa deploy`命令执行新的部署，如下面的日志片段所示：

```py
$ zappa deploy dev
Calling deploy for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter11-dev-1531334904.zip (5.6MiB)..
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 5.92M/5.92M [00:12<00:00, 360KB/s]
Scheduling..
Scheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Uploading chapter11-dev-template-1531334920.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.61K/1.61K [00:00<00:00, 10.4KB/s]
Waiting for stack chapter11-dev to create (this can take a bit)..
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00, 4.69s/res]
Deploying API Gateway..
Created a new x-api-key: zp0snz9tik
Deployment complete!: https://laqdydyrg3.execute-api.ap-south-1.amazonaws.com/dev
```

请注意，Zappa 将生成新的`x-api-key`并返回 API 密钥 ID，如前面的日志片段所述。

部署完成后，您将能够在 API Gateway 控制台中看到自动生成的 API 密钥，如此处所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00100.jpeg)

如前面的截图所示，您可以在 Zappa 设置中使用 API 密钥值，将 Zappa 部署的 API 与此密钥关联，以便 API 应用程序需要您在`x-api-key`头中具有此值。

下一步是通过单击前面截图中显示的`Associated Usage Plans`部分中的`Add to Usage Plan`将 API 密钥与使用计划关联起来。API 密钥可以与多个使用计划关联。这些计划使您能够根据您的业务模型为客户定义良好的结构使用计划。以下是第十一章 Basic Usage Plan 及其基本使用计划的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00101.jpeg)

如前面的截图所示，使用计划使您能够为每个 API 密钥定义限流限制和及时限定的 API 请求配额。一旦定义了计划，就可以将其与任何部署的 API 及其各自的阶段关联，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00102.jpeg)

我们将第十一章的`Basic Usage Plan` `dev` API 与`dev`阶段链接到了这个计划。这就是您可以为客户设置 API 的业务计划并共享 API 密钥以提供授权访问的方法。

现在，让我们在`zappa_settings.json`文件中使用前面 API 密钥截图中的 API 密钥值，并使用`"api_key"`属性。以下是更新后的`zappa_settings.json`文件。

文件-`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "domain": "random-quote.abdulwahid.info",
        "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784",
        "api_key_required": true,
"api_key":"yEddw9WeMH2UIZXHcaHQb1WvbindovrB55Rf4eAW"
    }
}
```

就这样。让我们再次使用`zappa update`命令更新部署，如下面提到的日志片段所示：

```py
$ zappa update dev
Calling update for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter11-dev-1531337694.zip (5.6MiB)..
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 5.92M/5.92M [00:16<00:00, 261KB/s]
Updating Lambda function code..
Updating Lambda function configuration..
Uploading chapter11-dev-template-1531337713.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.61K/1.61K [00:00<00:00, 8.50KB/s]
Deploying API Gateway..
Scheduling..
Unscheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled chapter11-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://random-quote.abdulwahid.info (https://laqdydyrg3.execute-api.ap-south-1.amazonaws.com/dev)
```

我们已经完成了启用 API 密钥认证。让我们继续下一节，看看 API 的执行情况。

# 使用 API 密钥头执行 API

我们启用了 API 密钥的认证，因此 API 密钥与`x-api-key`头是强制的。如果请求没有`x-api-key`头，将被拒绝访问并返回禁止响应。如果用户在`x-api-key`头中提供有效的 API 密钥值，则将被允许访问 API 资源。

没有`x-api-key`头的 API 执行如下：

```py
$ curl https://random-quote.abdulwahid.info/
{"message":"Forbidden"}
```

带有`x-api-key`头的 API 执行如下：

```py
$ curl --header "x-api-key: yEddw9WeMH2UIZXHcaHQb1WvbindovrB55Rf4eAW" https://random-quote.abdulwahid.info/
{"quote": "Problems worthy of attack prove their worth by fighting back.", "author": "Paul Erdos", "category": "Famous"}
```

我们已经完成了 API 密钥身份验证集成。让我们继续下一节，我们将探索使用 IAM 策略进行身份验证的另一种选项。

# IAM 策略

Amazon API Gateway 支持基于 IAM 的 V4 签名请求身份验证。API Gateway 要求用户通过对请求进行签名来进行身份验证。签署请求是使用加密函数创建数字签名的完整流程。您可以在以下链接中阅读有关签署请求过程的更多信息：

[`docs.aws.amazon.com/apigateway/api-reference/signing-requests/`](https://docs.aws.amazon.com/apigateway/api-reference/signing-requests/)

Zappa 通过在 Zappa 的设置中将`"iam_authorization"`属性设置为`true`来启用此功能。此属性默认设置为`false`。因此，您可以显式将其设置为 true，以启用基于 IAM 的身份验证。此功能使您能够根据 IAM 策略访问 API 资源。您可以通过 IAM 策略([`docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-iam-policy-examples.html`](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-iam-policy-examples.html))来控制此访问。

为了演示目的，我将为同一应用程序创建一个不同的阶段和自定义域。以下是 Zappa 设置的片段。

文件-`zappa_settings.json`:

```py
{
    "dev": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "domain": "random-quote.abdulwahid.info",
        "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784",
        "api_key_required": true,
        "api_key":"yEddw9WeMH2UIZXHcaHQb1WvbindovrB55Rf4eAW"
    },
    "dev_iam": {
 "app_function": "resources.api",
 "profile_name": "default",
 "project_name": "chapter11",
 "runtime": "python3.6",
 "s3_bucket": "zappa-ss0sm7k4r",
 "remote_env": "s3://book-configs/chapter-11-config.json",
 "domain": "random-quote-iam.abdulwahid.info",
 "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784",
 "iam_authorization": true
 }
}
```

在这里，我们创建了一个带有`iam_authentication`的不同阶段。此标志将启用基于 IAM 的身份验证。现在，您需要执行部署、更新和认证操作，以使此阶段与以下域名一起生效。

```py
curl execution:
```

```py
$ curl -s -w "\nStatus Code:%{http_code}" https://random-quote-iam.abdulwahid.info
{"message":"Missing Authentication Token"}
Status Code:403
```

现在，您需要对请求进行签名以访问部署的资源。签署请求需要您遵循一些流程，如此处所述：[`docs.aws.amazon.com/apigateway/api-reference/signing-requests/`](https://docs.aws.amazon.com/apigateway/api-reference/signing-requests/)。还有许多第三方库可用于生成签署请求所需的标头。我们将使用`requests-aws-sign`([`github.com/jmenga/requests-aws-sign`](https://github.com/jmenga/requests-aws-sign))库来使用签名请求访问 API 资源。

以下是签署请求以访问 API 资源的代码片段。

文件-`aws_sign_request_test.py`:

```py
import os
import requests
from requests_aws_sign import AWSV4Sign
from boto3 import session

# You must provide a credentials object as per http://boto3.readthedocs.io/en/latest/guide/configuration.html#configuring-credentials
# This example attempts to get credentials based upon the local environment
# e.g. Environment Variables, assume role profiles, EC2 Instance IAM profiles
session = session.Session(
    aws_access_key_id=os.environ['aws_access_key_id'],
    aws_secret_access_key=os.environ['aws_secret_access_key'])
credentials = session.get_credentials()

# You must provide an AWS region
region = session.region_name or 'ap-south-1'

# You must provide the AWS service. E.g. 'es' for Elasticsearch, 's3' for S3, etc.
service = 'execute-api'

url = "https://random-quote-iam.abdulwahid.info/"
auth=AWSV4Sign(credentials, region, service)
response = requests.get(url, auth=auth)

print (response.content)
```

就是这样！现在，您可以看到前面脚本的输出，如下面的代码所示：

```py
$ python aws_sign_request_test.py 
b'{"quote": "Many wealthy people are little more than janitors of their possessions.", "author": "Frank Lloyd Wright", "category": "Famous"}'
```

最后，我们通过签名请求获得了 API 访问权限。通过这种方式，您可以使用 IAM 身份验证保护无服务器 API 应用程序。让我们继续下一节，我们将探索保护无服务器 API 应用程序的另一种方式。

# API Gateway Lambda 授权程序

Amazon API Gateway Lambda 授权程序是一个简单的 AWS Lambda 函数，作为授权程序来控制对 API Gateway 资源的访问。这是因为 Lambda 授权程序将负责通过 bearer token 形式的授权头验证请求，并返回有效的 IAM 策略。您可以根据**JWT**（JSON Web Token）、OAuth 或 SAML 编写自定义的 Lambda 授权程序，具有不同的身份验证策略。

您可以从 API Gateway 控制台添加授权程序，如官方 AWS 文档中所述([`docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html`](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html))，或者您可以从名为`api-gateway-authorizer-python`的 Lambda 蓝图创建 Lambda 授权程序([`github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/python/api-gateway-authorizer-python.py`](https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/python/api-gateway-authorizer-python.py))，然后从 API Gateway 控制台将此 Lambda 函数关联为 API 资源的授权程序。

一旦您配置了授权者，API 网关期望请求以及授权头中的持有者令牌或参数。如果缺少授权头，它将拒绝请求。如果客户端向您的 API 资源发送带有持有者令牌的请求授权头，那么 API 网关将从请求头中提取持有者令牌和其他参数，并将它们作为事件参数提供给 Lambda 授权者函数。Lambda 授权者使用现有的 AWS IAM 策略或 AWS Cognito 用户池验证令牌，然后返回 IAM 策略以授权请求。API 网关通过在预配置的**TTL**（**生存时间**）期间缓存请求令牌的返回策略来维护子请求的会话，从 300 到 3600 秒， 默认为 300 秒。

Zappa 支持一种更简单的方法来配置 Lambda 授权者。您可以在 Zappa 设置中定义授权者属性如下：

```py
{
    "dev" : {
        ...
        "authorizer": {
            "function": "your_module.your_auth_function", 
            "arn": "arn:aws:lambda:<region>:<account_id>:function:<function_name>",
            "result_ttl": 300,
            "token_header": "Authorization", // Optional. Default 'Authorization'. The name of a custom authorization header containing the token that clients submit as part of their requests.
            "validation_expression": "^Bearer \\w+$", // Optional. A validation expression for the incoming token, specify a regular expression.
        }
        ...
    }
}
```

我们可以定义前面的属性。每个属性都有其自己的特定用途，以定义自定义 Lambda 授权者。让我们更详细地探讨这些属性：

+   `function`：这将是您自己的本地函数，用于执行令牌验证。Zappa 将自动创建并映射此函数作为 API 网关中的授权者。

+   `arn`：这将是您现有 Lambda 函数的`arn`，用于验证令牌。如果您选择蓝图 Lambda 授权者函数`api-gateway-authorizer-python`（[`github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/python/api-gateway-authorizer-python.py`](https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/python/api-gateway-authorizer-python.py)），那么您可以放入由蓝图创建的 Lambda 函数的`arn`。

+   `result_ttl`：这是一个可选属性。它通过 API 网关启用**生存时间**（**TTL**）周期来缓存授权者结果。默认情况下，它设置为 300 秒，您可以将其设置为最多 3600 秒。

+   `token_header`：这是一个可选属性。它用于设置自定义授权头的名称。它包含客户端提交的请求的一部分令牌。

+   `validation_expression`：这是一个可选属性。它用于设置授权头中令牌的验证表达式。默认情况下，它支持`"^Bearer \\w+$"`表达式来验证令牌表达式。

这是您可以为无服务器 API 创建自定义 Lambda 授权者的方法。这使您能够为 Zappa 部署的所有分布式 API 微服务创建集中式身份验证。

现在，让我们继续下一节，我们将探讨 AWS 失败的跟踪机制。

# 使用死信队列跟踪 AWS Lambda 失败

**死信队列**（**DLQ**）是亚马逊定义的机制，用于跟踪 AWS Lambda 函数在异步执行时的失败。AWS Lambda 在事件被丢弃之前，会以异步模式调用并在失败的情况下重试两次。DLQ 用于将此失败事件传递到 Amazon SQS 队列或 Amazon SNS 主题。

# 手动 DLQ 配置

DLQ 可以通过在 Lambda 函数的`DeadLetterConfig`参数上设置`TargetArn`（即 SQS 队列 ARN 或 SNS 主题 ARN）来进行配置，如下所述：

```py
{
    "Code": {
        "ZipFile": blob,
        "S3Bucket": “string”,
        "S3Key": “string”,
        "S3ObjectVersion": “string”
    },
    "Description": "string",
    "FunctionName": "string",
    "Handler": "string",
    "MemorySize": number,
    "Role": "string",
    "Runtime": "string",
    "Timeout": number
    "Publish": bool,
    "DeadLetterConfig": {
 "TargetArn": "string" 
 }
} 
```

# 使用 Zappa 自动化 DLQ 配置

为了自动化这个过程，Zappa 通过将 SQS 队列/SNS 主题 ARN 值设置为`dead_letter_arn`来启用这个功能。我们在第九章中创建了一个名为`UnhandledException`的 SNS 主题，让我们使用现有的 SNS 主题，它已经订阅了我的电子邮件。只有在异步 Lambda 函数调用失败和重试时，DQL 才会触发。然后，DQL 将把故障异常处理为消息发送到配置的 SNS 主题，我们将在订阅的电子邮件上收到处理后的异常数据。

现在，以下代码片段是更新后的 Zappa 设置。

文件-`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "domain": "random-quote.abdulwahid.info",
        "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784",
        "api_key_required": true,
        "api_key":"yEddw9WeMH2UIZXHcaHQb1WvbindovrB55Rf4eAW",
        "dead_letter_arn": "arn:aws:sns:ap-south-1:042373950390:UnhandledException"
    },
    "dev_iam": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "domain": "random-quote-iam.abdulwahid.info",
        "certificate_arn":"arn:aws:acm:us-east-1:042373950390:certificate/af0796fa-3a46-49ae-97d8-90a6b5ff6784",
        "iam_authorization": true
    }
}
```

在这里，我只为`dev`阶段更新了`dead_letter_arn`属性。因此，这个功能将在`dev`阶段可用。现在，我们已经在`dev`阶段的 Lambda 函数中设置好了 DLQ。完成配置后，您需要使用`zappa deploy`命令进行部署。就是这样！现在，我们的代码中应该有一个异步的 Lambda 函数机制，在运行时引发异常。

请注意，对于特定 Lambda 函数的更改，您需要使用`zappa deploy`命令重新部署函数。`zappa update`命令在这里不起作用，因为它负责更新现有的代码库，而不是 Lambda 配置。

# 在异步 Lambda 函数中引发异常

为了在异步 Lambda 调用中引发异常，我们需要有一个机制来实例化一个异步 Lambda 函数。让我们编写一个资源 API 并调用一个异步任务，这将引发异常。

以下是`resources.py`的更新代码：

```py
import falcon
from zappa.async import task
from mashape import fetch_quote

class RandomQuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        try:
            resp.media = fetch_quote()
        except Exception as e:
            raise falcon.HTTPError(falcon.HTTP_500, str(e))

@task
def async_task():
    raise ValueError("Async Failure Exception")

class AsyncTaskResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        try:
            async_task()
            resp.media = 'Called async task'
        except Exception as e:
            raise falcon.HTTPError(falcon.HTTP_500, strsk(e))

api = falcon.API()
api.add_route('/', RandomQuoteResource())
api.add_route('/async-failure', AsyncTaskResource())
```

在这里，我们创建了一个`AsyncTaskResource`作为`"/async-failure"`路由的资源类。这个路由使用`AsyncTaskResource`类中的`on_get`方法定义了 HTTP `GET`请求。我们还使用任务装饰器将`async_task`方法创建为一个异步方法。我们已经在第九章中看到了使用 Zappa 执行异步任务的实现，任务装饰器将在单独的 Lambda 实例中异步执行该方法。

从`async_task`中，我们引发了一个`ValueError`异常。这将导致异步 Lambda 执行失败，并在随后的失败时引发 DLQ 事件。DLQ 将把异常数据处理到我们配置的 SNS 主题 ARN。最后，我们将在电子邮件中收到异常信息。

```py
async-failure API:
```

```py
$ curl -H "x-api-key: yEddw9WeMH2UIZXHcaHQb1WvbindovrB55Rf4eAW" https://random-quote.abdulwahid.info/async-failure
"Called async task"
```

我们请求了`/async-failure` API，它立即响应并在异步 Lambda 函数中实例化了任务。由于我们在`async_task`方法中明确引发了异常，这将调用 DLQ 并通过发布到 SNS 主题来处理异常信息。以下是从 AWS 通知消息收到的电子邮件通知的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00103.jpeg)

这样，我们就可以追踪未知的故障。这个功能将帮助我们提高应用程序的质量并减少故障率。让我们继续下一节，我们将探讨如何使用 AWS X-Ray 分析 Zappa 应用程序。

# 使用 AWS X-Ray 分析 Zappa 应用程序

AWS X-Ray 是亚马逊网络服务提供的分析服务。它帮助开发人员对应用程序的行为和工作流程进行分析。借助 X-Ray，开发人员可以了解应用程序的性能并追踪根本原因以改进优化。

AWS X-Ray 可以在任何计算 AWS 服务上启用。一旦您启用了 X-Ray，它就会根据应用程序的交互生成数据段。例如，如果您向应用程序发出 HTTP 请求，那么 X-Ray 将生成有关主机、请求、响应、计算时间和错误的数据。基于这些数据段，X-Ray 生成了一个服务图。

服务图提供了一个可视化模式，供开发人员了解应用程序工作流程并帮助确定其性能。除了请求和响应数据生成外，X-Ray 还为您的应用程序与 AWS 资源、微服务、数据库和 HTTP Web API 调用的交互生成记录。

# AWS Lambda 的 X-Ray 手动集成

AWS Lambda 控制台具有特权，可以配置 Lambda 函数与 AWS X-Ray。因此，任何与 AWS Lambda 的交互都将被 AWS X-Ray 记录。您可以通过从控制台页面配置函数来在 Lambda 函数上启用 X-Ray，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00104.jpeg)

关于 AWS Lambda 控制台工作流程，您需要选择 AWS XRay。然后，您可以从主部分的底部面板配置其关联的设置，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00105.jpeg)

一旦选择了 X-Ray，默认执行角色权限将附加到您的 Lambda 函数。这样，AWS X-Ray 将记录对 Lambda 函数 API 执行的跟踪。

# Zappa 配置以启用 AWS X-Ray 支持

Zappa 始终在这里，以避免手动交互来配置您的 Lambda 函数。因此，Zappa 提供了一种简单的方法来配置 AWS X-Ray 与您的 Lambda 函数。您只需在 Zappa 设置中将`"xray_tracing"`设置为`true`。这将自动为您的 Lambda 函数启用 X-Ray 跟踪支持。

让我们创建现有 API 应用的另一个阶段。这个阶段将具有基本配置，没有身份验证和自定义域，因为我们只是想演示 X-Ray 的工作流程。以下是具有 X-Ray 支持的新阶段配置。

文件 - `zappa_settings.json`：

```py
{
    ...
    "dev_xray": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "xray_tracing": true
    }
}
```

如前所述，我们已经添加了一个名为`"dev_xray"`的新阶段，具有基本配置和 AWS X-Ray 跟踪支持。现在，让我们使用`zappa deploy`命令部署这个阶段。

```py
deploy command:
```

```py
$ zappa deploy dev_xray
Calling deploy for stage dev_xray..
Creating chapter11-dev-xray-ZappaLambdaExecutionRole IAM Role..
Creating zappa-permissions policy on chapter11-dev-xray-ZappaLambdaExecutionRole IAM Role.
Downloading and installing dependencies..
 - lazy-object-proxy==1.3.1: Using locally cached manylinux wheel
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter11-dev-xray-1531691356.zip (8.2MiB)..
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 8.65M/8.65M [00:19<00:00, 460KB/s]
Scheduling..
Scheduled chapter11-dev-xray-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Uploading chapter11-dev-xray-template-1531691381.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.64K/1.64K [00:00<00:00, 9.68KB/s]
Waiting for stack chapter11-dev-xray to create (this can take a bit)..
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00, 4.70s/res]
Deploying API Gateway..
Deployment complete!: https://r0wagu3zh3.execute-api.ap-south-1.amazonaws.com/dev_xray
```

就是这样！现在，我们的随机引用 API 已经在不同的阶段上线运行。一旦应用程序部署，Zappa 将生成一个随机的 API Gateway 链接，如前面的日志片段中所述。现在，您可以使用 curl 工具来访问 API。

以下是 API 执行的日志片段：

```py
$ curl https://r0wagu3zh3.execute-api.ap-south-1.amazonaws.com/dev_xray
{"quote": "A lie gets halfway around the world before the truth has a chance to get its pants on.", "author": "Sir Winston Churchill", "category": "Famous"}
```

我们已经集成了 AWS X-Ray，因此我们应用程序的所有交互将被 AWS X-Ray 记录为跟踪段。以下是 AWS X-Ray 服务地图的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00106.jpeg)

在这里，您可以查看应用程序的跟踪详细信息。这些详细信息根据其控制台上的时间范围可用。AWS X-Ray 支持客户端 SDK 库，使开发人员能够根据其需求持久化这些跟踪。AWS X-Ray 的客户端 SDK 具有许多实现，涵盖了多种语言和特定语言的框架。您可以在以下链接了解有关 AWS X-Ray 及其基于 Python 的 SDK 库的更多信息：

[`docs.aws.amazon.com/xray/latest/devguide/aws-xray.html`](https://docs.aws.amazon.com/xray/latest/devguide/aws-xray.html)

[`github.com/aws/aws-xray-sdk-python`](https://github.com/aws/aws-xray-sdk-python)

让我们继续下一节，我们将探讨 AWS VPC 与 AWS Lambda 函数的集成。

# 使用 AWS VPC 保护您的 Zappa 应用程序

AWS **虚拟私有云**（**VPC**）是专门为 AWS 资源提供的隔离虚拟网络服务。它类似于您自己数据中心中的传统网络机制。AWS VPC 使您能够保护 AWS 资源免受未经授权的访问。AWS 为每个区域提供了默认 VPC。默认 VPC 可帮助您配置所有 AWS 资源。

AWS VPC 专门为您的 AWS 账户提供了隔离层。您可以使用 AWS VPC 配置您的 AWS 资源。启用 VPC 后，您可以根据需要指定以下组件，例如 IP 地址范围、子网、安全组、路由表等。这些组件用于设置网络策略和策略。

# VPC 的手动配置

AWS Lambda 有配置 VPC 的特权。以下是 AWS Lambda 配置的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00107.jpeg)

如前面的屏幕截图所示，我们选择了默认 VPC。我们需要配置其他组件，如子网和安全组，这是必需的。子网是 VPC 中的 IP 地址范围。对于需要互联网访问的任何资源，应使用公共子网。私有子网用于不需要连接到互联网的任何资源。

另一方面，安全组定义了授权任何协议访问的入站和出站规则。

AWS VPC 具有完整的安全网络层实现。要了解 VPC 概念的每个方面，您应该阅读其官方文档[(](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html)[`docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html`](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html))。我们将专注于 Zappa 配置，以便以自动化方式启用 VPC。让我们继续下一节，在那里我们将配置 Zappa 与 VPC。

# 使用 Zappa 进行 VPC 配置

Zappa 有一种优化的方式来自动化部署应用程序的 VPC。您只需要提供`vpc_config`属性和子网和安全组 ID，如此处所述：

```py
{
    ...
    "vpc_config": { 
        "SubnetIds": [ "subnet-12345678" ],
        "SecurityGroupIds": [ "sg-12345678" ]
    },
    ...
}
```

我在前一节中提到了默认 VPC。您可以从 VPC 仪表板页面获取默认子网 ID，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00108.jpeg)

您可以通过从左侧面板选择安全组来获取安全组 ID，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00109.jpeg)

现在，我们将创建另一个带有 VPC 配置的部署阶段。您需要从前面的屏幕截图中放入子网 ID 和安全组 ID，并使用 Zappa 设置进行配置，如下面的代码片段所示。

文件—`zappa_settings.json`：

```py
{
    ...,
    "dev_vpc": {
        "app_function": "resources.api",
        "profile_name": "default",
        "project_name": "chapter11",
        "runtime": "python3.6",
        "s3_bucket": "zappa-ss0sm7k4r",
        "remote_env": "s3://book-configs/chapter-11-config.json",
        "vpc_config": {
 "SubnetIds": [ "subnet-1b10a072", "subnet-6303f22e" ],
 "SecurityGroupIds": [ "sg-892c4be0" ]
 }
    }
}
```

AWS VPC 是一个隔离的网络，因此在 VPC 网络内运行的任何服务都无法访问公共互联网。如果需要为任何资源访问公共互联网，则必须至少有两个子网。在 VPC 仪表板中使用以下设置：

+   对于`subnet-a`：

选择 NAT 网关部分并创建一个 NAT 网关。

选择 Internet 网关部分并创建一个 Internet 网关。

从路由表部分，创建一个名为`route-a`的路由，将 Internet 网关指向`0.0.0.0/0`。

+   对于`subnet-b`：

使用此子网配置您的 Lambda 函数。

从路由表部分，创建一个名为`route-b`的路由，将属于`subnet-a`的 NAT 指向`0.0.0.0/0`。

```py
zappa deploy command:
```

```py
$ zappa deploy dev_vpc
Important! A new version of Zappa is available!
Upgrade with: pip install zappa --upgrade
Visit the project page on GitHub to see the latest changes: https://github.com/Miserlou/Zappa
Calling deploy for stage dev_vpc..
Downloading and installing dependencies..
 - lazy-object-proxy==1.3.1: Downloading
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 56.0K/56.0K [00:00<00:00, 4.88MB/s]
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter11-dev-vpc-1532712120.zip (8.2MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 8.65M/8.65M [00:03<00:00, 2.56MB/s]
Scheduling..
Scheduled chapter11-dev-vpc-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Uploading chapter11-dev-vpc-template-1532712136.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.64K/1.64K [00:00<00:00, 40.8KB/s]
Waiting for stack chapter11-dev-vpc to create (this can take a bit)..
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00, 2.38s/res]
Deploying API Gateway..
Deployment complete!: https://6odti0061c.execute-api.ap-south-1.amazonaws.com/dev_vpc
```

就是这样。现在，我们的应用已成功配置了 AWS VPC。

# 摘要

在本章中，我们学习了不同的安全机制，并演示了它们在一个小型基于 API 的应用程序中的实现。AWS 拥有非常好的安全架构，但涉及手动交互过程，而 Zappa 自动化了这些过程并防止了手动交互。我们还涵盖了优化应用程序工作流程的跟踪、分析和通知过程。

在下一章中，我们将探讨 Zappa 开发，以及 Docker 容器化。请继续关注，以便您可以提升新的技能。

# 问题

1.  什么是 API 网关授权者？

1.  什么是 AWS Lambda DQL？

1.  为什么 AWS VPC 很重要？
