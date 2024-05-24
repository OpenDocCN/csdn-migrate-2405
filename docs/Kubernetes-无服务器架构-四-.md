# Kubernetes 无服务器架构（四）

> 原文：[`zh.annas-archive.org/md5/36BD40FEB49D3928DE19F4A0B653CB1B`](https://zh.annas-archive.org/md5/36BD40FEB49D3928DE19F4A0B653CB1B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录

关于

这一部分是为了帮助学生在书中执行活动。

其中包括学生执行的详细步骤，以实现活动的目标。

## 1\. 介绍无服务器

### 活动 1：伦敦自行车积分的 Twitter 机器人后端

**解决方案：**

执行以下步骤以完成此活动：

1.  创建一个`main.go`文件来注册函数处理程序，就像*练习 1*中一样。

这段代码是应用程序的入口，其中函数被注册，并启动主应用程序：

```
package main
import (
   "fmt"
   "net/http"
)
func main() {
   fmt.Println("Starting the 🚲 finder..")
   http.HandleFunc("/", FindBikes)
   fmt.Println("Function handlers are registered.")
   http.ListenAndServe(":8080", nil)
}
```

1.  为`FindBikes`函数创建一个`function.go`文件：

```
...
func FindBikes(w http.ResponseWriter, r *http.Request) {
   ...

   // Get bike points for the query
   bikePoints, err := httpClient.Get(fmt.Sprintf(TFL_API_URL + "BikePoint/Search?query=" + url2.QueryEscape(query)))
   ...
   // Get available number of bikes
   availableBikeResponse, err := httpClient.Get(TFL_API_URL + "BikePoint/" + bikePoint.ID)

...
         if bikeAmount == 0 {
            w.Write([]byte(fmt.Sprintf(RESPONSE_NO_AVAILABLE_BIKE, bikePoint.CommonName, url)))
            return
         } else {
            w.Write([]byte(fmt.Sprintf(DEFAULT_RESPONSE, bikePoint.CommonName, bikeAmount, url)))
            return
         }
...
```

#### 注意

活动所需的文件可以在以下链接找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Activity1`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Activity1)。

在这个文件中，应该实现实际的函数及其辅助函数。`FindBikes`负责从**TFL 统一 API**获取自行车积分位置的数据，然后获取可用自行车的数量。根据收集到的信息，该函数返回完整的句子，用作 Twitter 的响应。

1.  创建一个`Dockerfile`来构建和打包函数，就像*练习 2*中一样：

```
FROM golang:1.12.5-alpine3.9 AS builder
ADD . .
RUN go build *.go
FROM alpine:3.9
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN update-ca-certificates
COPY --from=builder /go/function ./bikes
RUN chmod +x ./bikes
ENTRYPOINT ["./bikes"]
```

在这个`Dockerfile`中，应用程序在第一个容器中构建，并在第二个容器中打包以进行交付。

1.  使用 Docker 命令构建容器镜像：`docker build . -t find-bikes`。

它应该看起来像这样：

![图 1.27：构建 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_27.jpg)

###### 图 1.27：构建 Docker 镜像

1.  运行容器镜像作为 Docker 容器，并使端口在主机系统上可用：`docker run -it --rm -p 8080:8080 find-bikes`。

事情应该看起来如下截图所示：

![图 1.28：运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_28.jpg)

###### 图 1.28：运行 Docker 容器

1.  使用不同查询测试函数的 HTTP 端点，例如**牛津**、**修道院**或**对角巷**。

我们期望得到伦敦街道的真实响应，以及来自文学作品的虚构街道的失败响应。

![图 1.29：不同街道的函数响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_29.jpg)

###### 图 1.29：不同街道的函数响应

1.  按下*Ctrl + C*退出容器：![图 1.30：退出容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_30.jpg)

###### 图 1.30：退出容器

## 2. 云中无服务器的介绍

### 活动 2：Slack 的每日站立会议提醒功能

**解决方案** – **Slack 设置：**

1.  在**Slack**工作区中，单击您的用户名，然后选择**自定义 Slack**，如下截图所示：![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_49.jpg)

###### 图 2.49：Slack 菜单

1.  在打开的窗口中单击**配置应用程序**，如下截图所示：![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_50.jpg)

###### 图 2.50：Slack 配置菜单

1.  单击**浏览应用程序目录**以从目录中添加新应用程序，如下截图所示：![图 2.51：Slack 管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_51.jpg)

###### 图 2.51：Slack 管理

1.  从**应用程序目录**的搜索框中找到**传入 WebHooks**，如下截图所示：![图 2.52：应用程序目录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_52.jpg)

###### 图 2.52：应用程序目录

1.  单击**添加配置**以为**传入 WebHooks**应用程序添加配置，如下截图所示：![图 2.53：传入 Webhooks 页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_53.jpg)

###### 图 2.53：传入 Webhooks 页面

1.  填写传入 webhook 的配置，指定您的特定频道名称和图标，如下截图所示：![图 2.54：传入 webhook 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_54.jpg)

###### 图 2.54：传入 webhook 配置

复制**Webhook URL**，然后单击**保存设置**，如上图所示。

1.  打开 Slack 工作区和我们在步骤 6 中提到的频道。您将看到一个集成消息：

![图 2.55：Slack 中的集成消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_55.jpg)

###### 图 2.55：Slack 中的集成消息

**活动解决方案**

执行以下步骤完成此活动：

1.  创建一个新函数，在调用函数时调用 Slack webhook。

在 GCF 中，可以使用名称`StandupReminder`，128 MB 内存和 HTTP 触发器来定义。

此功能可以在任何支持的语言中实现，例如**Go 1.11**，如下截图所示：

![图 2.56：Google Cloud 平台中的云函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_56.jpg)

###### 图 2.56：Google Cloud 平台中的云函数

要添加的代码如下：

```
package p
import (
    "bytes"
    "net/http"
)
func Reminder(http.ResponseWriter, *http.Request) {
    url := "https://hooks.slack.com/services/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"

    var jsonStr = []byte(`{"text": "Time for a stand-up meeting!"}`)
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))

    client := &http.Client{}
    _, err = client.Do(req)
    if err != nil {
        panic(err)
    }
}
```

#### 注意

不要忘记使用步骤 6 中的 Slack URL 更改`url`值。

您可以在本书 GitHub 存储库的活动解决方案中找到完整的`function.go`文件：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson02/Activity2/function.go`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson02/Activity2/function.go).

1.  创建一个调度程序作业，使用函数的触发 URL，并根据你的站立会议时间指定计划。

可以在 Google Cloud Scheduler 中定义调度程序的名称为`StartupReminder`，并且函数的 URL，如下面的截图所示：

![图 2.57：Google 云平台中的云调度程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_57.jpg)

###### 图 2.57：Google 云平台中的云调度程序

使用`0 9 * * 1-5`的计划，提醒将在每周一至周五的 09:00 调用函数。

1.  在提醒消息的计划时间到达时，检查 Slack 频道。

对于`0 9 * * 1-5`的计划，您将在工作日的 09:00 在您选择的 Slack 频道上看到一条消息，如下面的截图所示：

![图 2.58：Slack 提醒消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_58.jpg)

###### 图 2.58：Slack 提醒消息

1.  从云提供商中删除调度作业和函数，如下面的截图所示：![图 2.59：删除调度程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_59.jpg)

###### 图 2.59：调度程序的删除

可以这样删除函数：

![图 2.60：删除函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_60.jpg)

###### 图 2.60：删除函数

在这个活动中，我们使用函数构建了 Slack 应用程序的后端。我们首先为传入的 webhook 配置了 Slack，然后创建了一个发送数据到 webhook 的函数。由于我们的函数应该在预定义的时间被调用，我们使用了云调度程序服务来调用函数。通过在 Slack 中成功发送提醒消息，展示了将函数集成到其他云服务和外部服务中。

## 3. 无服务器框架简介

### 活动 3：Slack 的每日天气状态功能

**解决方案- Slack 设置**

1.  执行以下步骤来配置 Slack：

1.  在您的 Slack 工作区中，点击您的用户名，然后选择自定义 Slack：![图 3.44：Slack 菜单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_44.jpg)

###### 图 3.44：Slack 菜单

1.  点击打开窗口中的配置应用程序：![图 3.45：Slack 配置菜单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_45.jpg)

###### 图 3.45：Slack 配置菜单

1.  单击“浏览应用程序目录”以从目录中添加新应用程序：![图 3.46：Slack 管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_46.jpg)

###### 图 3.46：Slack 管理

1.  在应用目录的搜索框中找到传入的 WebHooks：![图 3.47：应用目录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_47.jpg)

###### 图 3.47：应用目录

1.  单击“设置”传入的 WebHooks 应用程序：![图 3.48：传入 WebHooks 页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_48.jpg)

###### 图 3.48：传入 WebHooks 页面

1.  选择一个频道发布笑话消息，并单击“添加传入 WebHooks 集成”：![图 3.49：频道选择](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_49.jpg)

###### 图 3.49：频道选择

1.  使用您特定的频道名称和图标填写传入 WebHook 的配置：![图 3.50：传入 WebHook 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_50.jpg)

###### 图 3.50：传入 WebHook 配置

复制 Webhook URL 并单击保存设置。

1.  打开您的 Slack 工作区和您在第 6 步中配置的频道，以检查集成消息：![图 3.51：Slack 中的集成消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_51.jpg)

###### 图 3.51：Slack 中的集成消息

活动解决方案

1.  执行以下步骤完成此活动：

1.  在您的终端中，启动 Serverless Framework 开发环境：

```
docker run -it --entrypoint=bash onuryilmaz/serverless
```

此命令将以交互模式启动 Docker 容器。在接下来的步骤中，将在此 Docker 容器内执行操作：

![图 3.52：启动服务器无容器的 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_52.jpg)

###### 图 3.52：启动服务器无容器的 Docker 容器

1.  在您的终端中，在名为 daily-weather 的文件夹中创建一个 Serverless Framework 应用程序结构。

创建一个名为 daily-joker 的文件夹，并将其更改为以下目录：

```
mkdir daily-weather
cd daily-weather
```

#### 注意

nano 和 vim 作为文本编辑器安装在 Serverless Framework 开发环境 Docker 容器中。

1.  创建一个 serverless.yaml 文件，并用以下内容替换 SLACK_WEBHOOK_URL 的值，该值是从 Slack 设置的第 6 步中复制的 URL。此外，更新 CITY 环境变量为当前办公地点，以获取正确的天气信息。此外，您可以更改计划部分，该部分当前在工作日的 08:00 触发函数：

```
service: daily-weather
provider:
  name: aws
  runtime: nodejs8.10
functions:
  weather:
    handler: handler.weather
    events:
      - schedule: cron(0 8 ? * 1-5 *)
    environment:
      CITY: Berlin
      SLACK_WEBHOOK_URL: https://hooks.slack.com/services/.../.../...
```

#### 注意

serverless.yaml 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson03/Activity3/serverless.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson03/Activity3/serverless.yaml)找到。

1.  在 daily-weather 文件夹中创建一个 package.json 文件来定义 Node.js 环境。

package.json 定义了函数及其依赖关系：

```
{
  "name": "daily-weather",
  "description": "",
  "main": "handler.js",
    "dependencies": {
    "node-fetch": "².2.1",
    "slack-node": "0.1.8"
  }
}
```

#### 注意

package.json 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson03/Activity3/package.json`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson03/Activity3/package.json)找到。

1.  在 daily-weather 文件夹中创建一个 handler.js 文件来实现实际功能。

handler.js 包括实际的 Node.js 函数：

```
const fetch = require('node-fetch');
const Slack = require('slack-node');
module.exports.weather = (event, context, callback) => {
    const webhookUri = process.env.SLACK_WEBHOOK_URL;
    const location = process.env.CITY;
    const slack = new Slack();
    slack.setWebhook(webhookUri);
    weatherURL = "http://wttr.in/" + encodeURIComponent(location) + "?m&&format=1"
    console.log(weatherURL)
    fetch(weatherURL)
        .then(response => response.text())
        .then(data => {
            console.log("======== WEATHER TEXT ========")
            console.error(data);
            console.log("======== WEATHER TEXT ========")
            slack.webhook({
                text: "Current weather status is " + data
            }, function(err, response) {
                console.log("======== SLACK SEND STATUS ========")
                console.error(response.status);
                return callback(null, {statusCode: 200, body: "ok" });
                console.log("======== SLACK SEND STATUS ========")
                if (err) {
                    console.log("======== ERROR ========")
                    console.error(error);
                    console.log("======== ERROR ========")
                    return callback(null, {statusCode: 500, body: JSON.stringify({ error}) });
                }
            });
        }).catch((error) => {
            console.log("======== ERROR ========")
            console.error(error);
            console.log("======== ERROR ========")
             return callback(null, {statusCode: 500, body: JSON.stringify({ error}) });
        });
};
```

#### 注意

handler.js 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson03/Activity3/handler.js`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson03/Activity3/handler.js)找到。

1.  在文件创建结束时，您将看到以下文件结构，包括三个文件：

```
ls -l
```

输出应该如下所示：

![图 3.53：文件夹结构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_53.jpg)

###### 图 3.53：文件夹结构

1.  安装 serverless 应用程序所需的 Node.js 依赖项。运行以下命令来安装依赖项：

```
npm install -i
```

输出应该如下所示：

![图 3.54：依赖安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_54.jpg)

###### 图 3.54：依赖安装

1.  将 AWS 凭据导出为环境变量。从练习 xx 中导出以下环境变量和 AWS 凭据：

```
export AWS_ACCESS_KEY_ID=AKIASVTPHRZR33BS256U
export AWS_SECRET_ACCESS_KEY=B***************************R
```

输出应该如下所示：

![图 3.55：AWS 凭证](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_55.jpg)

###### 图 3.55：AWS 凭证

1.  使用 Serverless Framework 将 serverless 应用程序部署到 AWS。运行以下命令来部署函数：

```
serverless deploy 
```

这些命令将使 Serverless Framework 将函数部署到 AWS。输出日志从打包服务和为源代码、工件和函数创建 AWS 资源开始。创建完所有资源后，服务信息部分提供了完整堆栈的摘要，如下图所示：

![图 3.56：Serverless Framework 部署输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_56.jpg)

###### 图 3.56：Serverless Framework 部署输出

1.  在 AWS 控制台中检查已部署函数的 AWS Lambda，如下图所示：![图 3.57：AWS 控制台中的 AWS Lambda](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_57.jpg)

###### 图 3.57：AWS 控制台中的 AWS Lambda

1.  使用 Serverless Framework 的客户端工具调用该函数。在您的终端中运行以下命令：

```
serverless invoke --function weather
```

此命令调用部署的函数并打印出响应，如下图所示：

![图 3.58：函数输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_58.jpg)

###### 图 3.58：函数输出

正如我们所看到的，statusCode 为 200，响应的主体也表明函数已成功响应。

1.  检查 Slack 频道发布的天气状态：![图 3.59：带有天气状态的 Slack 消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_59.jpg)

###### 图 3.59：带有天气状态的 Slack 消息

1.  返回到您的终端，并使用 Serverless Framework 删除该函数。在您的终端中运行以下命令：

```
serverless remove
```

此命令将删除部署的函数及其所有依赖项：

![图 3.60：移除函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_60.jpg)

###### 图 3.60：移除函数

1.  退出 Serverless Framework 开发环境容器。在您的终端中运行 exit：

](image/C12607_03_61.jpg)

###### 图 3.61：退出容器

在这个活动中，我们使用了一个无服务器框架构建了 Slack 应用的后端。我们首先配置了 Slack 以接收传入的 webhooks，然后创建了一个无服务器应用程序来向 webhook 发送数据。为了在预定的时间调用函数，利用了无服务器框架的配置，而不是特定于云的调度程序。由于无服务器框架为云提供商创建了一个抽象，我们在这个活动中开发的无服务器应用程序适用于多云部署。

## 4\. Kubernetes 深入探讨

### 活动 4：在 Kubernetes 中将金价收集到 MySQL 数据库中

**解决方案：**

执行以下步骤以完成此活动：

1.  创建一个应用程序，从`CurrencyLayer`中检索金价并将其插入到 MySQL 数据库中。

可以使用以下 main.go 文件在 Go 中实现此函数：

```
...
func main() {
    db, err := sql.Open("mysql",  ...
    ...
    r, err := http.Get(fmt.Sprintf(„http://apilayer.net/api/...
   ...
    stmt, err := db.Prepare("INSERT INTO GoldPrices(price) VALUES(?)")
    ...
    _, err = stmt.Exec(target.Quotes.USDXAU)
    ...
    log.Printf("Successfully inserted the price: %v", target.Quotes.USDXAU)
    ...
}
```

主要函数从数据库连接开始，然后从`CurrencyLayer`中检索价格。然后继续创建 SQL 语句并在数据库连接上执行。

#### 注意

main.go 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/main.go`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/main.go)找到。

1.  将应用程序构建为 Docker 容器。可以使用以下 Dockerfile 从第 1 步构建应用程序：

```
FROM golang:1.12.5-alpine3.9 AS builder
RUN apk add --no-cache git
ADD main.go /go/src/gold-price-to-mysql/main.go
WORKDIR /go/src/gold-price-to-mysql/
RUN go get -v
RUN go build .
FROM alpine:3.9
COPY --from=builder /go/src/gold-price-to-mysql/gold-price-to-mysql ./gold-price-to-mysql
RUN chmod +x ./gold-price-to-mysql
ENTRYPOINT ["./gold-price-to-mysql"]
```

#### 注意

Dockerfile 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/Dockerfile`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/Dockerfile)找到。

1.  使用以下命令在终端中运行：

```
docker build -t <USERNAME>/gold-price-to-mysql .
```

该命令将应用程序构建为 Docker 容器，如下图所示：

![图 4.26：Docker 构建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_26.jpg)

###### 图 4.26：Docker 构建

#### 注意

不要忘记将`<USERNAME>`更改为您的 Docker Hub 用户名。

1.  将 Docker 容器推送到 Docker 注册表。在终端中运行以下命令：

```
docker push <USERNAME>/gold-price-to-mysql
```

该命令将上传容器映像到 Docker Hub，如下图所示：

![图 4.27：Docker 推送](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_27.jpg)

###### 图 4.27：Docker 推送

#### 注意

不要忘记将`<USERNAME>`更改为您的 Docker Hub 用户名。

1.  将 MySQL 数据库部署到 Kubernetes 集群。创建一个 mysql.yaml 文件，其中包含 MySQL StatefulSet 的定义：

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  selector:
    matchLabels:
      app: mysql
  serviceName: mysql
  replicas: 1
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
      - name: mysql
        image: mysql:5.7
        env:
        - name: MYSQL_ROOT_PASSWORD
          value: "root"
        - name: MYSQL_DATABASE
          value: "db"
        - name: MYSQL_USER
          value: "user"
        - name: MYSQL_PASSWORD
          value: "password"
        ports:
        - name: mysql
          containerPort: 3306
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
          subPath: mysql
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 1Gi
```

#### 注意

mysql.yaml 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/mysql.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/mysql.yaml)找到。

1.  在终端中使用以下命令部署 StatefulSet：

```
kubectl apply -f mysql.yaml
```

该命令提交文件到 Kubernetes 并创建 mysql StatefulSet，如下图所示：

![图 4.28：StatefulSet 创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_28.jpg)

###### 图 4.28：StatefulSet 创建

1.  部署 Kubernetes 服务以公开 MySQL 数据库。创建一个 service.yaml 文件，其中包含以下 Kubernetes 服务定义：

```
apiVersion: v1
kind: Service
metadata:
  name: gold-price-db
spec:
  selector:
    app: mysql
  ports:
    - protocol: TCP
      port: 3306
      targetPort: 3306
```

#### 注意

service.yaml 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/service.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/service.yaml)找到。

1.  使用以下命令在终端中部署服务：

```
kubectl apply -f service.yaml
```

此命令将文件提交到 Kubernetes 并创建 gold-price-db 服务，如下图所示：

![图 4.29：服务创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_29.jpg)

###### 图 4.29：服务创建

1.  部署一个每分钟运行一次的 CronJob。创建一个名为 insert-gold-price.yaml 的文件，其中包含以下 Kubernetes CronJob 定义：

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: gold-price-to-mysql
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: insert
            image: <USERNAME>/gold-price-to-mysql
            env:
            - name: MYSQL_ADDRESS
              value: "gold-price-db:3306"
            - name: MYSQL_DATABASE
              value: "db"
            - name: MYSQL_USER
              value: "user"
            - name: MYSQL_PASSWORD
              value: "password"
            - name: API_KEY
              value: "<API-KEY>"
```

#### 注意

insert-gold-price.yaml 可在[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/insert-gold-price.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/insert-gold-price.yaml)找到。

不要忘记将`<USERNAME>`更改为您的 Docker Hub 用户名，将`<API-KEY>`更改为您的 CurrencyLayer API 密钥。

1.  在您的终端中使用以下命令部署 CronJob：

```
kubectl apply -f insert-gold-price.yaml
```

此命令将文件提交到 Kubernetes 并创建 gold-price-to-mysql CronJob，如下图所示：

![图 4.30：CronJob 创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_30.jpg)

###### 图 4.30：CronJob 创建

1.  等待几分钟并检查 CronJob 的实例。在您的终端中使用以下命令检查运行中的 pod：

```
kubectl get pods
```

此命令列出了 pod，并且您应该看到一些实例，其名称以 gold-price-to-mysql 开头，并且状态为已完成，如下图所示：

![图 4.31：Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_31.jpg)

###### 图 4.31：Pod 列表

1.  连接到数据库并检查条目：

```
kubectl run mysql-client --image=mysql:5.7 -i -t --rm --restart=Never \
-- mysql -h gold-price-db -u user -ppassword  db -e "SELECT * FROM GoldPrices;"
```

此命令运行 mysql:5.7 镜像的临时实例，并运行 SELECT * FROM GoldPrices 命令，如下图所示：

![图 4.32：表列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_32.jpg)

###### 图 4.32：表列表

在 GoldPrices MySQL 表中，每分钟收集一次价格数据。它显示 MySQL StatefulSet 正在成功运行数据库。此外，CronJob 每分钟创建一次 pod 并成功运行。

1.  从 Kubernetes 中清除数据库和自动化任务。在您的终端中使用以下命令清除资源：

```
kubectl delete -f insert-gold-price.yaml,service.yaml,mysql.yaml
```

您应该看到以下图中显示的输出：

![图 4.33：资源删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_33.jpg)

###### 图 4.33：资源删除

在这个活动中，我们在 Kubernetes 中创建了一个 MySQL 数据库作为 StatefulSet。Kubernetes 已经创建了所需的卷资源并附加到 MySQL 容器上。接着，我们创建并打包了我们的无服务器函数。该函数被部署到 Kubernetes 集群作为 CronJob。Kubernetes 确保该函数每分钟都被调度和运行。在 Kubernetes 中运行函数提供了两个重要的优势。第一个是重用 Kubernetes 集群和资源。换句话说，我们不需要额外的云资源来运行我们的无服务器工作负载。第二个优势是与数据的接近。由于我们的微服务已经在 Kubernetes 上运行，建议将我们的数据库放在 Kubernetes 中。当无服务器应用程序也在同一集群中运行时，更容易操作、管理和排除故障应用程序。

## 5.生产就绪的 Kubernetes 集群

### 活动 5：在 GKE 集群中最小化无服务器函数的成本

**解决方案**

1.  创建一个具有可抢占服务器的新节点池。

在 GCP 云 shell 中运行以下和即将到来的函数：

```
gcloud beta container node-pools create preemptible --preemptible \
--min-nodes 1 --max-nodes 10  --enable-autoscaling  \
--cluster serverless --zone us-central1-a 
```

#### 注意

如果您的集群在另一个区域运行，请更改`zone`参数。

此函数创建一个名为`preemptible`的新节点池，自动缩放的最小节点数为 1 个，最大节点数为 10 个，如下图所示：

![图 5.29：节点池创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_29.jpg)

###### 图 5.29：节点池创建

1.  给可抢占服务器施加污点，只能运行无服务器函数：

```
kubectl taint node -l cloud.google.com/gke-nodepool=preemptible   \
preemptible="true":NoSchedule
```

此命令将对所有具有标签`cloud.google.com/node-pool = preemptible`的节点应用污点。污点键将是`preemptible`，值为`true`。此限制的操作是`NoSchedule`，这意味着只有具有匹配容忍性的 pod 才会被调度到这些节点上，如下图所示：

![图 5.30：给节点施加污点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_30.jpg)

###### 图 5.30：给节点施加污点

1.  创建一个 Kubernetes 服务以访问后端 pod：

```
kubectl expose deployment backend --port 80 --target-port=80
```

此命令在端口`80`上为部署后端创建了一个服务，如下图所示：

![图 5.31：暴露部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_31.jpg)

###### 图 5.31：暴露部署

1.  创建一个`CronJob`，每分钟连接到后端服务。CronJob 定义应该具有容忍性，以在可抢占服务器上运行。

在名为`cronjob.yaml`的文件中创建一个包含以下内容的`CronJob`定义：

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: backend-checker
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: checker
            image: appropriate/curl
            args:
            - curl
            - -I
            - backend
          nodeSelector:
            cloud.google.com/gke-nodepool: "preemptible"
          tolerations:
          - key: preemptible
            operator: Equal
            value: "true"
            effect: NoSchedule
          restartPolicy: OnFailure
```

该文件包含了每分钟运行 `curl -I backend` 函数的 `CronJob` 定义。`nodeSelector` 表示调度器将选择在具有标签键 `cloud.google.com/gke-nodepool` 和值 `preemptible` 的节点上运行。然而，由于可抢占节点上有污点，因此还添加了容忍。

#### 注意

`cronjob.yaml` 可在 GitHub 上找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson05/Activity5/cronjob.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson05/Activity5/cronjob.yaml)。

1.  使用以下命令部署 CronJob：

```
kubectl apply -f cronjob.yaml
```

输出应如下所示：

![图 5.32：CronJob 创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_32.jpg)

###### 图 5.32：CronJob 创建

1.  检查 `CronJob` 函数的节点分配：

```
kubectl get pods -o wide
```

此命令列出了带有相应节点的 pod。如预期的那样，在 `high-memory` 节点上运行了确切的 10 个后端实例。此外，如下图所示，在 `preemptible` 节点上运行了 3 个 `CronJob` 函数实例：

![图 5.33：Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_33.jpg)

###### 图 5.33：Pod 列表

1.  检查 `CronJob` 函数实例的日志：

```
kubectl logs brand-checker-<ID> 
```

#### 注意

用 *步骤 5* 中的 pod 名称替换 `<ID>`。

函数的输出显示了 `curl` 连接到 `nginx` 实例的轨迹，如下图所示：

![图 5.34：curl 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_34.jpg)

###### 图 5.34：curl 输出

1.  清理后端部署和无服务器函数：

```
kubectl delete deployment/backend cronjob/backend-checker
```

此命令将删除 `backend` 部署和 `backend-checker` CronJob，如下图所示：

![图 5.35：清理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_35.jpg)

###### 图 5.35：清理

1.  如果不再需要，删除 Kubernetes 集群：

```
gcloud container clusters delete serverless --zone us-central1-a 
```

#### 注意

如果您的集群在另一个区域运行，请在命令中更改 `zone` 参数。

此命令将从 GKE 中删除集群，如下图所示：

![图 5.36：集群移除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_05_36.jpg)

###### 图 5.36：集群移除

在此活动中，我们对生产集群进行了管理任务。在 Kubernetes 集群中创建不同类型的节点并运行异构节点集有助于降低整个集群的成本。此外，启用了自动缩放以满足用户需求，无需人工干预。

自动扩展和应用程序迁移是生产集群上最常见的运维任务。这些任务可以在最小的停机时间和成本下实现更好的性能。然而，用于生产环境的 Kubernetes 平台还应满足您日常运营的要求。Kubernetes 和云提供商的能力对于安装、监视和操作在云中运行的应用程序至关重要。

## 6. Kubernetes 中即将推出的无服务器功能

### 活动 6：在无服务器环境中部署容器化应用

**解决方案**

1.  首先，创建一个新目录来存储此活动的文件，并切换到新创建的目录：

```
$ mkdir chapter-06-activity
$ cd chapter-06-activity
```

1.  创建一个可以返回给定时区的当前日期和时间的应用程序。我们将使用 PHP 来编写这个函数，但您可以选择任何您熟悉的语言。创建一个名为 index.php 的文件，其中包含第 1 步中给出的内容。

现在我们需要根据 Google Cloud Run 的容器运行时合同（[`cloud.google.com/run/docs/reference/container-contract`](https://cloud.google.com/run/docs/reference/container-contract)）创建 Docker 镜像。创建一个名为 Dockerfile 的新文件，其中包含第 2 步中的内容。

1.  一旦 Dockerfile 准备好，我们就可以构建 Docker 镜像。用你的 GCP 项目的 ID 替换`<your-gcp-project-name>`。接下来，使用 docker build 命令构建 Docker 镜像。`--tag`标志用于按照`[HOSTNAME]/[GCP-PROJECT-ID]/[IMAGE-NAME]:[TAG]`格式标记 Docker 镜像，因为我们将在下一步将其推送到**Google 容器注册表（GCR）**：

```
$ export GCP_PROJECT=<your-gcp-project-name>
$ docker build . --tag gcr.io/${GCP_PROJECT}/clock:v1.0
```

输出应该如下所示：

![图 6.57：构建 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_57.jpg)

###### 图 6.57：构建 Docker 镜像

1.  接下来，我们可以将 docker 镜像推送到 GCR：

```
$ docker push gcr.io/${GCP_PROJECT}/clock:v1.0
```

输出应该如下所示：

![图 6.58：推送 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_58.jpg)

###### 图 6.58：推送 Docker 镜像

1.  现在我们已经创建并推送了一个 Docker 镜像到注册表。现在转到 GCP 控制台，打开 Cloud Run 页面。单击**创建服务**按钮，使用以下信息创建一个新服务：

容器镜像 URL：`gcr.io/<your-gcp-project-id>/clock:v1.0`

部署平台：Cloud Run（完全托管）

位置：从可用选项中选择任何您喜欢的区域

服务名称：clock

认证：**允许未经身份验证的调用**

页面将如下所示：

![图 6.59：创建服务](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_59.jpg)

###### 图 6.59：创建服务

1.  单击**创建**按钮，您将被导航到服务详细信息页面：![图 6.60：服务详细信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_60.jpg)

###### 图 6.60：服务详细信息

1.  从服务详细信息页面打开提供的 URL。对我来说，这个 URL 是`https://clock-awsve2jaoa-uc.a.run.app/`，但您的 URL 将会不同：![图 6.61：时区错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_61.jpg)

###### 图 6.61：时区错误

1.  由于我们没有提供时区参数，所以我们收到了这个错误。

1.  让我们再次使用带有时区参数的 URL 进行调用，`https://clock-awsve2jaoa-uc.a.run.app/?timezone=Europe/London`![图 6.62：带时区的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_06_62.jpg)

###### 图 6.62：带时区的输出

在这个活动中，我们已成功在 Google Cloud Run 上部署了一个容器化应用程序，可以根据提供的`时区`值输出当前日期和时间。

## 7. 使用 Kubeless 的 Kubernetes 无服务器

### 活动 7：使用 Kubeless 将消息发布到 Slack

**解决方案- Slack 设置**

1.  访问 https://slack.com/create 以创建一个工作区。输入您的电子邮件地址，然后单击“创建”：![图 7.77：创建新工作区](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_77.jpg)

###### 图 7.77：创建新工作区

1.  现在，您将收到一个六位数的确认码，发送到您在上一页输入的电子邮件中。在下一页上输入收到的代码：![图 7.78：检查您的电子邮件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_78.jpg)

###### 图 7.78：检查您的电子邮件

1.  在这里添加一个合适的名称。这将是您的工作区名称：![图 7.79：添加工作区名称](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_79.jpg)

###### 图 7.79：添加工作区名称

1.  在这里添加一个合适的名称。这将是您的 Slack 频道名称：![图 7.80：添加 Slack 频道名称](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_80.jpg)

###### 图 7.80：添加 Slack 频道名称

如果您愿意，可以跳过以下部分：

![图 7.81：填写更多细节或选择跳过](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_81.jpg)

###### 图 7.81：填写更多细节或选择跳过

1.  现在您的 Slack 频道已准备就绪。单击**在 Slack 中查看您的频道**，如下面的屏幕截图所示：![图 7.82：查看新的 Slack 频道](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_82.jpg)

###### 图 7.82：查看新的 Slack 频道

一旦点击，我们应该看到我们的频道如下：

![图 7.83：您的新 Slack 频道](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_83.jpg)

###### 图 7.83：您的新 Slack 频道

1.  现在我们要向 Slack 添加一个传入的 Webhook 应用程序。从左侧菜单中，在应用程序部分下选择添加应用程序：![图 7.84：在应用程序部分下添加应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_84.jpg)

###### 图 7.84：在应用程序部分下添加应用程序

1.  在搜索栏中输入`传入的 Webhooks`，然后点击**安装**传入的 Webhook 应用程序：![图 7.85：浏览应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_85.jpg)

###### 图 7.85：浏览应用程序

1.  点击**添加配置**：![图 7.86：添加配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_86.jpg)

###### 图 7.86：添加配置

1.  点击**添加传入的 WebHooks 集成**：![图 7.87：添加传入的 webhooks](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_87.jpg)

###### 图 7.87：添加传入的 webhooks

1.  保存 webhook URL。在编写 Kubeless 函数时，我们将需要这个。

1.  现在，让我们创建函数并部署它。首先，我们需要创建 requirements.txt 文件，该文件指定了我们需要为函数的运行时安装的依赖项。这些是我们需要成功运行函数的额外模块。我们将使用 requests 包向 Slack webhook 端点发送 HTTP POST 请求：

```
Requests==2.22.0
```

**活动解决方案**

1.  按照以下步骤创建函数。

```
import json
import requests
def main(event, context):
    webhook_url = 'YOUR_INCOMMING_WEBHOOK_URL'
    response = requests.post(
        webhook_url, data=json.dumps(event['data']),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code == 200:
        return "Your message successfully sent to Slack"
    else:
        return "Error while sending your message to Slack: " + response.get('error')
```

1.  部署函数：

```
$ kubeless function deploy slack --runtime python3.6 \
                                      --from-file slack.py \
                                      --handler slack.main \
                                      --dependencies requirements.txt
```

部署函数将产生以下输出：

![图 7.88：部署函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_88.jpg)

###### 图 7.88：部署函数

在部署 slack 函数时，我们将传递我们在上一步中创建的 requirements.txt 文件作为依赖项。这将确保 Kubeless 运行时包含函数执行所需的 Python 包。

1.  调用 kubeless 函数：

```
$ kubeless function call slack --data '{"username": "kubeless-bot", "text": "Welcome to Serverless Architectures with Kubeless !!!"}'
```

这将产生以下输出：

![图 7.89：调用函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_89.jpg)

###### 图 7.89：调用函数

1.  转到您的 Slack 工作区，并验证消息是否成功发布到 Slack 频道：![图 7.90：验证消息是否成功发布](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_07_90.jpg)

###### 图 7.90：验证消息是否成功发布

在这个活动中，我们创建了一个 Slack 空间并创建了一个传入的 webhook。接下来，我们创建并部署了一个 Kubeless 函数，可以向 Slack 频道发布消息。

## 8. Apache OpenWhisk 简介

### 活动 8：通过电子邮件接收每日天气更新

创建 OpenWeather 和 SendGrid 帐户的步骤：

1.  在[`home.openweathermap.org/users/sign_up`](https://home.openweathermap.org/users/sign_up)创建一个**OpenWeather**账户：![图 8.72：创建 OpenWeather 账户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_72.jpg)

###### 图 8.72：创建 OpenWeather 账户

1.  一旦您注册到**OpenWeather**，API 密钥将自动生成。转到**API 密钥**选项卡（[`home.openweathermap.org/api_keys`](https://home.openweathermap.org/api_keys)）并保存 API 密钥，因为这个密钥是从 OpenWeather API 获取数据所需的。![图 8.73：OpenWeather API 密钥](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_73.jpg)

###### 图 8.73：OpenWeather API 密钥

1.  在 Web 浏览器中使用`https://api.openweathermap.org/data/2.5/weather?q=London&appid=<YOUR-API-KEY>`来测试**OpenWeather** API。请注意，您需要用步骤 2 中的 API 密钥替换`<YOUR-API-KEY>`：

#### 注意

可能需要几分钟来激活您的 API 密钥。如果收到**无效的 API 密钥**，请等待几分钟后重试。请参阅[`openweathermap.org/faq#error401`](http://openweathermap.org/faq#error401)获取更多信息。在调用 URL 时出现错误。

![图 8.74：调用 OpenWeather API](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_74.jpg)

###### 图 8.74：调用 OpenWeather API

1.  在[`signup.sendgrid.com/`](https://signup.sendgrid.com/)创建一个**SendGrid**账户。

应该如下所示：

![图 8.75：创建 SendGrid 账户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_75.jpg)

###### 图 8.75：创建 SendGrid 账户

1.  转到**设置** > **API 密钥**，然后点击**创建 API 密钥**按钮：![图 8.76：SendGrid 中的 API 密钥页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_76.jpg)

###### 图 8.76：SendGrid 中的 API 密钥页面

1.  在**API 密钥名称**字段中提供一个名称，选择**完全访问**单选按钮，然后点击**创建和查看**按钮以创建具有完全访问权限的 API 密钥：![图 8.77：在 SendGrid 中生成 API 密钥](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_77.jpg)

###### 图 8.77：在 SendGrid 中生成 API 密钥

1.  一旦生成密钥，请复制 API 密钥并将其保存在安全的地方，因为您只能看到这个密钥一次：![图 8.78：在 SendGrid 中生成的 API 密钥](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_78.jpg)

###### 图 8.78：在 SendGrid 中生成的 API 密钥

**活动解决方案**

1.  使用*步骤 3*中提供的函数代码创建`get-weather.js`函数。将`<OPEN_WEATHER_API_KEY>`替换为*步骤 1*中保存的 API 密钥。

1.  创建名为`getWeather`的操作，其中包含在前一步中创建的`get-weather.js`函数，并将`cityName`参数的默认值设置为`London`：

```
$ wsk action create getWeather get-weather.js --param cityName London
```

输出应如下所示：

![图 8.79：创建 getWeather 操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_79.jpg)

###### 图 8.79：创建 getWeather 操作

1.  通过调用操作验证操作是否按预期工作：

```
$ wsk action invoke getWeather --result
```

![图 8.80：调用 getWeather 操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_80.jpg)

###### 图 8.80：调用 getWeather 操作

1.  现在我们可以创建发送电子邮件的操作（我们将使用与 SendGrid 生成的 API 密钥）。我们将为此函数使用`sendgrid`模块。首先，我们需要创建一个目录来存储函数代码和依赖项：

```
$ mkdir send-email
$ cd send-email
```

输出应如下所示：

![图 8.81：创建 send-mail 目录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_81.jpg)

###### 图 8.81：创建 send-mail 目录

1.  运行`npm init`命令，接受默认参数：

```
$ npm init
```

输出应如下所示：

![图 8.82：npm init](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_82.jpg)

###### 图 8.82：npm init

1.  安装`sendgrid` `npm`包，这是函数所需的：

```
$ npm install sendgrid -save
```

输出应如下所示：

![图 8.83：添加 sendgrid 依赖包](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_83.jpg)

###### 图 8.83：添加 sendgrid 依赖包

1.  使用*步骤 4*中提供的函数代码创建`index.js`文件。将`<SEND_GRID_API_KEY>`替换为创建 SendGrid 帐户时保存的密钥。类似地，将`<TO_EMAIL>`替换为接收天气数据的电子邮件地址，将`<FROM_EMAIL>`替换为发送天气数据的电子邮件地址。

1.  压缩所有依赖项的代码：

```
$ zip -r send-email.zip *
```

1.  现在我们可以使用`send-email.zip`创建名为`sendEmail`的操作：

```
$ wsk action create sendEmail send-email.zip --kind nodejs:default
```

输出应如下所示：

![图 8.84：创建 sendEmail 操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_84.jpg)

###### 图 8.84：创建 sendEmail 操作

1.  验证`sendEmail`操作是否按预期工作：

#### 注意

请确保检查您的垃圾邮件文件夹，因为电子邮件客户端可能已将其归类为垃圾邮件。

```
$ wsk action invoke sendEmail --param message "Test Message" –result
```

输出应如下所示：

![图 8.85：调用 sendEmail 操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_85.jpg)

###### 图 8.85：调用 sendEmail 操作

1.  使用*步骤 5*中提供的函数代码创建`format-weather-data.js`函数。

1.  创建名为`formatWeatherData`的操作，其中包含在前一步中创建的`format-weather-data.js`函数：

```
$ wsk action create formatWeatherData format-weather-data.js
```

输出应如下所示：

![图 8.86：创建 formatWeatherData 操作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_86.jpg)

###### 图 8.86：创建 formatWeatherData 动作

1.  通过组合`getWeather`、`formatWeatherData`和`sendEmail`动作创建一个名为`weatherMailSender`的序列：

```
$ wsk action create weatherMailSender --sequence getWeather,formatWeatherData,sendEmail
```

输出应如下所示：

![图 8.87：创建 weatherMailSender 动作序列](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_87.jpg)

###### 图 8.87：创建 weatherMailSender 动作序列

1.  调用`weatherMailSender`序列：

```
$ wsk action invoke weatherMailSender --result
```

输出应如下所示：

![图 8.88：调用 weatherMailSender 动作序列](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_88.jpg)

###### 图 8.88：调用 weatherMailSender 动作序列

1.  检查您添加为`<TO_EMAIL>`的邮件帐户（检查垃圾邮件文件夹）。在[`app.sendgrid.com/email_activity`](https://app.sendgrid.com/email_activity)上检查电子邮件传递的状态。

输出应如下所示：

![图 8.89：从 weatherMailSender 动作序列接收的电子邮件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_89.jpg)

###### 图 8.89：从 weatherMailSender 动作序列接收的电子邮件

1.  最后，我们需要创建触发器和规则，以便每天上午 8 点调用该序列。首先，我们将创建`weatherMailSenderCronTrigger`，它将在每天上午 8:00 触发：

```
$ wsk trigger create weatherMailSenderCronTrigger \
                             --feed /whisk.system/alarms/alarm \
                             --param cron "0 8 * * *" 
ok: invoked /whisk.system/alarms/alarm with id cf1af9989a7a46a29af9989a7ad6a28c
{
    "activationId": "cf1af9989a7a46a29af9989a7ad6a28c",
    "annotations": [
        {
            "key": "path",
            "value": "whisk.system/alarms/alarm"
        },
        {
            "key": "waitTime",
            "value": 66
        },
        {
            "key": "kind",
            "value": "nodejs:10"
        },
        {
            "key": "timeout",
            "value": false
        },
        {
            "key": "limits",
            "value": {
                "concurrency": 1,
                "logs": 10,
                "memory": 256,
                "timeout": 60000
            }
        }
    ],
    "duration": 162,
    "end": 1565457634929,
    "logs": [],
    "name": "alarm",
    "namespace": "sathsara89@gmail.com_dev",
    "publish": false,
    "response": {
        "result": {
            "status": "success"
        },
        "status": "success",
        "success": true
    },
    "start": 1565457634767,
    "subject": "sathsara89@gmail.com",
    "version": "0.0.152"
}
ok: created trigger weatherMailSenderCronTrigger
```

1.  然后，我们将创建一个名为`weatherMailSenderCronRule`的规则，以连接触发器（`weatherMailSenderCronTrigger`）和动作（`weatherMailSender`）：

```
$ wsk rule create weatherMailSenderCronRule weatherMailSenderCronTrigger weatherMailSender
```

输出应如下所示：

![图 8.90：创建 weatherMailSenderCronRule](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_08_90.jpg)

###### 图 8.90：创建 weatherMailSenderCronRule

完成上述步骤后，您应该每天在上午 8:00 收到发送到指定电子邮件地址的有关所请求城市天气数据的电子邮件。

## 9\. 使用 OpenFaaS 进行无服务器化

### 活动 9：OpenFaaS 表单处理器

**解决方案**

1.  首先，您需要创建一个 SendGrid 账户并生成一个 API 密钥。您可以使用在*第八章，介绍 Apache OpenWhisk*中创建的相同 API 密钥。请参考*第八章，介绍 Apache OpenWhisk*中关于如何创建 SendGrid 账户和生成 API 密钥的步骤 4-7 的活动。

1.  使用 python3 模板创建一个名为 contact-form 的 OpenFaaS 函数。这将是联系表单的前端：

```
$ faas-cli new contact-form --lang=python3
```

输出应如下所示：

![图 9.59：创建 contact-form 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_09_591.jpg)

###### 图 9.59：创建 contact-form 函数

1.  在 contact-form 目录内创建一个名为 html 的新目录以存储 HTML 文件：

```
$ mkdir contact-form/html
```

输出应如下所示：

![图 9.60：创建 HTML 文件夹](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_09_601.jpg)

###### 图 9.60：创建 HTML 文件夹

1.  在 contact-form/html 文件夹中创建 contact-us.html 文件，并使用步骤 2 中提供的代码填写表单。

1.  更新 contact-form 文件夹中的`handler.py` Python 文件。这个 Python 函数将读取`contact-us.html`文件的内容，并将其作为函数响应返回：

```
import os

def handle(req):
    current_directory = os.path.dirname(__file__)
    html_file_path = os.path.join(current_directory, 'html', 'contact-us.html')
    with(open(html_file_path, 'r')) as html_file:
        html = html_file.read()

    return html
```

1.  更新函数定义（`contact-form.yml`）文件，将 content_type 指定为`text/html`，如下面的代码所示：

```
version: 1.0
provider:
  name: openfaas
  gateway: http://192.168.99.100:31112
functions:
  contact-form:
    lang: python3
    handler: ./contact-form
    image: sathsarasa/contact-form:latest
    environment:
      content_type: text/html
```

1.  构建、推送和部署 contact-form 函数：

```
$  faas-cli up -f contact-form.yml
```

命令的输出应该如下所示：

```
[0] > Building contact-form.
Clearing temporary build folder: ./build/contact-form/
Preparing ./contact-form/ ./build/contact-form//function
Building: sathsarasa/contact-form:latest with python3 template. Please wait..
Sending build context to Docker daemon  14.34kB
...
Successfully built 6c008c91f0bb
Successfully tagged sathsarasa/contact-form:latest
Image: sathsarasa/contact-form:latest built.
[0] < Building contact-form done.
[0] worker done.
[0] > Pushing contact-form [sathsarasa/contact-form:latest].
The push refers to repository [docker.io/sathsarasa/contact-form]
...
latest: digest: sha256:b4f0a4f474af0755b53acb6a1c0ce26e0f91a9a893bb8bfc78501cab267d823e size: 4282
[0] < Pushing contact-form [sathsarasa/contact-form:latest] done.
[0] worker done.
Deploying: contact-form.
WARNING! Communication is not secure, please consider using HTTPS. Letsencrypt.org offers free SSL/TLS certificates.
Deployed. 202 Accepted.
URL: http://192.168.99.100:31112/function/contact-form
```

1.  使用 python3 模板创建名为 form-processor 的第二个 OpenFaaS 函数。这将是联系表单的后端：

```
$ faas-cli new form-processor --lang=python3
```

输出应该如下所示：

![图 9.61：创建 form-processor 函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_09_61.jpg)

###### 图 9.61：创建 form-processor 函数

1.  更新 form-processor 文件夹中的`handler.py` Python 文件。这个 Python 函数执行接收输入到“联系我们”表单中的电子邮件、姓名和消息参数，格式化要发送的电子邮件正文，使用 SendGrid 发送电子邮件，并将电子邮件发送状态作为函数响应返回。

1.  用步骤 1 中保存的 SendGrid API 密钥替换<SEND_GRID_API_KEY>，用电子邮件地址替换<TO_EMAIL>以接收“联系我们”表单数据：

```
     import json
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
def handle(req):

    SENDGRID_API_KEY = '<SEND_GRID_API_KEY>'
    TO_EMAIL = '<TO_EMAIL>'
    EMAIL_SUBJECT = 'New Message from OpenFaaS Contact Form'

    json_req = json.loads(req)
    email = json_req["email"]
    name = json_req["name"]
    message = json_req["message"]
    email_body = '<strong>Name: </strong>' + name + '<br><br> <strong>Email: </strong>' + email + '<br><br> <strong>Message: </strong>' + message

    email_object = Mail(
        from_email= email,
        to_emails=TO_EMAIL,
        subject=EMAIL_SUBJECT,
        html_content=email_body)

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(email_object)
        sendingStatus = "Message sent successfully"
    except Exception as e:
        sendingStatus = "Message sending failed"

    return sendingStatus
```

1.  在 form-processor/requirements.txt 中将 sendgrid 模块添加为 form-processor 函数的依赖项：

```
sendgrid
```

1.  增加 form-processor.yml 中的超时（read_timeout、write_timeout 和 exec_timeout）值，如下面的代码所示：

```
version: 1.0
provider:
  name: openfaas
  gateway: http://192.168.99.100:31112
functions:
  form-processor:
    lang: python3
    handler: ./form-processor
    image: sathsarasa/form-processor:latest
    environment:
      read_timeout: 20
      write_timeout: 20
      exec_timeout: 20
```

1.  构建、部署和推送 form-processor 函数：

```
$  faas-cli up -f form-processor.yml
```

命令的输出应该如下所示：

```
[0] > Building form-processor.
Clearing temporary build folder: ./build/form-processor/
Preparing ./form-processor/ ./build/form-processor//function
Building: sathsarasa/form-processor:latest with python3 template. Please wait..
Sending build context to Docker daemon  10.24kB
...
Successfully built 128245656019
Successfully tagged sathsarasa/form-processor:latest
Image: sathsarasa/form-processor:latest built.
[0] < Building form-processor done.
[0] worker done.
[0] > Pushing form-processor [sathsarasa/form-processor:latest].
The push refers to repository [docker.io/sathsarasa/form-processor]
...
latest: digest: sha256:c700592a3a7f16875c2895dbfa41bd269631780d9195290141c245bec93a2257 size: 4286
[0] < Pushing form-processor [sathsarasa/form-processor:latest] done.
[0] worker done.
Deploying: form-processor.
WARNING! Communication is not secure, please consider using HTTPS. Letsencrypt.org offers free SSL/TLS certificates.
Deployed. 202 Accepted.
URL: http://192.168.99.100:31112/function/form-processor
```

1.  通过在 Web 浏览器中打开 URL 来打开**联系我们**表单：

`http://192.168.99.100:31112/function/contact-form`

联系表单应该如下所示：

![图 9.62：调用“联系我们”表单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_09_62.jpg)

###### 图 9.62：调用“联系我们”表单

1.  填写表单，然后提交表单，如下图所示：![图 9.63：提交联系我们表单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_09_63.jpg)

###### 图 9.63：提交联系我们表单

1.  检查步骤 9 中提供的电子邮件帐户`<TO_EMAIL>`以验证电子邮件发送：

![图 9.64：验证电子邮件发送](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_09_64.jpg)

###### 图 9.64：验证电子邮件发送
