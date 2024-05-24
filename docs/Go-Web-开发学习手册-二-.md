# Go Web 开发学习手册（二）

> 原文：[`zh.annas-archive.org/md5/2756E08144D91329B3B7569E0C2831DA`](https://zh.annas-archive.org/md5/2756E08144D91329B3B7569E0C2831DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：微服务和通信

我们的应用现在开始变得更加真实。在上一章中，我们为它们添加了一些 API 和客户端界面。

在过去几年中，微服务变得非常热门，主要是因为它们减少了非常大或单片应用的开发和支持负担。通过拆分这些单片应用，微服务实现了更加敏捷和并发的开发。它们可以让不同团队在不用太担心冲突、向后兼容性问题或者干扰应用的其他部分的情况下，分别处理应用的不同部分。

在本章中，我们将介绍微服务，并探讨 Go 语言如何在其中发挥作用，以实现它们甚至驱动它们的核心机制。

总结一下，我们将涵盖以下方面：

+   微服务方法介绍

+   利用微服务的利弊

+   理解微服务的核心

+   微服务之间的通信

+   将消息发送到网络

+   从另一个服务中读取

# 微服务方法介绍

如果你还没有遇到过微服务这个术语，或者没有深入探讨过它的含义，我们可以很快地揭开它的神秘面纱。微服务本质上是一个整体应用的独立功能，被拆分并通过一些通用的协议变得可访问。

通常情况下，微服务方法被用来拆分非常庞大的单片应用。

想象一下 2000 年代中期的标准 Web 应用。当需要新功能时，比如给新用户发送电子邮件的功能，它会直接添加到代码库中，并与应用的其他部分集成。

随着应用的增长，必要的测试覆盖范围也在增加。因此，关键错误的潜在可能性也在增加。在这种情况下，一个关键错误不仅会导致该组件（比如电子邮件系统）崩溃，还会导致整个应用崩溃。

这可能是一场噩梦，追踪、修补和重新部署，这正是微服务旨在解决的问题。

如果应用的电子邮件部分被分离到自己的应用中，它就具有了一定程度的隔离和保护，这样找到问题就容易得多。这也意味着整个堆栈不会因为有人在整个应用的一个小部分引入了关键错误而崩溃，如下图所示：

![微服务方法介绍](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_07_01.jpg)

考虑以下基本的示例架构，一个应用被拆分成四个独立的概念，它们在微服务框架中代表着自己的应用。

曾经，每个部分都存在于自己的应用中；现在它们被拆分成更小、更易管理的系统。应用之间的通信通过使用 REST API 端点的消息队列进行。

# 利用微服务的利弊

如果微服务在这一点上看起来像灵丹妙药，我们也应该注意到，这种方法并非没有自己的问题。是否值得进行权衡取决于整体组织方法。

正如前面提到的，稳定性和错误检测对于微服务来说是一个重大的生产级胜利。但如果考虑到应用不会崩溃的另一面，这也可能意味着问题会隐藏得比原本更长时间。整个站点崩溃是很难忽视的，但除非有非常健壮的日志记录，否则可能需要几个小时才能意识到电子邮件没有发送。

但微服务还有其他很大的优势。首先，利用外部标准通信协议（比如 REST）意味着你不会被锁定在单一语言中。

例如，如果你的应用程序的某个部分在 Node 中的编写比在 Go 中更好，你可以这样做，而不必重写整个应用程序。这是开发人员经常会面临的诱惑：重写整个应用程序，因为引入了新的和闪亮的语言应用程序或功能。好吧，微服务可以安全地实现这种行为——它允许开发人员或一组开发人员尝试某些东西，而无需深入到他们希望编写的特定功能之外。

这也带来了一个潜在的负面情景——因为应用程序组件是解耦的，所以围绕它们的机构知识也可以是解耦的。很少有开发人员可能了解足够多以使服务运行良好。团队中的其他成员可能缺乏语言知识，无法介入并修复关键错误。

最后一个，但很重要的考虑是，微服务架构通常意味着默认情况下是分布式环境。这导致我们面临的最大的即时警告是，这种情况几乎总是意味着最终一致性是游戏的名字。

由于每条消息都必须依赖于多个外部服务，因此您需要经历多层延迟才能使更改生效。

# 理解微服务的核心

你可能会想到一件事，当你考虑这个系统来设计协调工作的不和谐服务时：通信平台是什么？为了回答这个问题，我们会说有一个简单的答案和一个更复杂的答案。

简单的答案是 REST。这是一个好消息，因为您很可能对 REST 非常熟悉，或者至少从第五章中了解了一些内容，*RESTful API 的前端集成*。在那里，我们描述了利用 RESTful、无状态协议进行 API 通信的基础，并实现 HTTP 动词作为操作。

这让我们得出了更复杂的答案：在一个大型或复杂的应用程序中，并非所有内容都可以仅仅依靠 REST 来运行。有些事情需要状态，或者至少需要一定程度的持久一致性。

对于后者的问题，大多数微服务架构都以消息队列作为信息共享和传播的平台。消息队列充当一个通道，接收来自一个服务的 REST 请求，并将其保存，直到另一个服务检索请求进行进一步处理。

# 微服务之间的通信

有许多微服务之间进行通信的方法，正如前面提到的；REST 端点为消息提供了一个很好的着陆点。您可能还记得前面的图表，显示消息队列作为服务之间的中央通道。这是处理消息传递的最常见方式之一，我们将使用 RabbitMQ 来演示这一点。

在这种情况下，我们将展示当新用户注册到我们的 RabbitMQ 安装中的电子邮件队列以便传递消息时，这些消息将被电子邮件微服务接收。

### 注意

您可以在这里阅读有关 RabbitMQ 的更多信息，它使用**高级消息队列协议**（**AMQP**）：[`www.rabbitmq.com/`](https://www.rabbitmq.com/)。

要为 Go 安装 AMQP 客户端，我们建议使用 Sean Treadway 的 AMQP 包。您可以使用`go get`命令安装它。您可以在[github.com/streadway/amqp](http://github.com/streadway/amqp)上获取它

# 将消息发送到网络

有很多使用 RabbitMQ 的方法。例如，一种方法允许多个工作者完成相同的工作，作为在可用资源之间分配工作的方法。

毫无疑问，随着系统的增长，很可能会发现对该方法的使用。但在我们的小例子中，我们希望根据特定通道对任务进行分离。当然，这与 Go 的并发通道不相似，所以在阅读这种方法时请记住这一点。

但是要解释这种方法，我们可能有单独的交换机来路由我们的消息。在我们的示例中，我们可能有一个日志队列，其中来自所有服务的消息被聚合到一个单一的日志位置，或者一个缓存过期方法，当它们从数据库中删除时，从内存中删除缓存项。

在这个例子中，我们将实现一个电子邮件队列，可以从任何其他服务接收消息，并使用其内容发送电子邮件。这将使所有电子邮件功能都在核心和支持服务之外。

回想一下，在第五章中，*与 RESTful API 集成的前端*，我们添加了注册和登录方法。我们在这里最感兴趣的是`RegisterPOST()`，在这里我们允许用户注册我们的网站，然后评论我们的帖子。

新注册用户收到电子邮件并不罕见，无论是用于确认身份还是用于简单的欢迎消息。我们将在这里做后者，但添加确认是微不足道的；只是生成一个密钥，通过电子邮件发送，然后在链接被点击后启用用户。

由于我们使用了外部包，我们需要做的第一件事是导入它。

这是我们的做法：

```go
import (
  "bufio"
  "crypto/rand"
  "crypto/sha1"
  "database/sql"
  "encoding/base64"
  "encoding/json"
  "fmt"
  _ "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
  "github.com/gorilla/sessions"
  "github.com/streadway/amqp"
  "html/template"
  "io"
  "log"
  "net/http"
  "regexp"
  "text/template"
  "time"
)
```

请注意，这里我们包含了`text/template`，这并不是严格必要的，因为我们有`html/template`，但我们在这里注意到，以防您希望在单独的进程中使用它。我们还包括了`bufio`，我们将在同一模板处理过程中使用它。

为了发送电子邮件，有一个消息和一个电子邮件的标题将是有帮助的，所以让我们声明这些。在生产环境中，我们可能会有一个单独的语言文件，但在这一点上我们没有其他东西可以展示：

```go
var WelcomeTitle = "You've successfully registered!"
var WelcomeEmail = "Welcome to our CMS, {{Email}}!  We're glad you could join us."
```

这些只是我们在成功注册时需要利用的电子邮件变量。

由于我们正在将消息发送到线上，并将一些应用程序逻辑的责任委托给另一个服务，所以现在我们只需要确保我们的消息已被 RabbitMQ 接收。

接下来，我们需要连接到队列，我们可以通过引用或重新连接每条消息来传递。通常，您会希望将连接保持在队列中很长时间，但在测试时，您可能选择重新连接和关闭每次连接。

为了这样做，我们将把我们的 MQ 主机信息添加到我们的常量中：

```go
const (
  DBHost  = "127.0.0.1"
  DBPort  = ":3306"
  DBUser  = "root"
  DBPass  = ""
  DBDbase = "cms"
  PORT    = ":8080"
  MQHost  = "127.0.0.1"
  MQPort  = ":5672"
)
```

当我们创建一个连接时，我们将使用一种相对熟悉的`TCP Dial()`方法，它返回一个 MQ 连接。这是我们用于连接的函数：

```go
func MQConnect() (*amqp.Connection, *amqp.Channel, error) {
  url := "amqp://" + MQHost + MQPort
  conn, err := amqp.Dial(url)
  if err != nil {
    return nil, nil, err
  }
  channel, err := conn.Channel()
  if err != nil {
    return nil, nil, err
  }
  if _, err := channel.QueueDeclare("", false, true, false, false, nil); err != nil {
    return nil, nil, err
  }
  return conn, channel, nil
}
```

我们可以选择通过引用传递连接，或者将其作为全局连接，并考虑所有适用的注意事项。

### 提示

您可以在[`www.rabbitmq.com/heartbeats.html`](https://www.rabbitmq.com/heartbeats.html)了解更多关于 RabbitMQ 连接和检测中断连接的信息

从技术上讲，任何生产者（在本例中是我们的应用程序）都不会将消息推送到队列，而是将它们推送到交换机。RabbitMQ 允许您使用`rabbitmqctl` `list_exchanges`命令找到交换机（而不是`list_queues`）。在这里，我们使用一个空的交换机，这是完全有效的。队列和交换机之间的区别并不是微不足道的；后者负责定义围绕消息的规则，以便传递到一个或多个队列。

在我们的`RegisterPOST()`中，当成功注册时，让我们发送一个 JSON 编码的消息。我们需要一个非常简单的`struct`来维护我们需要的数据：

```go
type RegistrationData struct {
  Email   string `json:"email"`
  Message string `json:"message"`
}
```

现在，如果且仅如果注册过程成功，我们将创建一个新的`RegistrationData struct`：

```go
  res, err := database.Exec("INSERT INTO users SET user_name=?, user_guid=?, user_email=?, user_password=?", name, guid, email, password)

  if err != nil {
    fmt.Fprintln(w, err.Error)
  } else {
    Email := RegistrationData{Email: email, Message: ""}
    message, err := template.New("email").Parse(WelcomeEmail)
    var mbuf bytes.Buffer
    message.Execute(&mbuf, Email)
    MQPublish(json.Marshal(mbuf.String()))
    http.Redirect(w, r, "/page/"+pageGUID, 301)
  }
```

最后，我们需要实际发送我们的数据的函数`MQPublish()`：

```go
func MQPublish(message []byte) {
  err = channel.Publish(
    "email", // exchange
    "",      // routing key
    false,   // mandatory
    false,   // immediate
    amqp.Publishing{
      ContentType: "text/plain",
      Body:        []byte(message),
    })
}
```

# 从另一个服务中读取

现在我们已经在我们的应用程序中向消息队列发送了一条消息，让我们使用另一个微服务来从队列的另一端取出它。

为了展示微服务设计的灵活性，我们的次要服务将是一个连接到消息队列并监听电子邮件队列消息的 Python 脚本。当它找到一条消息时，它将解析消息并发送电子邮件。可选地，它可以将状态消息发布回队列或记录下来，但目前我们不会走这条路：

```go
import pika
import json
import smtplib
from email.mime.text import MIMEText

connection = pika.BlockingConnection(pika.ConnectionParameters( host='localhost'))
channel = connection.channel()
channel.queue_declare(queue='email')

print ' [*] Waiting for messages. To exit press CTRL+C'

def callback(ch, method, properties, body):
    print " [x] Received %r" % (body,)
    parsed = json.loads(body)
    msg = MIMEText()
    msg['From'] = 'Me'
    msg['To'] = parsed['email']
    msg['Subject'] = parsed['message']
    s = smtplib.SMTP('localhost')
    s.sendmail('Me', parsed['email'], msg.as_string())
    s.quit()

channel.basic_consume(callback,
                      queue='email',
                      no_ack=True)

channel.start_consuming()
```

# 总结

在本章中，我们试图通过利用微服务来将应用程序分解为不同的责任领域。在这个例子中，我们将我们应用程序的电子邮件方面委托给了另一个用 Python 编写的服务。

我们这样做是为了利用微服务或互连的较小应用作为可调用的网络化功能的概念。这种理念最近驱动着网络的很大一部分，并具有无数的好处和缺点。

通过这样做，我们实现了一个消息队列，它作为我们通信系统的支柱，允许每个组件以可靠和可重复的方式与其他组件交流。在这种情况下，我们使用了一个 Python 应用程序来读取消息，这些消息是从我们的 Go 应用程序通过 RabbitMQ 发送的，并且处理了那些电子邮件数据。

在第八章*日志和测试*中，我们将专注于日志记录和测试，这可以用来扩展微服务的概念，以便我们可以从错误中恢复，并了解在过程中可能出现问题的地方。


# 第八章：日志和测试

在上一章中，我们讨论了将应用程序责任委托给可通过 API 访问的网络服务和由消息队列处理的进程内通信。

这种方法模仿了将大型单片应用程序分解为较小块的新兴趋势；因此，允许开发人员利用不同的语言、框架和设计。

我们列举了这种方法的一些优点和缺点；大多数优点涉及保持开发的敏捷和精益，同时防止可能导致整个应用程序崩溃和级联错误的灾难性错误，一个很大的缺点是每个单独组件的脆弱性。例如，如果我们的电子邮件微服务在大型应用程序中有糟糕的代码，错误会很快显现出来，因为它几乎肯定会直接对另一个组件产生可检测的影响。但通过将进程隔离为微服务的一部分，我们也隔离了它们的状态和状态。

这就是本章内容发挥作用的地方——在 Go 应用程序中进行测试和记录的能力是该语言设计的优势。通过在我们的应用程序中利用这些功能，它可以扩展到包括更多的微服务；因此，我们可以更好地跟踪系统中任何问题的齿轮，而不会给整个应用程序增加太多额外的复杂性。

在本章中，我们将涵盖以下主题：

+   引入 Go 中的日志记录

+   IO 日志记录

+   格式化你的输出

+   使用 panic 和致命错误

+   引入 Go 中的测试

# 引入 Go 中的日志记录

Go 提供了无数种方法来将输出显示到`stdout`，最常见的是`fmt`包的`Print`和`Println`。事实上，你可以完全放弃`fmt`包，只使用`print()`或`println()`。

在成熟的应用程序中，你不太可能看到太多这样的情况，因为仅仅显示输出而没有能力将其存储在某个地方以进行调试或后续分析是罕见的，也缺乏实用性。即使你只是向用户输出一些反馈，通常也有意义这样做，并保留将其保存到文件或其他地方的能力，这就是`log`包发挥作用的地方。本书中的大多数示例出于这个原因使用了`log.Println`而不是`fmt.Println`。如果你在某个时候选择用其他（或附加）`io.Writer`替换`stdout`，这种更改是微不足道的。

# 记录到 IO

到目前为止，我们一直在将日志记录到`stdout`，但你可以利用任何`io.Writer`来接收日志数据。事实上，如果你希望输出路由到多个地方，你可以使用多个`io.Writer`。

## 多个记录器

大多数成熟的应用程序将写入多个日志文件，以区分需要保留的各种类型的消息。

这种最常见的用例在 Web 服务器中找到。它们通常保留一个`access.log`和一个`error.log`文件，以允许分析所有成功的请求；然而，它们还保留了不同类型消息的单独记录。

在下面的示例中，我们修改了我们的日志记录概念，包括错误和警告。

```go
package main

import (
  "log"
  "os"
)
var (
  Warn   *log.Logger
  Error  *log.Logger
  Notice *log.Logger
)
func main() {
  warnFile, err := os.OpenFile("warnings.log", os.O_RDWR|os.O_APPEND, 0660)
  defer warnFile.Close()
  if err != nil {
    log.Fatal(err)
  }
  errorFile, err := os.OpenFile("error.log", os.O_RDWR|os.O_APPEND, 0660)
  defer errorFile.Close()
  if err != nil {
    log.Fatal(err)
  }

  Warn = log.New(warnFile, "WARNING: ", Log.LstdFlags
)

  Warn.Println("Messages written to a file called 'warnings.log' are likely to be ignored :(")

  Error = log.New(errorFile, "ERROR: ", log.Ldate|log.Ltime)
  Error.SetOutput(errorFile)
  Error.Println("Error messages, on the other hand, tend to catch attention!")
}
```

我们可以采用这种方法来存储各种信息。例如，如果我们想要存储注册错误，我们可以创建一个特定的注册错误记录器，并在遇到该过程中的错误时允许类似的方法。

```go
  res, err := database.Exec("INSERT INTO users SET user_name=?, user_guid=?, user_email=?, user_password=?", name, guid, email, passwordEnc)

  if err != nil {
    fmt.Fprintln(w, err.Error)
    RegError.Println("Could not complete registration:", err.Error)
  } else {
    http.Redirect(w, r, "/page/"+pageGUID, 301)
  }
```

# 格式化你的输出

在实例化新的`Logger`时，你可以传递一些有用的参数和/或辅助字符串，以帮助定义和澄清输出。每个日志条目都可以以一个字符串开头，这在审查多种类型的日志条目时可能会有所帮助。你还可以定义你希望在每个条目上的日期和时间格式。

要创建自定义格式的日志，只需调用`New()`函数，并使用`io.Writer`，如下所示：

```go
package main

import (
  "log"
  "os"
)

var (
  Warn   *log.Logger
  Error  *log.Logger
  Notice *log.Logger
)

func main() {
  warnFile, err := os.OpenFile("warnings.log", os.O_RDWR|os.O_APPEND, 0660)
  defer warnFile.Close()
  if err != nil {
    log.Fatal(err)
  }
  Warn = log.New(warnFile, "WARNING: ", log.Ldate|log.Ltime)

  Warn.Println("Messages written to a file called 'warnings.log' are likely to be ignored :(")
  log.Println("Done!")
}
```

这不仅允许我们使用`log.Println`函数与我们的`stdout`，还允许我们在名为`warnings.log`的日志文件中存储更重要的消息。使用`os.O_RDWR|os.O_APPEND`常量允许我们写入文件并使用追加文件模式，这对于日志记录很有用。

# 使用 panic 和致命错误

除了简单地存储应用程序的消息之外，您还可以创建应用程序的 panic 和致命错误，这将阻止应用程序继续运行。这对于任何错误不会导致执行停止的用例至关重要，因为这可能会导致潜在的安全问题、数据丢失或任何其他意外后果。这些类型的机制通常被限制在最关键的错误上。

何时使用`panic()`方法并不总是清楚的，但在实践中，这应该被限制在不可恢复的错误上。不可恢复的错误通常意味着状态变得模糊或无法保证。

例如，对从数据库获取的记录进行操作，如果未能从数据库返回预期的结果，则可能被视为不可恢复的，因为未来的操作可能发生在过时或丢失的数据上。

在下面的例子中，我们可以实现一个 panic，我们无法创建一个新用户；这很重要，这样我们就不会尝试重定向或继续进行任何进一步的创建步骤：

```go
  if err != nil {
    fmt.Fprintln(w, err.Error)
    RegError.Println("Could not complete registration:", err.Error)
    panic("Error with registration,")
  } else {
    http.Redirect(w, r, "/page/"+pageGUID, 301)
  }
```

请注意，如果您想强制出现此错误，您可以在查询中故意制造一个 MySQL 错误：

```go
  res, err := database.Exec("INSERT INTENTIONAL_ERROR INTO users SET user_name=?, user_guid=?, user_email=?, user_password=?", name, guid, email, passwordEnc)
```

当触发此错误时，您将在相应的日志文件或`stdout`中找到它：

![使用 panic 和致命错误](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_08_01.jpg)

在上面的例子中，我们利用 panic 作为一个硬性停止，这将阻止进一步的执行，从而可能导致进一步的错误和/或数据不一致。如果不需要硬性停止，使用`recover()`函数允许您在问题得到解决或减轻后重新进入应用程序流程。

# 在 Go 中引入测试

Go 打包了大量出色的工具，用于确保您的代码干净、格式良好、没有竞争条件等。从`go vet`到`go fmt`，许多在其他语言中需要单独安装的辅助应用程序都作为 Go 的一部分打包了。

测试是软件开发的关键步骤。单元测试和测试驱动开发有助于发现对开发人员来说并不立即显而易见的错误。通常我们对应用程序太熟悉，以至于无法发现可能引发其他未发现的错误的可用性错误。

Go 的测试包允许对实际功能进行单元测试，同时确保所有依赖项（网络、文件系统位置）都可用；在不同的环境中进行测试可以让您在用户之前发现这些错误。

如果您已经在使用单元测试，Go 的实现将会非常熟悉和愉快：

```go
package example

func Square(x int) int {
  y := x * x
  return y
}
```

这保存为`example.go`。接下来，创建另一个 Go 文件，测试这个平方根功能，代码如下：

```go
package example

import (
  "testing"
)

func TestSquare(t *testing.T) {
  if v := Square(4); v != 16 {
    t.Error("expected", 16, "got", v)
  }
}
```

您可以通过进入目录并简单地输入`go test -v`来运行此测试。如预期的那样，给定我们的测试输入，这是通过的：

![在 Go 中引入测试](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_08_02.jpg)

这个例子显然是微不足道的，但为了演示如果您的测试失败会看到什么，让我们修改我们的`Square()`函数如下：

```go
func Square(x int) int {
  y := x
  return y
}
```

再次运行测试后，我们得到：

![在 Go 中引入测试](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_08_03.jpg)

对命令行应用程序进行命令行测试与与 Web 交互是不同的。我们的应用程序包括标准的 HTML 端点以及 API 端点；测试它需要比我们之前使用的方法更多的细微差别。

幸运的是，Go 还包括一个专门用于测试 HTTP 应用程序结果的包，`net/http/httptest`。

与前面的例子不同，`httptest`让我们评估从我们的各个函数返回的一些元数据，这些函数在 HTTP 版本的单元测试中充当处理程序。

那么，让我们来看一种简单的评估我们的 HTTP 服务器可能产生的内容的方法，通过生成一个快速端点，它简单地返回一年中的日期。

首先，我们将向我们的 API 添加另一个端点。让我们将这个处理程序示例分离成自己的应用程序，以便隔离其影响：

```go
package main

import (
  "fmt"
  "net/http"
  "time"
)

func testHandler(w http.ResponseWriter, r *http.Request) {
  t := time.Now()
  fmt.Fprintln(w, t.YearDay())
}

func main() {
  http.HandleFunc("/test", testHandler)
  http.ListenAndServe(":8080", nil)
}
```

这将简单地通过 HTTP 端点`/test`返回一年中的日期（1-366）。那么我们如何测试这个呢？

首先，我们需要一个专门用于测试的新文件。当涉及到需要达到多少测试覆盖率时，这通常对开发人员或组织很有帮助，理想情况下，我们希望覆盖每个端点和方法，以获得相当全面的覆盖。在这个例子中，我们将确保我们的一个 API 端点返回一个正确的状态码，以及一个`GET`请求返回我们在开发中期望看到的内容：

```go
package main

import (
  "io/ioutil"
  "net/http"
  "net/http/httptest"
  "testing"
)

func TestHandler(t *testing.T) {
  res := httptest.NewRecorder()
  path := "http://localhost:4000/test"
  o, err := http.NewRequest("GET", path, nil)
  http.DefaultServeMux.ServeHTTP(res, req)
  response, err := ioutil.ReadAll(res.Body)
  if string(response) != "115" || err != nil {
    t.Errorf("Expected [], got %s", string(response))
  }
}
```

现在，我们可以通过确保我们的端点通过（200）或失败（404）并返回我们期望的文本来在我们的实际应用程序中实现这一点。我们还可以自动添加新内容并对其进行验证，通过这些示例后，您应该有能力承担这一任务。

鉴于我们有一个 hello-world 端点，让我们编写一个快速测试，验证我们从端点得到的响应，并看看我们如何在`test.go`文件中获得一个正确的响应：

```go
package main

import (
  "net/http"
  "net/http/httptest"
  "testing"
)

func TestHelloWorld(t *testing.T) {

  req, err := http.NewRequest("GET", "/page/hello-world", nil)
  if err != nil {
    t.Fatal("Creating 'GET /page/hello-world' request failed!")
  }
  rec := httptest.NewRecorder()
  Router().ServeHTTP(rec, req)
}
```

在这里，我们可以测试我们是否得到了我们期望的状态码，尽管它很简单，但这并不一定是一个微不足道的测试。实际上，我们可能还会创建一个应该失败的测试，以及另一个检查我们是否得到了我们期望的 HTTP 响应的测试。但这为更复杂的测试套件，比如健全性测试或部署测试，奠定了基础。例如，我们可能会生成仅供开发使用的页面，从模板生成 HTML 内容，并检查输出以确保我们的页面访问和模板解析按照我们的期望工作。

### 注意

在[`golang.org/pkg/net/http/httptest/`](https://golang.org/pkg/net/http/httptest/)上阅读有关使用 http 和 httptest 包进行测试的更多信息

# 总结

简单地构建一个应用程序甚至不到一半的战斗，作为开发人员进行用户测试引入了测试策略中的巨大差距。测试覆盖率是一种关键武器，当我们发现错误之前，它可以帮助我们找到错误。

幸运的是，Go 提供了实现自动化单元测试所需的所有工具，以及支持它所需的日志记录架构。

在本章中，我们看了日志记录器和测试选项。通过为不同的消息生成多个记录器，我们能够将由内部应用程序故障引起的警告与错误分开。

然后，我们使用测试和`httptest`包来进行单元测试，自动检查我们的应用程序并通过测试潜在的破坏性更改来保持其当前状态。

在第九章*安全*中，我们将更彻底地研究实施安全性；从更好的 TLS/SSL 到防止注入和中间人和跨站点请求伪造攻击。


# 第九章：安全

在上一章中，我们看了如何存储应用程序生成的信息，以及向我们的套件添加单元测试，以确保应用程序的行为符合我们的期望，并在不符合期望时诊断错误。

在那一章中，我们没有为我们的博客应用程序添加太多功能；所以现在让我们回到那里。我们还将把本章的一些日志记录和测试功能扩展到我们的新功能中。

到目前为止，我们一直在开发一个 Web 应用程序的框架，该应用程序实现了博客数据和用户提交的评论的一些基本输入和输出。就像任何公共网络服务器一样，我们的服务器也容易受到各种攻击。

这些问题并不是 Go 独有的，但我们有一系列工具可以实施最佳实践，并扩展我们的服务器和应用程序以减轻常见问题。

在构建一个公开访问的网络应用程序时，一个快速简便的常见攻击向量参考指南是**开放网络应用程序安全项目**（**OWASP**），它提供了一个定期更新的最关键的安全问题清单。OWASP 可以在[`www.owasp.org/`](https://www.owasp.org/)找到。其十大项目编制了最常见和/或最关键的网络安全问题。虽然它不是一个全面的清单，并且在更新之间容易过时，但在编制潜在攻击向量时仍然是一个很好的起点。

多年来，一些最普遍的攻击向量不幸地一直存在；尽管安全专家一直在大声疾呼其严重性。有些攻击向量在 Web 上的曝光迅速减少（比如注入），但它们仍然会长期存在，甚至在遗留应用程序逐渐淘汰的情况下。

以下是 2013 年末最近的十大漏洞中的四个概述，其中一些我们将在本章中讨论：

+   **注入**：任何未经信任的数据有机会在不转义的情况下被处理，从而允许数据操纵或访问数据或系统，通常不会公开暴露。最常见的是 SQL 注入。

+   **破坏的身份验证**：这是由于加密算法不佳，密码要求不严格，会话劫持是可行的。

+   **XSS**：跨站点脚本允许攻击者通过在另一个站点上注入和执行脚本来访问敏感信息。

+   **跨站点请求伪造**：与 XSS 不同，这允许攻击向量来自另一个站点，但它会欺骗用户在另一个站点上完成某些操作。

虽然其他攻击向量从相关到不相关都有，但值得评估我们没有涵盖的攻击向量，看看其他可能存在利用的地方。

首先，我们将看一下使用 Go 在应用程序中实现和强制使用 HTTPS 的最佳方法。

# 到处使用 HTTPS - 实施 TLS

在第五章中，*前端与 RESTful API 的集成*，我们讨论了创建自签名证书并在我们的应用程序中使用 HTTPS/TLS。但让我们快速回顾一下为什么这对于我们的应用程序和 Web 的整体安全性如此重要。

首先，简单的 HTTP 通常不会为流量提供加密，特别是对于重要的请求头值，如 cookie 和查询参数。我们在这里说通常是因为 RFC 2817 确实指定了在 HTTP 协议上使用 TLS 的系统，但几乎没有使用。最重要的是，它不会给用户提供必要的明显反馈，以注册网站的安全性。

其次，HTTP 流量容易受到中间人攻击。

另一个副作用是：Google（也许其他搜索引擎）开始偏爱 HTTPS 流量而不是不太安全的对应物。

直到相对最近，HTTPS 主要被限制在电子商务应用程序中，但利用 HTTP 的不足的攻击的可用性和普遍性的增加——如侧面攻击和中间人攻击——开始将 Web 的大部分推向 HTTPS。

您可能已经听说过由此产生的运动和座右铭**HTTPS 无处不在**，这也渗透到了强制网站使用实施最安全可用协议的浏览器插件中。

我们可以做的最简单的事情之一是扩展第六章中的工作，*会话和 Cookie*是要求所有流量通过 HTTPS 重新路由 HTTP 流量。还有其他方法可以做到这一点，正如我们将在本章末看到的那样，但它可以相当简单地实现。

首先，我们将实现一个`goroutine`来同时为我们的 HTTPS 和 HTTP 流量提供服务，分别使用`tls.ListenAndServe`和`http.ListenAndServe`：

```go
  var wg sync.WaitGroup
  wg.Add(1)
  go func() {
    http.ListenAndServe(PORT, http.HandlerFunc(redirectNonSecure))
    wg.Done()
  }()
  wg.Add(1)
  go func() {
    http.ListenAndServeTLS(SECUREPORT, "cert.pem", "key.pem", routes)
    wg.Done()
  }()

  wg.Wait()
```

这假设我们将一个`SECUREPORT`常量设置为`":443"`，就像我们将`PORT`设置为`":8080"`一样，或者您选择的任何其他端口。没有什么可以阻止您在 HTTPS 上使用另一个端口；这里的好处是浏览器默认将`https://`请求重定向到端口`443`，就像它将 HTTP 请求重定向到端口`80`，有时会回退到端口`8080`一样。请记住，在许多情况下，您需要以 sudo 或管理员身份运行以使用低于`1000`的端口启动。

您会注意到在前面的示例中，我们使用了一个专门用于 HTTP 流量的处理程序`redirectNonSecure`。这实现了一个非常基本的目的，正如您在这里所看到的：

```go
func redirectNonSecure(w http.ResponseWriter, r *http.Request) {
  log.Println("Non-secure request initiated, redirecting.")
  redirectURL := "https://" + serverName + r.RequestURI
  http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}
```

在这里，`serverName`被明确设置。

从请求中获取域名或服务器名称可能存在一些潜在问题，因此最好在可能的情况下明确设置这一点。

在这里添加的另一个非常有用的部分是**HTTP 严格传输安全**（**HSTS**），这种方法与兼容的消费者结合使用，旨在减轻协议降级攻击（如强制/重定向到 HTTP）。

这只是一个 HTTPS 标头，当被使用时，将自动处理并强制执行`https://`请求，以替代使用较不安全的协议。

OWASP 建议为此标头使用以下设置：

```go
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

请注意，此标头在 HTTP 上被忽略。

# 防止 SQL 注入

尽管注入仍然是当今 Web 上最大的攻击向量之一，但大多数语言都有简单而优雅的方法来通过准备好的语句和经过消毒的输入来防止或大大减轻留下易受攻击的 SQL 注入的可能性。

但即使使用提供这些服务的语言，仍然有机会留下漏洞的空间。

无论是在 Web 上还是在服务器上或独立的可执行文件中，任何软件开发的核心原则都是不要相信从外部（有时是内部）获取的输入数据。

这个原则对于任何语言都是正确的，尽管有些语言通过准备好的查询或抽象（如对象关系映射（ORM））使与数据库的交互更安全和/或更容易。

从本质上讲，Go 没有任何 ORM，因为从技术上讲，甚至没有一个 O（对象）（Go 不是纯粹的面向对象的），很难在这个领域复制许多面向对象语言所拥有的东西。

然而，有许多第三方库试图通过接口和结构来强制 ORM，但是很多这些都可以很容易地手工编写，因为您可能比任何库更了解您的模式和数据结构，即使是在抽象的意义上。

然而，对于 SQL，Go 具有几乎支持 SQL 的任何数据库的强大和一致的接口。

为了展示 SQL 注入漏洞如何在 Go 应用程序中简单地出现，我们将比较原始的 SQL 查询和准备好的语句。

当我们从数据库中选择页面时，我们使用以下查询：

```go
err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid="+requestGUID, pageGUID).Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date)
```

这向我们展示了如何通过接受未经处理的用户输入来打开您的应用程序以进行注入漏洞。在这种情况下，任何请求类似于

`/page/foo;delete from pages`理论上可以迅速清空你的`pages`表。

我们在路由器级别有一些初步的消毒工作，这在这方面有所帮助。由于我们的 mux 路由只包括字母数字字符，我们可以避免一些需要被转义的字符被路由到我们的`ServePage`或`APIPage`处理程序中：

```go
  routes.HandleFunc("/page/{guid:[0-9a-zA\\-]+}", ServePage)
  routes.HandleFunc("/api/page/{id:[\\w\\d\\-]+}", APIPage).
    Methods("GET").
    Schemes("https")
```

然而，这并不是一个绝对可靠的方法。前面的查询接受了原始输入并将其附加到 SQL 查询中，但是我们可以在 Go 中使用参数化、准备好的查询来更好地处理这个问题。以下是我们最终使用的内容：

```go
  err := database.QueryRow("SELECT page_title,page_content,page_date FROM pages WHERE page_guid=?", pageGUID).Scan(&thisPage.Title, &thisPage.Content, &thisPage.Date)
  if err != nil {
    http.Error(w, http.StatusText(404), http.StatusNotFound)
    log.Println("Couldn't get page!")
    return
  }
```

这种方法在 Go 的任何查询接口中都可以使用，它使用`?`来代替值作为可变参数的查询：

```go
res, err := db.Exec("INSERT INTO table SET field=?, field2=?", value1, value2)
rows, err := db.Query("SELECT * FROM table WHERE field2=?",value2)
statement, err := db.Prepare("SELECT * FROM table WHERE field2=?",value2)
row, err := db.QueryRow("SELECT * FROM table WHERE field=?",value1)
```

虽然所有这些在 SQL 世界中有着略微不同的目的，但它们都以相同的方式实现了准备好的查询。

# 防止跨站脚本攻击

我们简要提到了跨站脚本攻击和限制它作为一种向量，这使得您的应用程序对所有用户更安全，而不受少数不良分子的影响。问题的关键在于一个用户能够添加危险内容，并且这些内容将被显示给用户，而不会清除使其危险的方面。

最终你在这里有一个选择——在输入时对数据进行消毒，或者在呈现给其他用户时对数据进行消毒。

换句话说，如果有人产生了一个包含`script`标签的评论文本块，你必须小心阻止其他用户的浏览器渲染它。你可以选择保存原始 HTML，然后在输出渲染时剥离所有或只剥离敏感标签。或者，你可以在输入时对其进行编码。

没有标准答案；然而，您可能会发现遵循前一种方法有价值，即接受任何内容并对输出进行消毒。

这两种方法都存在风险，但这种方法允许您保留消息的原始意图，如果您选择在以后改变您的方法。缺点是当然你可能会意外地允许一些原始数据通过未经处理的：

```go
template.HTMLEscapeString(string)
template.JSEscapeString(inputData)
```

第一个函数将获取数据并删除 HTML 的格式，以产生用户输入的消息的纯文本版本。

第二个函数将做类似的事情，但是针对 JavaScript 特定的值。您可以使用类似以下示例的快速脚本很容易地测试这些功能：

```go
package main

import (
  "fmt"
  "github.com/gorilla/mux"
  "html/template"
  "net/http"
)

func HTMLHandler(w http.ResponseWriter, r *http.Request) {
  input := r.URL.Query().Get("input")
  fmt.Fprintln(w, input)
}

func HTMLHandlerSafe(w http.ResponseWriter, r *http.Request) {
  input := r.URL.Query().Get("input")
  input = template.HTMLEscapeString(input)
  fmt.Fprintln(w, input)
}

func JSHandler(w http.ResponseWriter, r *http.Request) {
  input := r.URL.Query().Get("input")
  fmt.Fprintln(w, input)
}

func JSHandlerSafe(w http.ResponseWriter, r *http.Request) {
  input := r.URL.Query().Get("input")
  input = template.JSEscapeString(input)
  fmt.Fprintln(w, input)
}

func main() {
  router := mux.NewRouter()
  router.HandleFunc("/html", HTMLHandler)
  router.HandleFunc("/js", JSHandler)
  router.HandleFunc("/html_safe", HTMLHandlerSafe)
  router.HandleFunc("/js_safe", JSHandlerSafe)
  http.ListenAndServe(":8080", router)
}
```

如果我们从不安全的端点请求，我们将得到我们的数据返回：

![防止跨站脚本攻击](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_09_01.jpg)

将此与`/html_safe`进行比较，后者会自动转义输入，您可以在其中看到内容以其经过处理的形式：

![防止跨站脚本攻击](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_09_02.jpg)

这一切都不是绝对可靠的，但如果您选择按用户提交的方式接受输入数据，您将希望寻找一些方法来在结果显示时传递这些信息，而不会让其他用户受到跨站脚本攻击的威胁。

# 防止跨站请求伪造（CSRF）

虽然我们在这本书中不会深入讨论 CSRF，但总的来说，它是一系列恶意行为者可以使用的方法，以欺骗用户在另一个站点上执行不需要的操作。

由于它至少在方法上与跨站脚本攻击有关，现在谈论它是值得的。

这最明显的地方是在表单中；把它想象成一个允许你发送推文的 Twitter 表单。如果第三方强制代表用户在没有他们同意的情况下请求，想象一下类似这样的情况：

```go
<h1>Post to our guestbook (and not twitter, we swear!)</h1>
  <form action="https://www.twitter.com/tweet" method="POST">
  <input type="text" placeholder="Your Name" />
  <textarea placeholder="Your Message"></textarea>
  <input type="hidden" name="tweet_message" value="Make sure to check out this awesome, malicious site and post on their guestbook" />
  <input type="submit" value="Post ONLY to our guestbook" />
</form>
```

没有任何保护，任何发布到这个留言簿的人都会无意中帮助传播垃圾邮件到这次攻击中。

显然，Twitter 是一个成熟的应用程序，早就处理了这个问题，但你可以得到一个大致的想法。你可能会认为限制引用者会解决这个问题，但这也可以被欺骗。

最简单的解决方案是为表单提交生成安全令牌，这可以防止其他网站能够构造有效的请求。

当然，我们的老朋友 Gorilla 在这方面也提供了一些有用的工具。最相关的是`csrf`包，其中包括用于生成请求令牌的工具，以及预先制作的表单字段，如果违反或忽略将产生`403`。

生成令牌的最简单方法是将其作为您的处理程序将用于生成模板的接口的一部分，就像我们的`ApplicationAuthenticate()`处理程序一样：

```go
    Authorize.TemplateTag = csrf.TemplateField(r)
    t.ExecuteTemplate(w, "signup_form.tmpl", Authorize)
```

此时，我们需要在我们的模板中公开`{{.csrfField}}`。要进行验证，我们需要将其链接到我们的`ListenAndServe`调用：

```go
    http.ListenAndServe(PORT, csrf.Protect([]byte("32-byte-long-auth-key"))(r))
```

# 保护 cookie

我们之前研究过的攻击向量之一是会话劫持，我们在 HTTP 与 HTTPS 的背景下讨论了这个问题，以及其他人如何看到网站身份关键信息的方式。

对于许多非 HTTPS 应用程序来说，在公共网络上找到这些数据非常简单，这些应用程序利用会话作为确定性 ID。事实上，一些大型应用程序允许会话 ID 在 URL 中传递。

在我们的应用程序中，我们使用了 Gorilla 的`securecookie`包，它不依赖于 HTTPS，因为 cookie 值本身是使用 HMAC 哈希编码和验证的。

生成密钥本身可以非常简单，就像我们的应用程序和`securecookie`文档中所演示的那样：

```go
var hashKey = []byte("secret hash key")
var blockKey = []byte("secret-er block key")
var secureKey = securecookie.New(hashKey, blockKey)
```

### 注意

有关 Gorilla 的`securecookie`包的更多信息，请参见：[`www.gorillatoolkit.org/pkg/securecookie`](http://www.gorillatoolkit.org/pkg/securecookie)

目前，我们应用程序的服务器首先使用 HTTPS 和安全 cookie，这意味着我们可能对在 cookie 本身中存储和识别数据感到更有信心。我们大部分的创建/更新/删除操作都是在 API 级别进行的，这仍然实现了会话检查，以确保我们的用户已经通过身份验证。

# 使用 secure 中间件

在本章中，快速实施一些安全修复（和其他内容）的更有帮助的软件包之一是 Cory Jacobsen 的一个软件包，贴心地称为`secure`。

Secure 提供了许多有用的实用程序，例如 SSL 重定向（正如我们在本章中实现的那样），允许的主机，HSTS 选项和 X-Frame-Options 的简写，用于防止您的网站被加载到框架中。

这其中涵盖了我们在本章中研究的一些主题，并且基本上是最佳实践。作为一个中间件，secure 可以是一种快速覆盖这些最佳实践的简单方法。

### 注意

要获取`secure`，只需在[github.com/unrolled/secure](http://github.com/unrolled/secure)上获取它。

# 摘要

虽然本章并不是对 Web 安全问题和解决方案的全面审查，但我们希望解决一些由 OWASP 和其他人提出的最大和最常见的向量之一。

在本章中，我们涵盖或审查了防止这些问题渗入您的应用程序的最佳实践。

在第十章中，*缓存、代理和性能改进*，我们将讨论如何使您的应用程序在流量增加的同时保持可扩展性和速度。


# 第十章：缓存、代理和性能改进

我们已经涵盖了大量关于 Web 应用程序的内容，您需要连接数据源，渲染模板，利用 SSL/TLS，为单页应用构建 API 等等。

尽管基本原理很清楚，但您可能会发现，根据这些准则构建的应用程序投入生产后可能会迅速出现一些问题，特别是在负载较重的情况下。

在上一章中，我们通过解决 Web 应用程序中一些最常见的安全问题，实施了一些最佳安全实践。让我们在本章中也做同样的事情，通过应用最佳实践来解决一些性能和速度方面的最大问题。

为了做到这一点，我们将查看管道中一些最常见的瓶颈，并看看我们如何减少这些瓶颈，使我们的应用在生产中尽可能高效。

具体来说，我们将确定这些瓶颈，然后寻找反向代理和负载平衡，将缓存实施到我们的应用程序中，利用**SPDY**，以及了解如何使用托管云服务来通过减少到达我们应用程序的请求数来增强我们的速度计划。

通过本章的结束，我们希望能够提供工具，帮助任何 Go 应用程序充分利用我们的环境，发挥最佳性能。

在本章中，我们将涵盖以下主题：

+   识别瓶颈

+   实施反向代理

+   实施缓存策略

+   实施 HTTP/2

# 识别瓶颈

为了简化事情，对于您的应用程序，有两种类型的瓶颈，一种是由开发和编程缺陷引起的，另一种是由底层软件或基础设施限制引起的。

对于前者的答案很简单，找出糟糕的设计并修复它。在糟糕的代码周围打补丁可能会隐藏安全漏洞，或者延迟更大的性能问题被及时发现。

有时，这些问题源于缺乏压力测试；在本地性能良好的代码并不保证在不施加人为负载的情况下能够扩展。缺乏这种测试有时会导致生产中出现意外的停机时间。

然而，忽略糟糕的代码作为问题的根源，让我们来看看一些其他常见的问题：

+   磁盘 I/O

+   数据库访问

+   高内存/CPU 使用率

+   缺乏并发支持

当然还有数百种问题，例如网络问题、某些应用程序中的垃圾收集开销、不压缩有效载荷/标头、非数据库死锁等等。

高内存和 CPU 使用率往往是结果而不是原因，但许多其他原因是特定于某些语言或环境的。

对于我们的应用程序，数据库层可能是一个薄弱点。由于我们没有进行缓存，每个请求都会多次命中数据库。ACID 兼容的数据库（如 MySQL/PostgreSQL）因负载而崩溃而臭名昭著，而对于不那么严格的键/值存储和 NoSQL 解决方案来说，在相同硬件上不会有问题。数据库一致性的成本对此有很大的影响，这是选择传统关系数据库的权衡之一。

# 实施反向代理

正如我们现在所知道的，与许多语言不同，Go 配备了完整和成熟的 Web 服务器平台，其中包括`net/http`。

最近，一些其他语言已经配备了用于本地开发的小型玩具服务器，但它们并不适用于生产。事实上，许多明确警告不要这样做。一些常见的是 Ruby 的 WEBrick，Python 的 SimpleHTTPServer 和 PHP 的-S。其中大多数都存在并发问题，导致它们无法成为生产中的可行选择。

Go 的`net/http`是不同的；默认情况下，它可以轻松处理这些问题。显然，这在很大程度上取决于底层硬件，但在紧要关头，您可以成功地原生使用它。许多网站正在使用`net/http`来提供大量的流量。

但即使是强大的基础 web 服务器也有一些固有的局限性：

+   它们缺乏故障转移或分布式选项

+   它们在上游具有有限的缓存选项

+   它们不能轻易负载平衡传入的流量

+   它们不能轻易集中日志记录

这就是反向代理的作用。反向代理代表一个或多个服务器接受所有传入的流量，并通过应用前述（和其他）选项和优势来分发它。另一个例子是 URL 重写，这更适用于可能没有内置路由和 URL 重写的基础服务。

在你的 web 服务器（如 Go）前放置一个简单的反向代理有两个重要的优势：缓存选项和无需访问基础应用程序即可提供静态内容的能力。

反向代理站点的最受欢迎的选项之一是 Nginx（发音为 Engine-X）。虽然 Nginx 本身是一个 web 服务器，但它早期因轻量级和并发性而广受赞誉。它很快成为了前端应用程序在其他较慢或较重的 web 服务器（如 Apache）前的首要防御。近年来情况有所改变，因为 Apache 在并发选项和利用替代事件和线程的方面已经赶上了。以下是一个反向代理 Nginx 配置的示例：

```go
server {
  listen 80;
  root /var/;
  index index.html index.htm;

  large_client_header_buffers 4 16k;

  # Make site accessible from http://localhost/
  server_name localhost

  location / {
    proxy_pass http://localhost:8080;
    proxy_redirect off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }

}
```

在这种情况下，请确保您的 Go 应用程序正在端口`8080`上运行，并重新启动 Nginx。对`http//:port 80`的请求将通过 Nginx 作为反向代理传递到您的应用程序。您可以通过查看标头或在浏览器的**开发人员工具**中进行检查。

![实施反向代理](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-webdev/img/B04294_10_01.jpg)

请记住，我们希望尽可能支持 TLS/SSL，但在这里提供反向代理只是改变端口的问题。我们的应用程序应该在另一个端口上运行，可能是一个附近的端口，以便清晰，然后我们的反向代理将在端口`443`上运行。

提醒一下，任何端口都可以用于 HTTP 或 HTTPS。但是，当未指定端口时，浏览器会自动将其定向到`443`以进行安全连接。只需修改`nginx.conf`和我们应用程序的常量即可。

```go
server {
  listen 443;
  location / {
     proxy_pass http://localhost:444;
```

让我们看看如何修改我们的应用程序，如下面的代码所示：

```go
const (
  DBHost  = "127.0.0.1"
  DBPort  = ":3306"
  DBUser  = "root"
  DBPass  = ""
  DBDbase = "cms"
  PORT    = ":444"
)
```

这使我们能够通过前端代理传递 SSL 请求。

### 提示

在许多 Linux 发行版中，您需要 SUDO 或 root 权限才能使用 1000 以下的端口。

# 实施缓存策略

有许多方法可以决定何时创建和何时过期缓存项，因此我们将看一种更简单更快的方法。但是，如果您有兴趣进一步开发，您可能会考虑其他缓存策略；其中一些可以提供资源使用效率和性能。

## 使用最近最少使用

在分配的资源（磁盘空间、内存）内保持缓存稳定性的一种常见策略是**最近最少使用**（**LRU**）系统用于缓存过期。在这种模型中，利用有关最后缓存访问时间（创建或更新）的信息，缓存管理系统可以移除列表中最老的条目。

这对性能有很多好处。首先，如果我们假设最近创建/更新的缓存条目是当前最受欢迎的条目，我们可以更快地移除那些没有被访问的条目；以便为现有和可能更频繁访问的新资源释放资源。

这是一个公平的假设，假设用于缓存的分配资源并不是微不足道的。如果你有大量的文件缓存或大量的内存用于内存缓存，那么最老的条目，就最后一次访问而言，很可能并没有被频繁地使用。

还有一个相关且更精细的策略叫做最不常用，它严格维护缓存条目本身的使用统计。这不仅消除了对缓存数据的假设，还增加了统计维护的开销。

在这里的演示中，我们将使用 LRU。

## 通过文件缓存

我们的第一个方法可能最好描述为一个经典的缓存方法，但并非没有问题。我们将利用磁盘为各个端点（API 和 Web）创建基于文件的缓存。

那么与在文件系统中缓存相关的问题是什么呢？嗯，在本章中我们提到过，磁盘可能会引入自己的瓶颈。在这里，我们做了一个权衡，以保护对数据库的访问，而不是可能遇到磁盘 I/O 的其他问题。

如果我们的缓存目录变得非常大，这将变得特别复杂。在这一点上，我们将引入更多的文件访问问题。

另一个缺点是我们必须管理我们的缓存；因为文件系统不是短暂的，我们的可用空间是有限的。我们需要手动过期缓存文件。这引入了另一轮维护和另一个故障点。

尽管如此，这仍然是一个有用的练习，如果你愿意承担一些潜在的问题，它仍然可以被利用：

```go
package cache

const (
  Location "/var/cache/"
)

type CacheItem struct {
  TTL int
  Key string
}

func newCache(endpoint string, params ...[]string) {

}

func (c CacheItem) Get() (bool, string) {
  return true, ""
}

func (c CacheItem) Set() bool {

}

func (c CacheItem) Clear() bool {

}
```

这为我们做了一些准备，比如基于端点和查询参数创建唯一的键，检查缓存文件的存在，如果不存在，按照正常情况获取请求的数据。

在我们的应用程序中，我们可以简单地实现这一点。让我们在`/page`端点前面放一个文件缓存层，如下所示：

```go
func ServePage(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  pageGUID := vars["guid"]
  thisPage := Page{}
  cached := cache.newCache("page",pageGUID)
```

前面的代码创建了一个新的`CacheItem`。我们利用可变参数`params`来生成一个引用文件名：

```go
func newCache(endpoint string, params ...[]string) CacheItem {
cacheName := endponit + "_" + strings.Join(params, "_")
c := CacheItem{}
return c
}
```

当我们有一个`CacheItem`对象时，我们可以使用`Get()`方法进行检查，如果缓存仍然有效，它将返回`true`，否则该方法将返回`false`。我们利用文件系统信息来确定缓存项是否在其有效的存活时间内：

```go
  valid, cachedData := cached.Get()
  if valid {
    thisPage.Content = cachedData
    fmt.Fprintln(w, thisPage)
    return
  }
```

如果我们通过`Get()`方法找到一个现有的项目，我们将检查确保它在设置的`TTL`内已经更新：

```go
func (c CacheItem) Get() (bool, string) {

  stats, err := os.Stat(c.Key)
  if err != nil {
    return false, ""
  }

  age := time.Nanoseconds() - stats.ModTime()
  if age <= c.TTL {
    cache, _ := ioutil.ReadFile(c.Key)
    return true, cache
  } else {
    return false, ""
  }
}
```

如果代码有效并且在 TTL 内，我们将返回`true`，并且文件的主体将被更新。否则，我们将允许页面检索和生成的通过。在这之后我们可以设置缓存数据：

```go
  t, _ := template.ParseFiles("templates/blog.html")
  cached.Set(t, thisPage)
  t.Execute(w, thisPage)
```

然后我们将保存这个为：

```go
func (c CacheItem) Set(data []byte) bool {
  err := ioutil.WriteFile(c.Key, data, 0644)
}
```

这个函数有效地写入了我们的缓存文件的值。

我们现在有一个工作系统，它将接受各个端点和无数的查询参数，并创建一个基于文件的缓存库，最终防止了对数据库的不必要查询，如果数据没有改变的话。

在实践中，我们希望将这个限制在大部分基于读的页面上，并避免在任何写或更新端点上盲目地进行缓存，特别是在我们的 API 上。

## 内存中的缓存

正如文件系统缓存因存储价格暴跌而变得更加可接受，我们在 RAM 中也看到了类似的变化，紧随硬存储之后。这里的巨大优势是速度，内存中的缓存因为显而易见的原因可以非常快。

Memcache 及其分布式的兄弟 Memcached，是为了为 LiveJournal 和*Brad Fitzpatrick*的原型社交网络创建一个轻量级和超快的缓存而演变而来。如果这个名字听起来很熟悉，那是因为 Brad 现在在谷歌工作，并且是 Go 语言本身的重要贡献者。

作为我们文件缓存系统的一个替代方案，Memcached 将起到类似的作用。唯一的主要变化是我们的键查找，它将针对工作内存而不是进行文件检查。

### 注意

使用 Go 语言与 memcache 一起使用，访问*Brad Fitz*的网站 [godoc.org/github.com/bradfitz/gomemcache/memcache](http://godoc.org/github.com/bradfitz/gomemcache/memcache)，并使用`go get`命令进行安装。

# 实现 HTTP/2

谷歌在过去五年中投资的更有趣、也许更高尚的举措之一是专注于使网络更快。通过诸如 PageSpeed 之类的工具，谷歌试图推动整个网络变得更快、更精简、更用户友好。

毫无疑问，这项举措并非完全无私。谷歌建立了他们的业务在广泛的网络搜索上，爬虫始终受制于它们爬取的页面速度。网页加载得越快，爬取就越快、更全面；因此，需要的时间和基础设施就越少，所需的资金也就越少。这里的底线是，更快的网络对谷歌有利，就像对创建和查看网站的人一样。

但这是互惠的。如果网站更快地遵守谷歌的偏好，每个人都会从更快的网络中受益。

这将我们带到了 HTTP/2，这是 HTTP 的一个版本，取代了 1999 年引入的 1.1 版本，也是大部分网络的事实标准方法。HTTP/2 还包含并实现了许多 SPDY，这是谷歌开发并通过 Chrome 支持的临时协议。

HTTP/2 和 SPDY 引入了一系列优化，包括头部压缩和非阻塞和多路复用的请求处理。

如果您使用的是 1.6 版本，`net/http`默认支持 HTTP/2。如果您使用的是 1.5 或更早版本，则可以使用实验性包。

### 注意

要在 Go 版本 1.6 之前使用 HTTP/2，请从 [godoc.org/golang.org/x/net/http2](http://godoc.org/golang.org/x/net/http2) 获取。

# 总结

在本章中，我们专注于通过减少对底层应用程序瓶颈的影响来增加应用程序整体性能的快速获胜策略，即我们的数据库。

我们已经在文件级别实施了缓存，并描述了如何将其转化为基于内存的缓存系统。我们研究了 SPDY 和 HTTP/2，它现在已成为默认的 Go `net/http`包的一部分。

这绝不代表我们可能需要生成高性能代码的所有优化，但涉及了一些最常见的瓶颈，这些瓶颈可能会导致在开发中表现良好的应用在生产环境中在重负载下表现不佳。

这就是我们结束这本书的地方；希望大家都享受这段旅程！
