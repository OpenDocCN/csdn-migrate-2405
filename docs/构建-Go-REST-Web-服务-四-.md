# 构建 Go REST Web 服务（四）

> 原文：[`zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77`](https://zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：部署我们的 REST 服务

在本章中，我们将看到如何使用 Nohup 和 Nginx 等工具部署我们的 Go 应用程序。要使网站对互联网可见，我们需要有一个**虚拟专用服务器**（**VPS**）和部署工具。我们首先将看到如何运行一个 Go 可执行文件并使用 Nohup 将其作为后台进程。接下来，我们将安装 Nginx 并配置它以代理 Go 服务器。

在本章中，我们将涵盖以下主题：

+   什么是 Nginx 代理服务器？

+   学习 Nginx 服务器块

+   Nginx 中的负载均衡策略

+   使用 Nginx 部署我们的 Go 服务

+   限制速率和保护我们的 Nginx 代理服务器

+   使用名为 Supervisord 的工具监视我们的 Go 服务

# 获取代码

本章的代码可在[`github.com/narenaryan/gorestful/tree/master/chapter10`](https://github.com/narenaryan/gorestful/tree/master/chapter10)找到。将其复制到`GOPATH`并按照章节中给出的说明运行。

# 安装和配置 Nginx

Nginx 是一个高性能的 Web 服务器和负载均衡器，非常适合部署高流量的网站。尽管这个决定是有意见的，但 Python 和 Node 开发人员通常使用它。

Nginx 还可以充当上游代理服务器，允许我们将 HTTP 请求重定向到在同一服务器上运行的多个应用程序服务器。Nginx 的主要竞争对手是 Apache 的 httpd。Nginx 是一个出色的静态文件服务器，可以被 Web 客户端使用。由于我们正在处理 API，我们将研究处理 HTTP 请求的方面。

在 Ubuntu 16.04 上，使用以下命令安装 Nginx：

```go
sudo apt-get update
sudo apt-get install nginx
```

在 macOS X 上，您可以使用`brew`安装它：

```go
brew install nginx
```

[`brew.sh/`](https://brew.sh/)是一个非常有用的 macOS X 用户软件打包系统。我的建议是使用它来安装软件。安装成功后，您可以通过在浏览器中打开机器 IP 来检查它。在您的 Web 浏览器中打开`http://localhost/`。您将看到这个：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/0b1237f3-8514-42f1-8b8a-deed58642a4e.png)

这意味着 Nginx 已成功安装。它正在端口`80`上提供服务并提供默认页面。在 macOS 上，默认的 Nginx 监听端口将是`8000`：

```go
sudo vi /usr/local/etc/nginx/nginx.conf
```

在 Ubuntu（Linux）上，文件将位于此路径：

```go
sudo vi /etc/nginx/nginx.conf
```

打开文件，搜索服务器并将端口`80`修改为`8000`：

```go
server {
        listen 8080; # Change this to 80 
        server_name localhost;
        #charset koi8-r;
        #access_log logs/host.access.log main;
        location / {
            root html;
            index index.html index.htm;
        }

        ... 
}
```

现在一切准备就绪。服务器在`80` HTTP 端口上运行，这意味着客户端可以使用 URL（`http://localhost/`）访问它，而不需要端口（`http://localhost:3000`）。这个基本服务器从一个名为`html`的目录中提供静态文件。`root`参数可以修改为我们放置 Web 资产的任何目录。您可以使用以下命令检查 Nginx 的状态：

```go
service nginx status
```

Windows 操作系统上的 Nginx 相当基本，实际上并不适用于生产级部署。开源开发人员通常更喜欢 Debian 或 Ubuntu 服务器来部署带有 Nginx 的 API 服务器。

# 什么是代理服务器？

代理服务器是一个保存原始服务器信息的服务器。它充当客户端请求的前端。每当客户端发出 HTTP 请求时，它可以直接进入应用服务器。但是，如果应用服务器是用编程语言编写的，您需要一个可以将应用程序响应转换为客户端可理解响应的翻译器。**通用网关接口**（**CGI**）也是这样做的。对于 Go，我们可以运行一个简单的 HTTP 服务器，它可以作为一个普通服务器运行（不需要翻译）。那么，为什么我们要使用另一个名为 Nginx 的服务器？我们使用 Nginx 是因为它将许多东西带入了视野。

拥有代理服务器（Nginx）的好处：

+   它可以充当负载均衡器

+   它可以坐在应用程序集群的前面并重定向 HTTP 请求

+   它可以以良好的性能提供文件系统

+   它可以很好地流媒体

如果同一台机器正在运行多个应用程序，那么我们可以将所有这些应用程序放在一个伞下。Nginx 也可以充当 API 网关，可以是多个 API 端点的起点。我们将在下一章中看到一个专门的 API 网关，但 Nginx 也可以起到这样的作用。参考以下图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/3a9a868e-2d81-4eef-9fc9-35f663a39bb8.jpg)

如果您看到，图示客户端直接与 Nginx 通信，而不是其他应用程序运行的端口。在图表中，Go 正在`8000`端口上运行，其他应用程序正在不同的端口上运行。这意味着不同的服务器提供不同的 API 端点。如果客户端希望调用这些 API，则需要访问三个端口。相反，如果我们有 Nginx，它可以作为所有三个的代理服务器，并简化客户端的请求-响应周期。

Nginx 也被称为上游服务器，因为它为其他服务器提供请求。从图示中，Python 应用程序可以顺利地从 Go 应用程序请求 API 端点。

# 重要的 Nginx 路径

有一些重要的 Nginx 路径，我们需要了解如何使用代理服务器。在 Nginx 中，我们可以同时托管多个站点（`www.example1.com`，`www.exampl2.com`等）。看一下下表：

| **类型** | **路径** | **描述** |
| --- | --- | --- |
| 配置 | `/etc/nginx/nginx.con` | 这是基本的 Nginx 配置文件。它可以用作默认文件。 |
| 配置 | `/etc/nginx/sites-available/` | 如果我们在 Nginx 中运行多个站点，我们可以有多个配置文件。 |
| 配置 | `/etc/nginx/sites-enabled/` | 这些是当前在 Nginx 上激活的站点。 |
| 日志 | `/var/log/nginx/access.log` | 此日志文件记录服务器活动，如时间戳和 API 端点。 |
| 日志 | `/var/log/nginx/error.log` | 此日志文件记录所有与代理服务器相关的错误，如磁盘空间，文件系统权限等。 |

这些路径在 Linux 操作系统中。对于 macOS X，请使用`/usr/local/nginx`作为基本路径。

# 使用服务器块

服务器块是实际的配置部分，告诉服务器要提供什么以及在哪个端口上监听。我们可以在`sites-available`文件夹中定义多个服务器块。在 Ubuntu 上，位置将是：

```go
/etc/nginx/sites-available
```

在 macOS X 上，位置将是：

```go
/usr/local/etc/nginx/sites-avaiable
```

直到我们将`sites-available`复制到`sites-enabled`目录，配置才会生效。因此，对于您创建的每个新配置，始终为`sites-available`创建到`sites-enabled`的软链接。

# 创建一个示例 Go 应用程序并对其进行代理

现在，让我们在 Go 中创建一个简单的应用程序服务器，并记录日志：

```go
mkdir -p $GOPATH/src/github.com/narenaryan/basicServer
vi $GOPATH/src/github.com/narenaryan/basicServer/main.go
```

这个文件是一个基本的 Go 服务器，用来说明代理服务器的功能。然后，我们向 Nginx 添加一个配置，将端口`8000`（Go 运行端口）代理到 HTTP 端口（`80`）。现在，让我们编写代码：

```go
package main
import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"
)
// Book holds data of a book
type Book struct {
    ID int
    ISBN string
    Author string
    PublishedYear string
}
func main() {
    // File open for reading, writing and appending
    f, err := os.OpenFile("app.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    if err != nil {
        fmt.Printf("error opening file: %v", err)
    }
    defer f.Close()
    // This attache sprogram logs to file
    log.SetOutput(f)
    // Function handler for handling requests
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%q", r.UserAgent())
        // Fill the book details
        book := Book{
            ID: 123,
            ISBN: "0-201-03801-3",
            Author: "Donald Knuth",
            PublishedYear: "1968",
        }
        // Convert struct to JSON using Marshal
        jsonData, _ := json.Marshal(book)
        w.Header().Set("Content-Type", "application/json")
        w.Write(jsonData)
    })
    s := &http.Server{
        Addr: ":8000",
        ReadTimeout: 10 * time.Second,
        WriteTimeout: 10 * time.Second,
        MaxHeaderBytes: 1 << 20,
    }
    log.Fatal(s.ListenAndServe())
}
```

这是一个简单的服务器，返回书籍详细信息作为 API（这里是虚拟数据）。运行程序并在`8000`端口上运行。现在，打开一个 shell 并进行 CURL 命令：

```go
CURL -X GET "http://localhost:8000"
```

它返回数据：

```go
{
  "ID":123,
  "ISBN":"0-201-03801-3",
  "Author":"Donald Knuth",
  "PublishedYear":"1968"
}
```

但是客户端需要在这里请求`8000`端口。我们如何使用 Nginx 代理此服务器？正如我们之前讨论的，我们需要编辑默认的 sites-available 服务器块，称为`default`：

```go
vi /etc/nginx/sites-available/default
```

编辑此文件，找到服务器块，并在其中添加一行：

```go
server {
        listen 80 default_server;
        listen [::]:80 default_server ipv6only=on;

        root /usr/share/nginx/html;
        index index.html index.htm;

        # Make site accessible from http://localhost/
        server_name localhost;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
                # Uncomment to enable naxsi on this location
                # include /etc/nginx/naxsi.rules
                proxy_pass http://127.0.0.1:8000;
        }
}
```

`config`文件的这一部分称为服务器块。这控制了代理服务器的设置，其中`listen`表示`nginx`应该监听的位置。`root`和`index`指向静态文件，如果需要提供任何文件。`server_name`是您的域名。由于我们还没有准备好域名，它只是本地主机。`location`是这里的关键部分。在`location`中，我们可以定义我们的`proxy_pass`，它可以代理给定的`URL:PORT`。由于我们的 Go 应用程序正在`8000`端口上运行，我们在那里提到了它。如果我们在不同的机器上运行它，比如：

```go
http://example.com:8000
```

我们可以将相同的内容作为参数传递给`proxy_pass`。为了使这个配置生效，我们需要重新启动 Nginx 服务器。使用以下命令进行：

```go
service nginx restart
```

现在，进行 CURL 请求到`http://localhost`，您将看到 Go 应用程序的输出：

```go
CURL -X GET "http://localhost"
{
  "ID":123,
  "ISBN":"0-201-03801-3",
  "Author":"Donald Knuth",
  "PublishedYear":"1968"
}
```

`location`是一个指令，定义了可以代理给定`server:port`组合的**统一资源标识符**（**URI**）。这意味着通过定义各种 URI，我们可以代理在同一服务器上运行的多个应用程序。它看起来像：

```go
server {
    listen ...;
    ...
    location / {
        proxy_pass http://127.0.0.1:8000;
    }

    location /api {
        proxy_pass http://127.0.0.1:8001;
    }
    location /mail {
        proxy_pass http://127.0.0.1:8002;
    }
    ...
}
```

在这里，三个应用程序在不同的端口上运行。在将它们添加到我们的配置文件后，客户端可以访问它们：

```go
http://localhost/
http://localhost/api/
http://localhost/mail/
```

# 使用 Nginx 进行负载均衡

在实际情况下，我们使用多个服务器来处理大量的 API 请求。但是谁需要将传入的客户端请求转发到服务器实例？负载均衡是一个过程，其中中央服务器根据某些标准将负载分配给各个服务器。参考以下图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/9477923c-dd86-43cd-a6bc-c009d8bbe88d.jpeg)

这些请求标准被称为负载均衡方法。让我们看看每个方法在一个简单的表中是如何工作的：

| **负载均衡方法** | **描述** |
| --- | --- |
| 轮询 | 请求均匀分布到服务器上，并且考虑服务器权重。 |
| 最少连接 | 请求被发送到当前为最少客户端提供服务的服务器。 |
| IP 哈希 | 用于将来自特定客户端 IP 的请求发送到给定服务器。只有在该服务器不可用时才会被发送到另一个服务器。 |
| 最少时间 | 客户端的请求被发送到平均延迟（为客户端提供服务的时间）最低且活动连接最少的机器。 |

我们现在看到了如何在 Nginx 中实际实现负载均衡，用于我们的 Go API 服务器。这个过程的第一步是在 Nginx 配置文件的`http`部分创建一个`upstream`：

```go
http {
    upstream cluster {
        server site1.mysite.com weight=5;
        server site2.mysite.com weight=2;
        server backup.mysite.com backup;
    }
}
```

在这里，服务器是运行相同代码的服务器的 IP 地址或域名。我们在这里定义了一个名为`backend`的`upstream`。这是一个我们可以在位置指令中引用的服务器组。权重应该根据可用资源进行分配。在前面的代码中，`site1`被赋予更高的权重，因为它可能是一个更大的实例（内存和磁盘）。现在，在位置指令中，我们可以使用`proxy_pass`命令指定服务器组：

```go
server {
    location / {
        proxy_pass http://cluster;
    }
}
```

现在，运行的代理服务器将传递所有命中`/`的 API 端点的请求到集群中的机器。默认的请求路由算法将是轮询，这意味着所有服务器的轮流将一个接一个地重复。如果我们需要更改它，我们在上游定义中提到。看一下以下代码片段：

```go
http {
    upstream cluster {
        least_conn;
        server site1.mysite.com weight=5;
        server site2.mysite.com;
        server backup.mysite.com backup;
    }
}

server {
    location / {
        proxy_pass http://cluster;
    }
}
```

前面的配置表示*创建一个由三台机器组成的集群，并添加最少连接的负载均衡方法*。`least_conn`是我们用来指定负载均衡方法的字符串。其他值可以是`ip_hash`或`least_time`。您可以通过在**局域网**（**LAN**）中拥有一组机器来尝试这个。或者，我们可以安装 Docker，并使用多个虚拟容器作为不同的机器来测试负载均衡。

我们需要在`/etc/nginx/nginx.conf`文件中添加`http`块，而服务器块在`/etc/nginx/sites-enabled/default`中。最好将这两个设置分开。

# 限制我们的 REST API 的速率

我们还可以通过速率限制来限制对 Nginx 代理服务器的访问速率。它提供了一个名为`limit_conn_zone`的指令（[`nginx.org/en/docs/http/ngx_http_limit_conn_module.html#limit_conn_zone`](http://nginx.org/en/docs/http/ngx_http_limit_conn_module.html#limit_conn_zone)）。其格式如下：

```go
limit_conn_zone client_type zone=zone_type:size;
```

`client_type`可以是两种类型：

+   IP 地址（限制来自给定 IP 地址的请求）

+   服务器名称（限制来自服务器的请求）

`zone_type`也会随着`client_type`的变化而改变。它的取值如下表所示：

| **客户端类型** | **区域类型** |
| --- | --- |
| `$binary_remote_address` | `addr` |
| `$server_name` | `servers` |

Nginx 需要将一些东西保存到内存中，以记住用于速率限制的 IP 地址和服务器。`size`是我们为 Nginx 分配的存储空间，用于执行其记忆功能。它可以取值如 8m（8MB）或 16m（16MB）。现在，让我们看看在哪里添加这些设置。前面的设置应该作为全局设置添加到`nginx.conf`文件中的`http`指令中：

```go
http {
    limit_conn_zone $server_name zone=servers:10m;
}
```

这为 Nginx 分配了用于使用的共享内存。现在，在 sites-available/default 的服务器指令中，添加以下内容：

```go
server {
   limit_conn servers 1000;
}
```

在前面的配置中，使用`limit_conn`限制给定服务器的连接总数不会超过 1K。如果我们尝试从给定 IP 地址对客户端进行速率限制，那么可以使用这个：

```go
server {
  location /api {
      limit_conn addr 1;
  }
}
```

此设置阻止客户端（IP 地址）向服务器（例如在线铁路订票）打开多个连接。如果我们有一个客户端下载文件并需要设置带宽约束，可以使用`limit_rate`：

```go
server {
  location /download {
      limit_conn addr 10;
      limit_rate 50k;
  }
}
```

通过这种方式，我们可以控制客户端与 Nginx 代理的服务的交互。如果我们直接使用 Go 二进制文件运行服务，就会失去所有这些功能。

# 保护我们的 Nginx 代理服务器

这是 Nginx 设置中最重要的部分。在本节中，我们将看到如何使用基本身份验证限制对服务器的访问。这对于我们的 REST API 服务器非常重要，因为假设我们有服务器 X、Y 和 Z 彼此通信。X 可以直接为客户端提供服务，但 X 通过调用内部 API 与 Y 和 Z 交流获取一些信息。由于我们知道客户端不应该访问 Y 或 Z，我们可以设置只允许 X 访问资源。我们可以使用`nginx`访问模块允许或拒绝 IP 地址。它看起来像这样：

```go
location /api {
    ...
    deny 192.168.1.2;
    allow 192.168.1.1/24;
    allow 127.0.0.1;
    deny all;
}
```

此配置告诉 Nginx 允许来自范围为`192.168.1.1/24`的客户端的请求，但排除`192.168.1.2`。下一行表示允许来自同一主机的请求，并阻止来自任何其他客户端的所有其他请求。完整的服务器块如下所示：

```go
server {
    listen 80 default_server;
    root /usr/share/nginx/html;

    location /api {

        deny 192.168.1.2;
        allow 192.168.1.1/24;
        allow 127.0.0.1;
        deny all;
    }
}
```

有关此更多信息，请参阅[nginx_http_access_module](http://nginx.org/en/docs/http/ngx_http_access_module.html?_ga=2.117850185.1364707364.1504109372-1654310658.1503918562)上的文档。我们还可以为 Nginx 提供的静态文件添加密码保护访问。这在 API 中通常不适用，因为在那里，应用程序负责对用户进行身份验证。

# 使用 Supervisord 监控我们的 Go API 服务器

Nginx 坐在我们的 Go API 服务器前面，只是代理一个端口，这是可以的。但是，有时 Web 应用程序可能会因操作系统重新启动或崩溃而停止。每当您的 Web 服务器被终止时，就有人的工作是自动将其恢复。Supervisord 就是这样一个任务运行程序。为了使我们的 API 服务器一直运行，我们需要对其进行监控。Supervisord 是一个可以监控运行中进程（系统）并在它们被终止时重新启动它们的工具。

# 安装 Supervisord

我们可以使用 Python 的`pip`命令轻松安装 Supervisord。在 Ubuntu 16.04 上，只需使用`apt-get`命令：

```go
sudo apt-get install -y supervisor
```

这将安装两个工具，`supervisor`和`supervisorctl`。`Supervisorctl`用于控制 supervisor 并添加任务、重新启动任务等。让我们使用我们为 Nginx 创建的`basicServre.go`程序来说明这一点。将二进制文件安装到`$GOPATH/bin`目录中。在这里，假设我的`GOPATH`是`/root/workspace`：

```go
go install github.com/narenaryan/basicServer
```

始终将当前`GOPATH`的`bin`文件夹添加到系统路径中。每当安装项目二进制文件时，它将作为普通可执行文件在整个系统环境中可用。您可以通过将以下行添加到`~/.profile`文件来实现：`export PATH=$PATH:/usr/local/go/bin`。

现在，在以下位置创建一个配置文件：

```go
/etc/supervisor/conf.d/goproject.conf
```

您可以添加任意数量的配置文件，`supervisord`将它们视为要运行的单独进程。将以下内容添加到前述文件中：

```go
[supervisord]
logfile = /tmp/supervisord.log
[program:myserver]
command=/root/workspace/bin/basicServer
autostart=true
autorestart=true
redirect_stderr=true
```

默认情况下，我们在`/etc/supervisor/`有一个名为`supervisord.conf`的文件。查看它以供参考：

+   `[supervisord]`部分提供了`supervisord`的日志文件位置。

+   `[program:myserver]`是遍历到给定目录并执行给定命令的任务块。

现在，我们可以要求我们的`supervisorctl`重新读取配置并重新启动任务（进程）。为此，只需说：

```go
supervisorctl reread
supervisorctl update
```

然后，使用以下命令启动我们的`supervisorctl`：

```go
supervisorctl
```

您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/bca1c706-5370-4956-8339-561e3be10032.png)

因此，我们的书籍服务正在被`Supervisor`监视。让我们试图杀死进程，看看`Supervisor`会做什么：

```go
kill 6886
```

现在，尽快，`Supervisor`通过运行二进制文件启动一个新进程（不同的`pid`）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/6d881926-4c63-499a-9472-245d8cf528db.png)

这在生产场景中非常有用，因为服务需要在任何崩溃或操作系统重新启动的情况下保持运行。这里有一个问题，我们如何启动/停止应用程序服务？使用`supervisorctl`的`start`和`stop`命令进行平稳操作：

```go
supervisorctl> stop myserver
supervisorctl> start myserver
```

有关 Supervisor 的更多详细信息，请访问[`supervisord.org/`](http://supervisord.org/)。

# 摘要

本章专门介绍了如何将 API 服务部署到生产环境中。一种方法是运行 Go 二进制文件，并直接从客户端访问`IP:端口`组合。该 IP 将是**虚拟专用服务器**（**VPS**）的 IP 地址。相反，我们可以注册一个域名并指向 VPS。第二种更好的方法是将其隐藏在代理服务器后面。Nginx 就是这样一个代理服务器，使用它，我们可以在一个伞下拥有多个应用服务器。

我们看到了如何安装 Nginx 并开始配置它。Nginx 提供了诸如负载平衡和速率限制之类的功能，在向客户端提供 API 时可能至关重要。负载平衡是在类似服务器之间分配负载的过程。我们看到了有哪些类型的负载均衡机制可用。其中一些是轮询、IP 哈希、最小连接等。然后，我们通过允许和拒绝一些 IP 地址集来为我们的服务器添加了认证。

最后，我们需要一个进程监视器，可以将我们崩溃的应用程序恢复过来。Supervisord 是这项工作的一个非常好的工具。我们看到了如何安装 Supervisord，以及如何启动 supervisorctl，一个用于控制运行服务器的命令行应用程序。

在下一章中，我们将看到如何使用 API 网关使我们的 API 达到生产级别。我们将深入讨论如何将我们的 API 置于一个负责认证和速率限制的实体后面。


# 第十一章：使用 API 网关监视和度量 REST API

一旦我们开发了 API，我们需要将其暴露给外部世界。在这个过程中，我们部署它们。但这足够了吗？我们不需要跟踪我们的 API 吗？哪些客户端正在连接？请求的延迟是多少，等等？有许多其他的 API 开发后步骤，人们应该遵循，使其 API 达到生产级别。它们是身份验证、日志记录、速率限制等。添加这些功能的最佳方式是使用 API 网关。在本章中，我们将探索一个名为 Kong 的开源 API 网关。与云提供商相比，开源软件更可取，因为减少了供应商锁定的风险。所有 API 网关在实现上有所不同，但执行相同的任务。

在本章中，我们将涵盖以下主题：

+   为什么需要 API 网关？

+   介绍 Kong，一个开源的 API 网关

+   Docker 中的示例说明

+   将开发的 API 添加到 Kong

+   在 Kong 中登录

+   Kong 中的身份验证和速率限制

+   Kong CLI 中的重要命令

# 获取代码

您可以在以下链接找到本章的代码示例：[`github.com/narenaryan/gorestful/tree/master/chapter11`](https://github.com/narenaryan/gorestful/tree/master/chapter11)。本章中文件的用法在各自的部分中有解释。您还可以从存储库中导入 Postman 客户端集合（JSON 文件）来测试 API，我们将在本章中介绍。

# 为什么需要 API 网关？

假设一个名为 XYZ 的公司为其内部目的开发了 API。它以两种方式将 API 暴露给外部使用：

+   使用已知客户端的身份验证进行暴露

+   将其作为 API 服务公开

在第一种情况下，此 API 由公司内部的其他服务使用。由于它们是内部的，我们不限制访问。但在第二种情况下，由于 API 细节提供给外部世界，我们需要一个中间人来检查和验证请求。这个中间人就是 API 网关。API 网关是一个位于客户端和服务器之间的中间人，并在满足特定条件时将请求转发到服务器。

现在，XYZ 有一个用 Go 和 Java 编写的 API。有一些通用的事情适用于任何 API：

+   身份验证

+   请求和响应的日志记录

没有 API 网关，我们需要编写另一个跟踪请求和 API 身份验证等内容的服务器。当新的 API 不断添加到组织中时，实施和维护是繁琐的。为了处理这些基本事项，API 网关是一个很好的中间件。

基本上，API 网关会执行以下操作：

+   日志记录

+   安全

+   流量控制

+   转换

日志记录是跟踪请求和响应的方式。如果我们需要组织级别的日志记录，与 Go kit 中的应用级别日志记录相反，我们应该在 API 网关中启用日志记录。安全性是身份验证的工作方式。它可以是基本身份验证，基于令牌的身份验证，OAuth2.0 等。限制对有效客户端的 API 访问是至关重要的。

当 API 是付费服务时，流量控制就会发挥作用。当组织将数据作为 API 出售时，需要限制每个客户端的操作。例如，客户端每月可以发出 10,000 个 API 请求。速率可以根据客户选择的计划进行设置。这是一个非常重要的功能。转换就像在命中应用程序服务器之前修改请求，或者在发送回客户端之前修改响应。看一下以下图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/acf612e1-8b37-48f8-9243-52a71936c46d.png)

我们可以看到如何将上述功能添加到我们的 Web 服务中。从图表中，API 网关可以将请求重定向到任何给定的内部服务器。客户端看到所有 API 都在组织的单个实体下。

# Kong，一个开源的 API 网关

Kong 是一个开源的 API 网关和微服务管理层，提供高性能和可靠性。它是两个值得一提的库的组合。一个是**OpenResty**，另一个是**Nginx**。Kong 是这两个主要组件的包装器。OpenResty 是一个完整的 Web 平台，集成了 Nginx 和 Lua。Lua 是一种类似于 Go 的编程语言。Kong 是用 Lua 编写的。我们使用 Kong 作为部署我们的 Go REST 服务的工具。我们要讨论的主要主题是：

+   安装 Kong 和 Kong 数据库

+   将我们的 API 添加到 Kong

+   使用插件

+   登录 Kong

+   在 Kong 中进行速率限制

Kong 需要一个数据库才能运行。它可以是 Cassandra 或 PostgreSQL。由于我们已经熟悉 PostgreSQL，我们选择了它。在哪里安装它们？为了说明问题，我们可以在本地机器上安装它们，但有一个缺点；它可能会损坏我们的机器。为了测试设置，我们将使用 Docker。Docker 可以创建容器化应用程序并在可预测的隔离环境中运行它们。

使用 Kong，我们可以将我们的 API 隐藏在一个网关下。我们可以为我们的 API 创建消费者（客户端）。Kong 通过 REST API 执行所有操作。Kong 有两种 API：

+   应用程序 API（运行在端口`8000`上）

+   管理 API（运行在端口`8001`上）

使用应用程序 API，我们可以访问我们的 Web 服务。管理 API 允许我们在网关下添加/删除 API。我们将在接下来的部分中更详细地了解这些内容。有关 Kong 的更多详细信息，请访问[`getkong.org/`](https://getkong.org/)。

# 介绍 Docker

Docker 是一个可以创建操作系统的虚拟化工具，以微小容器的形式。它就像在单个主机上有多个操作系统。开发人员通常抱怨说*在我的环境中工作*，同时面临部署问题。Docker 通过定义镜像形式的 OS 环境来消除这些情况。Docker 镜像包含了在特定时间给定 OS 的所有信息。它允许我们任意多次地复制该环境。

最初只适用于 Linux，但现在适用于 macOS X 和 Windows。要下载和安装 Docker，请访问[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)。对于 Windows 和 Mac，二进制文件可在 Docker 网站上找到并且可以轻松安装。安装后，使用以下命令验证 Docker 安装：

```go
docker -v
Docker version 17.09.0-ce, build afdb6d4
```

它将提供版本号；始终选择最新的 Docker。现在 Docker 准备就绪，让我们运行一些命令来安装 Kong。接下来的部分需要一些 Docker 知识。如果不够自信，请阅读网上关于 Docker 基础知识的精彩文章。

我们的最终目标是创建三个容器：

+   Kong 数据库

+   Go 容器

+   Kong 应用

当这三个容器运行时，它为在 API 网关后面设置 Web 服务的舞台。

# 安装 Kong 数据库和 Kong

首先，安装 PostgreSQL DB。一个条件是我们需要暴露`5432`端口。用户和数据库名称应为`kong`，并且应作为环境变量传递给容器：

```go
docker run -d --name kong-database \
 -p 5432:5432 \
 -e "POSTGRES_USER=kong" \
 -e "POSTGRES_DB=kong" \
 postgres:9.4
```

这个命令的工作方式是这样的：

1.  从 Docker 存储库获取名为`postgres:9.4`的镜像。

1.  给镜像命名为`kong-database`。

1.  在名为`POSTGRES_USER`和`POSTGRES_DB`的容器中设置环境变量。

这将通过拉取托管在**DockerHub**（[`hub.docker.com/`](https://hub.docker.com/)）存储库上的 PostgreSQL 镜像来创建一个 Docker 容器。现在，通过运行另一个 Docker 命令来应用 Kong 所需的迁移：

```go
docker run --rm \
 --link kong-database:kong-database \
 -e "KONG_DATABASE=postgres" \
 -e "KONG_PG_HOST=kong-database" \
 kong:latest kong migrations up
```

它在先前创建的 PostgreSQL DB 容器上应用迁移。该命令有一个名为`--rm`的选项，表示*一旦迁移完成，删除此容器*。在安装 Kong 容器之前，让我们准备好我们的 Go 服务。这将是一个简单的项目，其中包含一个健康检查`GET` API。

现在，转到主机上的任何目录并创建一个名为`kongExample`的项目：

```go
mkdir kongExample
```

在该目录中创建一个名为`main.go`的程序，该程序获取`GET`请求的健康检查（日期和时间）：

```go
package main
import (
    "fmt"
    "github.com/gorilla/mux"
    "log"
    "net/http"
    "time"
)
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, time.Now().String())
}
func main() {
    // Create a new router
    r := mux.NewRouter()
    // Attach an elegant path with handler
    r.HandleFunc("/healthcheck", HealthcheckHandler)
    srv := &http.Server{
        Handler: r,
        Addr: "0.0.0.0:3000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout: 15 * time.Second,
    }
    log.Fatal(srv.ListenAndServe())
}
```

该程序在请求时返回日期和时间。现在，我们需要将这个应用程序 Docker 化。Docker 化意味着创建一个运行的容器。将 Dockerfile 添加到当前目录（在相同级别的`kongExample`中）：

```go
FROM golang
ADD kongExample /go/src/github.com/narenaryan/kongExample
RUN go get github.com/gorilla/mux
RUN go install github.com/narenaryan/kongExample
ENTRYPOINT /go/bin/kongExample
```

我们使用这个 Dockerfile 构建一个容器。它告诉我们从 DockerHub 拉取`golang`容器（自动安装 Go 编译器并设置`GOPATH`），并将这个`kongExample`项目复制到容器中。安装项目所需的必要软件包（在本例中是 Gorilla Mux），然后编译二进制文件并启动服务器。运行此命令创建容器：

```go
docker build . -t gobuild
```

注意`docker build`命令后的`.`。`-t`选项是为镜像打标签。它告诉 Docker 查看当前目录中的 Dockerfile，并根据给定的指令创建一个 Docker 镜像。我们需要实际运行这个镜像来创建一个容器：

```go
docker run  -p 3000:3000 --name go-server -dit gobuild
```

它创建一个名为`go-server`的容器，并在端口`3000`上启动 Go Web 服务器。现在安装 Kong 容器，就像这样：

```go
docker run -d --name kong \
 --link kong-database:kong-database \
 --link go-server:go-server \
 -e "KONG_DATABASE=postgres" \
 -e "KONG_PG_HOST=kong-database" \
 -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
 -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
 -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
 -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
 -p 8000:8000 \
 -p 8443:8443 \
 -p 8001:8001 \
 -p 8444:8444 \
 kong:latest
```

这个命令与第一个命令类似，只是我们暴露了许多其他端口供 Kong 使用。我们还从 DockerHub 拉取`kong:latest`镜像。其他的是 Kong 所需的环境变量。我们将`kong-database`链接到名为`kong-database`的主机名，将`go-server`链接到`go-server`。主机名是 Docker 环境中的一个有用的实体，用于从一个容器识别和访问另一个容器。Docker 维护一个内部的**域名空间**（**DNS**），用于跟踪 Docker 容器的 IP 地址到链接名称的映射。这将启动 Kong 容器并使用名为`kong.conf.default`的默认文件启动 Kong 服务。

现在，如果我们查看正在运行的容器，它列出了三个容器 ID：

```go
docker ps -q
b6cd3ad39f75
53d800fe3b15
bbc9d2ba5679
```

Docker 容器只是用于运行应用程序的隔离环境。将微服务运行在不同的容器中是最佳实践，因为它们松散耦合，一个环境不会干扰另一个环境。

这意味着我们成功地为 Kong API 网关设置了基础设施。让我们看看如何在 Kong 中添加来自`go-server`的 API。为了检查 Kong 的状态，只需向此 URL 发出`GET`请求：

```go
curl -X GET http://localhost:8001/status
```

它返回数据库的状态以及 Kong 的统计信息：

```go
{
  "database": {
    "reachable": true
  },
  "server": {
    "connections_writing": 1,
    "total_requests": 13,
    "connections_handled": 14,
    "connections_accepted": 14,
    "connections_reading": 0,
    "connections_active": 2,
    "connections_waiting": 1
  }
}
```

# 向 Kong 添加 API

Kong 提供了一个直观的 REST API 来将自定义 API 添加到网关。为了添加上述的健康检查 API，我们需要向运行在端口`8001`上的 Kong 管理 API 发出`POST`请求。从现在开始，我们使用 Postman REST 客户端来显示所有 API 请求。这些 API 请求也作为 JSON 文件集合在本章的存储库中提供，供读者下载并分别导入到他们的 Postman 客户端中。有关导出和导入 Postman 集合的更多信息，请访问[`www.getpostman.com/docs/postman/collections/data_formats`](https://www.getpostman.com/docs/postman/collections/data_formats)。

从 Postman 向 Kong 管理 URL`http://localhost:8001/apis`发出`POST`请求，并在 JSON 主体中使用这些字段：

```go
{
    "name": "myapi",
    "hosts": "server1",
    "upstream_url": "http://go-server:3000",
    "uris":["/api/v1"],
    "strip_uri": true,
    "preserve_host": false
}
```

它将我们的健康检查 API 添加到 Kong。Postman 屏幕看起来像以下截图所示，显示了所有更改。Postman 是一个很棒的工具，允许 Windows、macOS X 和 Linux 用户进行 HTTP API 请求的测试。您可以在这里下载它[`www.getpostman.com/`](https://www.getpostman.com/)。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/432b02ac-7514-4427-8898-e1a466291ffb.png)

一旦我们这样做，我们就会得到包含 API 详细信息的响应 JSON。这个新的`myapi`将被赋予一个 ID：

```go
{
  "created_at": 1509195475000,
  "strip_uri": true,
  "id": "795409ae-89ae-4810-8520-15418b96161f",
  "hosts": [
    "server1"
  ],
  "name": "myapi",
  "http_if_terminated": false,
  "preserve_host": false,
  "upstream_url": "http://go-server:3000",
  "uris": [
    "/api/v1"
  ],
  "upstream_connect_timeout": 60000,
  "upstream_send_timeout": 60000,
  "upstream_read_timeout": 60000,
  "retries": 5,
  "https_only": false
}
```

向此 URL 发出`GET`请求，`http://localhost:8001/apis/myapi`返回新添加的`myapi`的元数据。

关于我们发布到`POST` API 的字段，`name`是 API 的唯一名称。我们需要使用这个来在网关上标识 API。`hosts`是网关可以接受和转发请求的主机列表。上游 URL 是 Kong 转发请求的实际地址。由于我们在开始时链接了`go-server`容器，我们可以直接从 Kong 中引用`http://go-server:3000`。`uris`字段用于指定相对于上游代理（Go 服务器）的路径，以获取资源。

例如，如果 URI 是`/api/v1`，而 Go 服务器的 API 是`/healthcheck`，则生成的网关 API 将是：

```go
http://localhost:8000/api/v1/healthcheck
```

`preserve_host`是一个属性，它表示 Kong 是否应该将请求的主机字段更改为上游服务器的主机名。有关更多信息，请参阅[`getkong.org/docs/0.10.x/proxy/#the-preserve_host-property`](https://getkong.org/docs/0.10.x/proxy/#the-preserve_host-property)。其他设置，如`upstream_connect_timeout`，都很简单。

我们将我们的 API 添加到 Kong。让我们验证它是否将我们的健康检查请求转发到 Go 服务器。不要忘记为所有 API 请求添加一个名为`Host`值为`server1`的标头。这非常重要。API 调用如下图所示：

>![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/82c21b17-e5d8-48b2-b069-649abf0b7fb6.png)

我们成功收到了响应。这是我们的`main.go`程序中的`HealthcheckHandler`返回的响应。

如果收到 404 错误，请尝试从头开始执行该过程。问题可能是容器没有运行，或者 Kong 容器无法访问上游 URL。另一个关键错误可能来自于未在请求标头中添加主机。这是在添加 API 时给出的主机。

这个健康检查 API 实际上是作为 Go 服务运行的。我们向 API 网关发出了 API 请求，它正在将其转发到 Go。这证明我们成功地将我们的 API 与 API 网关链接起来。

这是 API 的添加，只是冰山一角。其他事情呢？我们将逐个研究 API 网关的每一个功能，并尝试为我们的 API 实现它们。

在 Kong 中，除了基本路由之外，还提供了其他功能，如日志记录和速率限制。我们需要使用插件将它们启用到我们的 API 中。Kong 插件是一个内置组件，可以让我们轻松地插入任何功能。有许多类型的插件可用。其中，我们将在下一节讨论一些有趣的插件。让我们从日志记录插件开始。

# Kong 中的 API 日志记录

Kong 中有许多插件可用于将请求记录到多个目标。目标是收集日志并将其持久化的系统。以下是可用于日志记录的重要插件：

+   文件日志

+   Syslog

+   HTTP 日志

第一个是文件日志记录。如果我们需要 Kong 服务器以 JSON 格式将请求和响应日志存储到文件中，使用此插件。我们应该调用 Kong 的管理 REST API（`http://localhost:8001/apis/myapi/plugins`）来执行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/a51c3022-a3b1-4a32-8dd7-9f3ffd1241a0.png)

点击发送按钮，网关将返回响应，如下所示：

```go
{
  "created_at": 1509202704000,
  "config": {
    "path": "/tmp/file.log",
    "reopen": false
  },
  "id": "57954bdd-ee11-4f00-a7aa-1a48f672d36d",
  "name": "file-log",
  "api_id": "795409ae-89ae-4810-8520-15418b96161f",
  "enabled": true
}
```

它基本上告诉 Kong，对于名为`myapi`的 API，将每个请求记录到名为`/tmp/file.log`的文件中。现在，向 API 网关发出健康检查的另一个请求（`http://localhost:8000/api/v1/healthcheck`）。此请求的日志将保存在给定的文件路径中。

我们如何查看这些日志？这些日志将保存在容器的`/tmp`文件夹中。打开一个新的终端标签，并使用以下命令进入 Kong 容器：

```go
docker exec -i -t kong /bin/bash
```

这将带您进入容器的 bash shell。现在，检查日志文件：

```go
cat /tmp/file.log
```

然后你会看到一个长长的 JSON 写入文件：

```go
{"api":{"created_at":1509195475000,"strip_uri":true,"id":"795409ae-89ae-4810-8520-15418b96161f","hosts":["server1"],"name":"myapi","headers":{"host":["server1"]},"http_if_terminated":false,"https_only":false,"retries":5,"uris":["\/api\/v1"],"preserve_host":false,"upstream_connect_timeout":60000,"upstream_read_timeout":60000,"upstream_send_timeout":60000,"upstream_url":"http:\/\/go-server:3000"},"request":{"querystring":{},"size":"423","uri":"\/api\/v1\/healthcheck","request_uri":"http:\/\/server1:8000\/api\/v1\/healthcheck","method":"GET","headers":{"cache-control":"no-cache","cookie":"session.id=MTUwODY2NTE3MnxOd3dBTkZaUVNqVTBURmRTUlRSRVRsUlpRMHhGU2xkQlZVNDFVMFJNVmxjMlRFNDJUVXhDTWpaWE1rOUNORXBFVkRJMlExSXlSMEU9fNFxTxKgoEsN2IWvrF-sJgH4tSLxTw8o52lfgj2DwnHI","postman-token":"b70b1881-d7bd-4d8e-b893-494952e44033","user-agent":"PostmanRuntime\/3.0.11-hotfix.2","accept":"*\/*","connection":"keep-alive","accept-encoding":"gzip, deflate","host":"server1"}},"client_ip":"172.17.0.1","latencies":{"request":33,"kong":33,"proxy":0},"response":{"headers":{"content-type":"text\/plain; charset=utf-8","date":"Sat, 28 Oct 2017 15:02:05 GMT","via":"kong\/0.11.0","connection":"close","x-kong-proxy-latency":"33","x-kong-upstream-latency":"0","content-length":"58"},"status":200,"size":"271"},"tries":[{"balancer_latency":0,"port":3000,"ip":"172.17.0.3"}],"started_at":1509202924971}
```

这里记录的 IP 地址是 Docker 分配给容器的内部 IP。这个日志还包含有关 Kong 代理、Go 服务器等的延迟信息的详细信息。您可以在[`getkong.org/plugins/file-log/`](https://getkong.org/plugins/file-log/)了解有关记录字段格式的更多信息。Kong 管理 API 用于启用其他日志记录类型与`file-log`类似。

我们从 Postman 向管理 API 发出的`POST`请求具有`Content-Type: "application/json"`的标头。

# Kong 中的 API 身份验证

正如我们提到的，API 网关应该负责多个 API 在其后运行的身份验证。在 Kong 中有许多插件可用于提供即时身份验证。在下一章中，我们将详细了解身份验证概念。目前，使用这些插件，我们可以通过调用 Kong 管理 API 为特定 API 添加身份验证。

基于 API 密钥的身份验证如今变得很有名。Kong 提供以下身份验证模式：

+   基于 API 密钥的身份验证

+   OAuth2 身份验证

+   JWT 身份验证

为了简单起见，让我们实现基于 API 密钥的身份验证。简而言之，基于密钥的身份验证允许外部客户端使用唯一令牌消耗 REST API。为此，在 Kong 中，首先启用密钥身份验证插件。要启用插件，请向`http://localhost:8001/apis/myapi/plugins` URL 发出`POST`请求，并在 JSON 主体中包含两个内容：

1.  `name`是`key-auth`。

1.  `config.hide_credentials`是`true`。

第二个选项是剥离/隐藏凭据以传递给 Go API 服务器。看一下以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/78461538-976d-4ab8-a7db-873035c6b39e.png)

它返回 JSON 响应与创建的`api_id`：

```go
    {
      "created_at": 1509212748000,
      "config": {
        "key_in_body": false,
        "anonymous": "",
        "key_names": [
          "apikey"
        ],
        "hide_credentials": true
      },
      "id": "5c7d23dd-6dda-4802-ba9c-7aed712c2101",
      "enabled": true,
      "api_id": "795409ae-89ae-4810-8520-15418b96161f",
      "name": "key-auth"
    }
```

现在，如果我们尝试进行健康检查 API 请求，我们会收到 401 未经授权的错误：

```go
{
  "message": "No API key found in request"
}
```

那么我们如何使用 API？我们需要创建一个消费者并为他授予权限访问 API。该权限是一个 API 密钥。让我们看看如何做到这一点。

要创建一个消费者，我们需要创建一个代表使用 API 的用户的消费者。向 Kong 管理 API 的消费者发出 API 调用。URL 端点将是`http://localhost:8001/consumers`。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/48f55137-10a1-4148-9b2b-38d3cb7c77e8.png)

`POST`主体应该有`username`字段。响应将是创建的消费者的 JSON：

```go
{
  "created_at": 1509213840000,
  "username": "johnd",
  "id": "df024acb-5cbd-4e4d-b3ed-751287eafd36"
}
```

现在，如果我们需要授予 API 权限给`johnd`，请向`http://localhost:8001/consumers/johnd/key-auth admin` URL 发出`POST`请求：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/8a03b590-0d46-413c-b86d-c4a77d74e258.png)

这将返回 API 密钥：

```go
{
  "id": "664435b8-0f16-40c7-bc7f-32c69eb6c39c",
  "created_at": 1509214422000,
  "key": "89MH58EXzc4xHBO8WZB9axZ4uhZ1vW9d",
  "consumer_id": "df024acb-5cbd-4e4d-b3ed-751287eafd36"
}
```

我们可以在随后的 API 调用中使用此 API 密钥生成。现在，在标头中使用`apikey`重新进行健康检查，其值是前面响应中的密钥，它将成功返回日期和时间以及`200 OK`。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/66502aeb-b4ac-4d19-ba66-eee9e0ae483e.png)

# Kong 中的 API 速率限制

我们可以限制特定消费者的 API 速率。例如，GitHub 限制客户端每小时进行 5000 次请求。之后，它会抛出 API 速率限制错误。我们可以使用 Kong 的`rate-limiting`插件为我们的 API 添加类似的速率限制约束。

我们可以使用此 API 进行启用：**`http://localhost:8001/apis/myapi/plugins`**，使用`POST` `name`、`config.hour`和`consumer_id`作为 body 参数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/44aca43e-a1c6-4b9a-ad2b-11f48a2f078c.png)

这个 API 调用正在创建速率限制规则。`consumer_id`是用户名`johnd`的 ID。这个 JSON 响应有一个`ID`

```go
{
  "created_at": 1509216578000,
  "config": {
    "hour": 5000,
    "redis_database": 0,
    "policy": "cluster",
    "hide_client_headers": false,
    "redis_timeout": 2000,
    "redis_port": 6379,
    "limit_by": "consumer",
    "fault_tolerant": true
  },
  "id": "b087a740-62a2-467a-96b5-9cee1871a368",
  "enabled": true,
  "name": "rate-limiting",
  "api_id": "795409ae-89ae-4810-8520-15418b96161f",
  "consumer_id": "df024acb-5cbd-4e4d-b3ed-751287eafd36"
}
```

现在，消费者（`johnd`）在 API 上有速率限制。他每小时只能允许对我们的健康检查 API 进行 5000 次请求。如果超过，他将收到以下错误：

```go
{"message":"API rate limit exceeded"}
```

客户端应该如何知道剩余的请求次数作为速率控制的一部分？当客户端向 API 发出请求时，Kong 在响应中设置了一些标头。尝试进行 10 次健康检查请求并检查响应标头；您将在响应标头中找到以下内容，证明速率限制正在起作用：

```go
X-RateLimit-Limit-hour →5000
X-RateLimit-Remaining-hour →4990
```

通过这种方式，Kong 提供了许多优秀的功能，可以将我们的 API 提升到更高的水平。这并不意味着 API 网关是绝对必要的，但它可以让您享受许多很酷的功能，而无需编写一行代码。它是一个开源软件，旨在避免在 Web 服务业务逻辑中重新编写通用定义的 API 网关功能。有关诸如负载平衡和请求转换之类的更多功能，请查看 Kong 的文档[`konghq.com/plugins/`](https://konghq.com/plugins/)。

# Kong CLI

Kong 配备了一个命令行工具，用于更改 Kong 的行为。它有一组命令来启动、停止和修改 Kong。Kong 默认使用配置文件。如果我们需要修改它，我们需要重新启动 Kong 才能应用这些更改。因此，所有这些基本工作都已经编码到 Kong CLI 工具中。基本功能包括：

+   `kong start`：用于启动 Kong 服务器

+   `kong reload`：用于重新加载 Kong 服务器

+   `kong stop`：用于停止 Kong 服务器

+   `kong check`：用于验证给定的 Kong 配置文件

+   `kong health`：用于检查必要的服务，如数据库，是否正在运行

请查看 Kong CLI 的文档以获取更多命令[`getkong.org/docs/0.9.x/cli/`](https://getkong.org/docs/0.9.x/cli/)。

# 其他 API 网关

市场上有许多其他 API 网关提供商。正如我们之前提到的，所有网关都执行相同类型的功能。像亚马逊 API 网关这样的企业网关服务提供商与 EC2 和 Lambdas 兼容。Apigee 是另一个知名的 API 网关技术，是 Google Cloud 的一部分。云服务提供商的问题在于它们可能导致供应商锁定（无法轻松迁移到另一个平台）。因此，对于初创公司来说，开源替代方案总是不错的选择。

# 总结

在本章中，我们从 API 网关的基础知识开始。API 网关尝试做一些事情；它充当我们的 API 的代理。通过充当代理，它将请求转发到不同域的多个 API。在转发的过程中，网关可以阻止请求，对其进行速率限制，还可以转换请求/响应。

Kong 是一个适用于 Linux 平台的优秀的开源 API 网关。它具有许多功能，如身份验证、日志记录和速率限制。我们看到了如何在 Docker 容器中安装 Kong、Kong 数据库和我们的 REST 服务。我们使用 Docker 而不是主机机器，因为容器可以随意销毁和创建。这减少了损坏主机系统的机会。在了解安装后，我们了解到 Kong 有两种类型的 REST API。一种是管理 API，另一种是应用程序 API。管理 API 是我们用来将 API 添加到网关的 API。应用程序 API 是我们应用程序的 API。我们看到了如何将 API 添加到 Kong。然后，我们了解了 Kong 插件。Kong 插件是可以插入 Kong 的功能模块。日志记录插件可用。Kong 还提供身份验证插件和速率限制插件。

我们使用 Postman 客户端进行了请求，并看到了返回的示例 JSON。对于身份验证，我们使用了基于`apikey`的消费者。然后，我们使用 Kong 的`key-auth`插件模拟了 GitHub 每小时 5000 次请求。

最后，我们介绍了 Kong CLI，并检查了其他企业 API 网关，如 Apigee 和亚马逊 API 网关。在下一章中，我们将更详细地了解身份验证的工作原理，并在没有 API 网关的情况下尝试保护我们的 API。


# 第十二章：处理我们的 REST 服务的身份验证

在本章中，我们将探讨 Go 中的身份验证模式。这些模式是基于会话的身份验证、JSON Web Tokens（JWT）和 Open Authentication 2（OAuth2）。我们将尝试利用 Gorilla 包的 sessions 库来创建基本会话。然后，我们将尝试进入高级 REST API 身份验证策略，比如使用无状态 JWT。最后，我们将看到如何实现我们自己的 OAuth2，并了解有哪些包可用来提供给我们现成的 OAuth2 实现。在上一章中，API 网关为我们实现了身份验证（使用插件）。如果 API 网关不在我们的架构中，我们如何保护我们的 API？你将在本章中找到答案。

在本章中，我们将涵盖以下主题：

+   认证工作原理

+   介绍 Postman，一个用于测试 API 的可视化客户端

+   Go 中基于会话的身份验证

+   引入 Redis 来存储用户会话

+   介绍 JSON Web Tokens（JWT）

+   OAuth2 架构和基础知识

# 获取代码

您可以在[`github.com/narenaryan/gorestful/tree/master/chapter12`](https://github.com/narenaryan/gorestful/tree/master/chapter12)获取本章的代码示例。由于示例程序不是包，读者需要按照 GOPATH 的方式创建项目文件。

# 认证工作原理

传统上，身份验证或简单身份验证以会话为中心的方式工作。请求服务器资源的客户端试图证明自己是任何给定资源的合适消费者。流程开始如下。客户端使用用户凭据向服务器发送身份验证请求。服务器接受这些凭据并将其与服务器上存储的凭据进行匹配。如果匹配成功，它会在响应中写入一个称为 cookie 的东西。这个 cookie 是一小段信息，传输到后续请求中。现代网站的用户界面（UI）是单页应用程序（SPA）。在那里，静态网页资产如 HTML、JS 是从 CDN 提供的，以渲染网页。从下一次开始，网页和应用服务器之间的通信只通过 REST API/Web 服务进行。

会话是记录用户在一定时间内的通信的一种好方法。会话通常存储在 cookie 中。以下图表可以总结认证（简称 auth）的整个过程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/a377d17c-27dc-4a16-b66c-fa5adbdbc5ed.png)

现在看看实际的方法。客户端（例如浏览器）向服务器的登录 API 发送请求。服务器尝试使用数据库检查这些凭据，如果凭据存在，就会在响应中写入一个 cookie，表示这个用户已经通过身份验证。cookie 是服务器在以后的时间点要消耗的消息。当客户端接收到响应时，它会在本地存储该 cookie。如果是 Web 浏览器是客户端，它会将其存储在 cookie 存储中。从下一次开始，客户端可以自由地通过显示 cookie 作为通行证来请求服务器的资源。当客户端决定终止会话时，它调用服务器上的注销 API。服务器在响应中销毁会话。这个过程继续进行。服务器还可以在 cookie 上设置过期时间，以便在没有活动的情况下，认证窗口在一定时间内有效。这就是所有网站的工作原理。

现在，我们将尝试使用 Gorilla kit 的`sessions`包来实现这样的系统。我们已经在最初的章节中看到了 Gorilla kit 如何提供 HTTP 路由。这个 sessions 包就是其中之一。我们需要首先使用以下命令安装这个包：

```go
go get github.com/gorilla/sessions
```

现在，我们可以使用以下语句创建一个新的会话：

```go
var store = sessions.NewCookieStore([]byte("secret_key"))
```

`secret_key`应该是 Gorilla sessions 用来加密会话 cookie 的密钥。如果我们将会话添加为普通文本，任何人都可以读取它。因此，服务器需要将消息加密为一个随机字符串。为此，它要求提供一个密钥。这个密钥可以是任何随机生成的字符串。将密钥保存在代码中并不是一个好主意，所以我们尝试将其存储为环境变量，并在代码中动态读取它。我们将看到如何实现这样一个系统。

# 基于会话的身份验证

在 GOPATH 中创建一个名为`simpleAuth`的项目，并添加一个名为`main.go`的文件，其中包含我们程序的逻辑：

```go
mkdir simpleAuth
touch main.py
```

在这个程序中，我们将看到如何使用 Gorilla sessions 包创建基于会话的身份验证。参考以下代码片段：

```go
package main
import (
    "log"
    "net/http"
    "os"
    "time"
    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
)
var store =
sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
var users = map[string]string{"naren": "passme", "admin": "password"}
// HealthcheckHandler returns the date and time
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session.id")
    if (session.Values["authenticated"] != nil) && session.Values["authenticated"] != false {
        w.Write([]byte(time.Now().String()))
    } else {
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}
// LoginHandler validates the user credentials
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session.id")
    err := r.ParseForm()
    if err != nil {
        http.Error(w, "Please pass the data as URL form encoded",
http.StatusBadRequest)
        return
    }
    username := r.PostForm.Get("username")
    password := r.PostForm.Get("password")
    if originalPassword, ok := users[username]; ok {
        if password == originalPassword {
            session.Values["authenticated"] = true
            session.Save(r, w)
        } else {
            http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
            return
        }
    } else {
        http.Error(w, "User is not found", http.StatusNotFound)
        return
    }
    w.Write([]byte("Logged In successfully"))
}
// LogoutHandler removes the session
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session.id")
    session.Values["authenticated"] = false
    session.Save(r, w)
    w.Write([]byte(""))
}
func main() {
    r := mux.NewRouter()
    r.HandleFunc("/login", LoginHandler)
    r.HandleFunc("/healthcheck", HealthcheckHandler)
    r.HandleFunc("/logout", LogoutHandler)
    http.Handle("/", r)
    srv := &http.Server{
        Handler: r,
        Addr: "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout: 15 * time.Second,
    }
    log.Fatal(srv.ListenAndServe())
}
```

这是一个 REST API，允许用户访问系统的健康状况（正常或异常）。为了进行身份验证，用户需要首先调用登录端点。该程序导入了两个名为 mux 和 sessions 的主要包，来自 Gorilla kit。Mux 用于将 HTTP 请求的 URL 端点链接到函数处理程序，sessions 用于在运行时创建新会话和验证现有会话。

在 Go 中，我们需要将会话存储在程序内存中。我们可以通过创建`CookieStore`来实现。这行明确告诉程序从名为`SESSION_SECRET`的环境变量中选择一个密钥来创建一个密钥。

```go
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
```

`sessions`有一个名为`NewCookieStore`的新函数，返回一个存储。我们需要使用这个存储来管理 cookie。我们可以通过这个语句获取一个 cookie 会话。如果会话不存在，它将返回一个空的会话：

```go
session, _ := store.Get(r, "session.id")
```

`session.id`是我们为会话指定的自定义名称。使用这个名称，服务器将在客户端响应中发送一个 cookie。`LoginHandler`尝试解析客户端提供的多部分表单数据。这一步在程序中是必不可少的：

```go
err := r.ParseForm()
```

这将使用解析后的键值对填充`r.PostForm`映射。该 API 需要用户名和密码进行身份验证。因此，我们对`username`和`password`感兴趣。一旦`LoginHandler`接收到数据，它会尝试与名为**users**的映射中的详细信息进行检查。在实际场景中，我们使用数据库来验证这些详细信息。为了简单起见，我们硬编码了值并尝试进行身份验证。如果用户名不存在，则返回一个资源未找到的错误。如果用户名存在但密码不正确，则返回一个`UnAuthorized`错误消息。如果一切顺利，通过设置 cookie 值返回一个 200 响应，如下所示：

```go
session.Values["authenticated"] = true
session.Save(r, w)
```

第一条语句将名为`"authenticated"`的 cookie 键设置为`true`。第二条语句实际上将会话保存在响应中。它以请求和响应写入器作为参数。如果我们删除这个语句，cookie 将不会产生任何效果。现在，来看看`HealthCheckHandler`，它最初与`LoginHandler`做同样的事情，如下所示：

```go
session, _ := store.Get(r, "session.id")
```

然后，它检查给定的请求是否具有名为`"authenticated"`的 cookie 键。如果该键存在且为 true，则表示之前服务器经过身份验证的用户。但是，如果该键不存在或`"authenticated"`值为`false`，则会话无效，因此返回一个`StatusForbidden`错误。

客户端应该有一种方式来使登录会话失效。它可以通过调用服务器的注销 API 来实现。该 API 只是将`"authenticated"`值设置为`false`。这告诉服务器客户端未经身份验证：

```go
session, _ := store.Get(r, "session.id")
session.Values["authenticated"] = false
session.Save(r, w)
```

通过这种方式，可以在任何编程语言中使用会话来实现简单的身份验证，包括 Go。

不要忘记添加这个语句，因为这是实际修改和保存 cookie 的语句：`session.Save(r, w)`。

现在，让我们看看这个程序的执行。与其使用 CURL，我们可以使用一个名为 Postman 的绝妙工具。其主要好处是它可以在包括 Microsoft Window 在内的所有平台上运行；不再需要 CURL 了。

错误代码可能意味着不同的事情。例如，当用户尝试在没有身份验证的情况下访问资源时，会发出 Forbidden（403）错误，而当给定资源在服务器上不存在时，会发出 Resource Not Found（404）错误。

# 介绍 Postman，一个用于测试 REST API 的工具

Postman 是一个很棒的工具，允许 Windows、macOS X 和 Linux 用户进行 HTTP API 请求。您可以在[`www.getpostman.com/`](https://www.getpostman.com/)下载它。

安装 Postman 后，在“输入请求 URL”文本框中输入 URL。选择请求类型（`GET`、`POST`等）。对于每个请求，我们可以有许多设置，如头部、`POST`主体和其他详细信息。请查阅 Postman 文档以获取更多详细信息。Postman 的基本用法很简单。请看下面的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/0e02ffe3-9719-4ff1-9d82-832c209ba65d.png)

构建器是我们可以添加/编辑请求的窗口。上面的截图显示了我们尝试发出请求的空构建器。运行上面的`simpleAuth`项目中的`main.go`，尝试调用健康检查 API，就像这样。单击发送按钮，您会看到响应被禁止：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/42a5cf72-dea0-41d6-b3a2-917401543995.png)

这是因为我们还没有登录。Postman 在身份验证成功后会自动保存 cookie。现在，将方法类型从`GET`更改为 POST，URL 更改为`http://localhost:8000/login`，调用登录 API。我们还应该将 auth 详细信息作为多部分表单数据传递。它看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/cb63a0a0-deb2-444c-a841-d642d390a511.png)

现在，如果我们点击发送，它会进行身份验证并接收 cookie。它返回一条消息，说成功登录。我们还可以通过点击右侧“发送”和“保存”按钮下方的 Cookies 链接来检查 cookies。它会显示已保存的 cookie 列表，你会在那里找到一个名为`session.id`的 cookie，内容看起来像这样：

```go
session.id=MTUwODYzNDcwN3xEdi1CQkFFQ180SUFBUkFCRUFBQUpmLUNBQUVHYzNSeWFXNW5EQThBRFdGMWRHaGxiblJwWTJGMFpXUUVZbTl2YkFJQ0FBRT189iF-ruBQmyTdtAOaMR-Rr9lNtsf1OJgirBDkcBpdEa0=; path=/; domain=localhost; Expires=Tue Nov 21 2017 01:11:47 GMT+0530 (IST);
```

尝试再次调用健康检查 API，它会返回系统日期和时间：

```go
2017-10-22 06:54:36.464214959 +0530 IST
```

如果客户端向注销 API 发出`GET`请求：

```go
http://localhost:8000/logout
```

会话将被使无效，并且访问资源将被禁止，直到进行另一个登录请求。

# 使用 Redis 持久化客户端会话

到目前为止我们创建的会话都存储在程序内存中。这意味着如果程序崩溃或重新启动，所有已登录的会话都将丢失。客户端需要重新进行身份验证以获取新的会话 cookie。有时这可能会很烦人。为了将会话保存在某个地方，我们选择了**Redis**。Redis 是一个键值存储，非常快，因为它存在于主内存中。

Redis 服务器存储我们提供的任何键值对。它提供基本的数据类型，如字符串、列表、哈希、集合等。有关更多详细信息，请访问[`redis.io/topics/data-types`](https://redis.io/topics/data-types)。我们可以在 Ubuntu 16.04 上使用以下命令安装 Redis：

```go
sudo apt-get install redis-server
```

在 macOS X 上，我们可以这样说：

```go
brew install redis
```

对于 Windows，也可以在 Redis 网站上找到二进制文件。安装 Redis 后，可以使用以下命令启动 Redis 服务器：

```go
redis-server
```

它在默认端口`6379`上启动服务器。现在，我们可以使用 Redis CLI（命令行工具）在其中存储任何内容。打开一个新的终端，输入`redis-cli`。一旦启动了 shell，我们可以执行 Redis 命令将数据存储和检索到用户定义的类型变量中：

```go
[7:30:30] naren:~ $ redis-cli
127.0.0.1:6379> SET Foo  1
OK
127.0.0.1:6379> GET Foo
"1"
```

我们可以使用`SET` Redis 命令存储键值。它将值存储为字符串。如果我们尝试执行`GET`，它会返回字符串。我们有责任将它们转换为数字。Redis 为我们提供了方便的函数来操作这些键。例如，我们可以像这样递增一个键：

```go
127.0.0.1:6379> INCR Foo
(integer) 2
```

Redis 在内部将整数视为整数。如果尝试递增非数字字符串，Redis 会抛出错误：

```go
127.0.0.1:6379> SET name "redis"
OK
127.0.0.1:6379> INCR name
(error) ERR value is not an integer or out of range
```

为什么我们在这里讨论 Redis？因为我们正在展示 Redis 的工作原理，并介绍 Redis 服务器上的一些基本命令。我们将把项目从`simpleAuth`修改为`simpleAuthWithRedis`。

在该项目中，我们使用 Redis 而不是在程序内存中存储会话。即使程序崩溃，会话也不会丢失，因为它们保存在外部服务器中。谁为此编写了桥接逻辑？我们应该。幸运的是，我们有一个包来处理 Redis 和 Go 会话包之间的协调。

使用以下命令安装该包：

```go
go get gopkg.in/boj/redistore.v1
```

并创建一个带有一些修改的新程序。在这里，我们使用`redistore`包，而不是使用会话库。`redistore`有一个名为`NewRediStore`的函数，它以 Redis 配置作为参数以及秘钥。所有其他函数保持不变。现在，在`simpleAuthWithRedis`目录中添加一个`main.go`文件：

```go
package main
import (
    "log"
    "net/http"
    "os"
    "time"
    "github.com/gorilla/mux"
    redistore "gopkg.in/boj/redistore.v1"
)
var store, err = redistore.NewRediStore(10, "tcp", ":6379", "", []byte(os.Getenv("SESSION_SECRET")))
var users = map[string]string{"naren": "passme", "admin": "password"}
// HealthcheckHandler returns the date and time
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session.id")
    if (session.Values["authenticated"] != nil) && session.Values["authenticated"] != false {
        w.Write([]byte(time.Now().String()))
    } else {
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}
// LoginHandler validates the user credentials
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session.id")
    err := r.ParseForm()
    if err != nil {
        http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
        return
    }
    username := r.PostForm.Get("username")
    password := r.PostForm.Get("password")
    if originalPassword, ok := users[username]; ok {
        if password == originalPassword {
            session.Values["authenticated"] = true
            session.Save(r, w)
        } else {
            http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
            return
        }
    } else {
        http.Error(w, "User is not found", http.StatusNotFound)
        return
    }
    w.Write([]byte("Logged In successfully"))
}
// LogoutHandler removes the session
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session.id")
    session.Options.MaxAge = -1
    session.Save(r, w)
    w.Write([]byte(""))
}
func main() {
    defer store.Close()
    r := mux.NewRouter()
    r.HandleFunc("/login", LoginHandler)
    r.HandleFunc("/healthcheck", HealthcheckHandler)
    r.HandleFunc("/logout", LogoutHandler)
    http.Handle("/", r)
    srv := &http.Server{
        Handler: r,
        Addr: "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout: 15 * time.Second,
    }
    log.Fatal(srv.ListenAndServe())
}
```

一个有趣的变化是，我们删除了会话，而不是将其值设置为`false`：

```go
  session.Options.MaxAge = -1
```

这个改进的程序与之前的程序完全相同，只是会话保存在 Redis 中。打开 Redis CLI 并输入以下命令以获取所有可用的键：

```go
[15:09:48] naren:~ $ redis-cli
127.0.0.1:6379> KEYS *
1) "session_VPJ54LWRE4DNTYCLEJWAUN5SDLVW6LN6MLB26W2OB4JDT26CR2GA"
127.0.0.1:6379>
```

那个冗长的`"session_VPJ54LWRE4DNTYCLEJWAUN5SDLVW6LN6MLB26W2OB4JDT26CR2GA"`是由`redistore`存储的键。如果我们删除该键，客户端将自动被禁止访问资源。现在停止运行程序并重新启动。您会看到会话没有丢失。通过这种方式，我们可以保存客户端会话。我们也可以在 SQLite 数据库上持久化会话。许多第三方包都是为了使这一点更容易而编写的。

**Redis**可以用作 Web 应用程序的缓存。它可以存储临时数据，如会话、频繁请求的用户内容等。通常与**memcached**进行比较。

# JSON Web Tokens（JWT）和 OAuth2 简介

以前的身份验证方式是明文用户名/密码和基于会话的。它有一个通过将它们保存在程序内存或 Redis/SQLite3 中来管理会话的限制。现代 REST API 实现了基于令牌的身份验证。在这里，令牌可以是服务器生成的任何字符串，允许客户端通过显示令牌来访问资源。在这里，令牌是以这样一种方式计算的，即客户端和服务器只知道如何编码/解码令牌。**JWT**试图通过使我们能够创建可以传递的令牌来解决这个问题。

每当客户端将认证详细信息传递给服务器时，服务器会生成一个令牌并将其传递回客户端。客户端将其保存在某种存储中，例如数据库或本地存储（在浏览器的情况下）。客户端使用该令牌向服务器定义的任何 API 请求资源：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/976d6e2e-da56-43e7-9c9c-ad288472b2ac.png)

这些步骤可以更简要地总结如下：

1.  客户端将用户名/密码在`POST`请求中传递给登录 API。

1.  服务器验证详细信息，如果成功，生成 JWT 并返回，而不是创建 cookie。客户端有责任存储这个令牌。

1.  现在，客户端有了 JWT。它需要在后续的 REST API 调用中添加这个令牌，比如`GET`、`POST`、`PUT`和`DELETE`。

1.  服务器再次检查 JWT，如果成功解码，服务器通过查看作为令牌一部分提供的用户名发送数据。

JWT 确保数据来自正确的客户端。创建令牌的技术负责处理这个逻辑。JWT 利用基于秘钥的加密。

# JSON web token 格式

我们在前面的部分讨论的一切都围绕着 JWT 令牌。我们将在这里看到它真正的样子以及它是如何生成的。JWT 是在执行几个步骤后生成的字符串。它们如下：

1.  通过对标头 JSON 进行**Base64Url**编码来创建 JWT 标头。

1.  通过对有效负载 JSON 进行**Base64Url**编码来创建 JWT 有效负载。

1.  通过使用秘钥对附加的标头和有效负载进行加密来创建签名。

1.  JWT 字符串可以通过附加标头、有效负载和签名来获得。

标头是一个简单的 JSON 对象。在 Go 中，它看起来像以下代码片段：

```go
`{
  "alg": "HS256",
  "typ": "JWT"
}`
```

`"alg"`是用于创建签名的算法（HMAC 与 SHA-256）的简写形式。消息类型是`"JWT"`。这对所有标头都是通用的。算法可能会根据系统而变化。

有效负载看起来像这样：

```go
`{
  "sub": "1234567890",
  "username": "Indiana Jones",
  "admin": true
}`
```

有效负载对象中的键称为声明。声明是指定服务器某些特殊含义的键。有三种类型的声明：

+   公共声明

+   私有声明（更重要）

+   保留声明

# 保留声明

保留声明是由 JWT 标准定义的声明。它们是：

+   iat: 发行时间

+   iss: 发行者名称

+   sub: 主题文本

+   aud: 受众名称

+   exp: 过期时间

例如，服务器在生成令牌时可以在有效负载中设置一个`exp`声明。然后客户端使用该令牌来访问 API 资源。服务器每次验证令牌时。当过期时间过去时，服务器将不再验证令牌。客户端需要通过重新登录生成新的令牌。

# 私有声明

私有声明是用来识别一个令牌与另一个令牌的名称。它可以用于授权。授权是识别哪个客户端发出了请求的过程。多租户是在系统中有多个客户端。服务器可以在令牌的有效负载上设置一个名为`username`的私有声明。下次，服务器可以读取这个有效负载并获取用户名，然后使用该用户名来授权和自定义 API 响应。

`"username": "Indiana Jones"`是前面示例有效负载上的私有声明。**公共声明**类似于私有声明，但它们应该在 IANA JSON Web Token 注册表中注册为标准。我们限制了这些的使用。

可以通过执行以下操作来创建签名（这不是代码，只是一个示例）：

```go
signature = HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

这只是对使用秘钥的 Base64URL 编码的标头和有效负载执行加密算法。这个秘钥可以是任何字符串。它与我们在以前的 cookie 会话中使用的秘钥完全相似。这个秘钥通常保存在环境变量中，并加载到程序中。

现在我们附加编码的标头、编码的有效负载和签名以获得我们的令牌字符串：

```go
tokenString = base64UrlEncode(header) + "." + base64UrlEncode(payload) + "." + signature
```

这就是 JWT 令牌是如何生成的。我们在 Go 中要手动做所有这些事情吗？不。在 Go 或任何其他编程语言中，有一些可用的包来包装令牌的手动创建和验证。Go 有一个名为`jwt-go`的精彩、流行的包。我们将在下一节中创建一个使用`jwt-go`来签署 JWT 并验证它们的项目。可以使用以下命令安装该包：

```go
go get github.com/dgrijalva/jwt-go 
```

这是该项目的官方 GitHub 页面：[`github.com/dgrijalva/jwt-go`](https://github.com/dgrijalva/jwt-go)。该包提供了一些函数，允许我们创建令牌。还有许多其他具有不同附加功能的包。您可以在[`jwt.io/#libraries-io`](https://jwt.io/#libraries-io)上查看所有可用的包和支持的功能。

# 在 Go 中创建 JWT

`jwt-go`包有一个名为`NewWithClaims`的函数，它接受两个参数：

1.  签名方法如 HMAC256、RSA 等

1.  声明映射

例如，它看起来像以下代码片段：

```go
token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
    "username": "admin",
    "iat":time.Now().Unix(),
})
```

`jwt.SigningMethodHS256`是包中可用的加密算法。第二个参数是一个带有声明的映射，例如私有（这里是用户名）和保留（发行于）。现在我们可以使用`SignedString`函数在令牌上生成一个`tokenString`：

```go
tokenString, err := token.SignedString("my_secret_key")
```

然后应将此`tokenString`传回客户端。

# 在 Go 中读取 JWT

`jwt-go`还为我们提供了解析给定 JWT 字符串的 API。`Parse`函数接受字符串和密钥函数作为参数。`key`函数是一个自定义函数，用于验证算法是否正确。假设这是由前面的编码生成的示例令牌字符串：

```go
tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoiMTUwODc0MTU5MTQ2NiJ9.5m6KkuQFCgyaGS_xcVy4xWakwDgtAG3ILGGTBgYVBmE"

```

我们可以解析并获取原始的 JSON 使用：

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // key function
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }
    return "my_secret_key", nil
})

if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    // Use claims for authorization if token is valid
    fmt.Println(claims["username"], claims["iat"])
} else {
    fmt.Println(err)
}
```

`token.Claims`由一个名为`MapClaims`的映射实现。我们可以从该映射中获取原始的 JSON 键值对。

# OAuth 2 架构和基础知识

OAuth 2 是用于在不同系统之间创建身份验证模式的身份验证框架。在此，客户端不是向资源服务器发出请求，而是首先请求某个名为资源所有者的实体。资源所有者返回客户端的身份验证授权（如果凭据成功）。客户端现在将此身份验证授权发送到另一个名为身份验证服务器的实体。此身份验证服务器接受授权并返回访问令牌。此令牌是客户端访问 API 资源的关键。它需要使用此访问令牌向资源服务器发出 API 请求，并提供响应。在整个流程中，第二部分可以使用 JWT 完成。在此之前，让我们了解身份验证和授权之间的区别。

# 身份验证与授权

**身份验证**是识别客户端是否真实的过程。当服务器对客户端进行身份验证时，它会检查用户名/密码对并创建会话 cookie/JWT。

**授权**是在成功身份验证后区分一个客户端与另一个客户端的过程。在云服务中，客户端请求的资源需要通过检查资源是否属于该客户端而不是其他客户端来提供。不同客户端的权限和资源访问也不同。例如，管理员拥有资源的最高权限。普通用户的访问受到限制。

OAuth2 是用于对多个客户端进行身份验证的协议，而 JWT 是一种令牌格式。我们需要对 JWT 令牌进行编码/解码以实现 OAuth 2 的第二阶段（以下截图中的虚线）。

看一下以下图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/e52ff092-f411-4ce0-b04b-536942867fa2.png)

在这个图表中，我们可以使用 JWT 实现虚线部分。身份验证发生在身份验证服务器级别，授权发生在资源服务器级别。

在下一节中，让我们编写一个程序，完成两件事：

1.  对客户端进行身份验证并返回 JWT 字符串。

1.  通过验证 JWT 授权客户端 API 请求。

创建一个名为`jwtauth`的目录并添加`main.go`：

```go
package main
import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"
    jwt "github.com/dgrijalva/jwt-go"
    "github.com/dgrijalva/jwt-go/request"
    "github.com/gorilla/mux"
)
var secretKey = []byte(os.Getenv("SESSION_SECRET"))
var users = map[string]string{"naren": "passme", "admin": "password"}
// Response is a representation of JSON response for JWT
type Response struct {
    Token string `json:"token"`
    Status string `json:"status"`
}
// HealthcheckHandler returns the date and time
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
    tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Don't forget to validate the alg is what you expect:
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
        }
        // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
        return secretKey, nil
    })
    if err != nil {
        w.WriteHeader(http.StatusForbidden)
        w.Write([]byte("Access Denied; Please check the access token"))
        return
    }
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        // If token is valid
        response := make(map[string]string)
        // response["user"] = claims["username"]
        response["time"] = time.Now().String()
        response["user"] = claims["username"].(string)
        responseJSON, _ := json.Marshal(response)
        w.Write(responseJSON)
    } else {
        w.WriteHeader(http.StatusForbidden)
        w.Write([]byte(err.Error()))
    }
}
// LoginHandler validates the user credentials
func getTokenHandler(w http.ResponseWriter, r *http.Request) {
    err := r.ParseForm()
    if err != nil {
        http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
        return
    }
    username := r.PostForm.Get("username")
    password := r.PostForm.Get("password")
    if originalPassword, ok := users[username]; ok {
        if password == originalPassword {
            // Create a claims map
            claims := jwt.MapClaims{
                "username": username,
                "ExpiresAt": 15000,
                "IssuedAt": time.Now().Unix(),
            }
            token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
            tokenString, err := token.SignedString(secretKey)
            if err != nil {
                w.WriteHeader(http.StatusBadGateway)
                w.Write([]byte(err.Error()))
            }
            response := Response{Token: tokenString, Status: "success"}
            responseJSON, _ := json.Marshal(response)
            w.WriteHeader(http.StatusOK)
            w.Header().Set("Content-Type", "application/json")
            w.Write(responseJSON)
        } else {
            http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
            return
        }
    } else {
        http.Error(w, "User is not found", http.StatusNotFound)
        return
    }
}
func main() {
    r := mux.NewRouter()
    r.HandleFunc("/getToken", getTokenHandler)
    r.HandleFunc("/healthcheck", HealthcheckHandler)
    http.Handle("/", r)
    srv := &http.Server{
        Handler: r,
        Addr: "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout: 15 * time.Second,
    }
    log.Fatal(srv.ListenAndServe())
}
```

这是一个非常冗长的程序。首先，我们导入`jwt-go`及其名为`request`的子包。我们为两个端点创建了一个 REST API；一个用于通过提供身份验证详细信息获取访问令牌，另一个用于获取授权用户的健康检查 API。

在**`getTokenHandler`**处理函数中，我们正在将用户名和密码与我们自定义定义的用户映射进行比较。这也可以是一个数据库。如果身份验证成功，我们将生成一个 JWT 字符串并将其发送回客户端。

在`HealthcheckHandler`中，我们从名为`access_token`的标头中获取访问令牌，并通过解析 JWT 字符串来验证它。谁编写验证逻辑？JWT 包本身。当创建新的 JWT 字符串时，它应该有一个名为`ExpiresAt`的声明。参考以下代码片段：

```go
      claims := jwt.MapClaims{
        "username": username,
        "ExpiresAt": 15000,
        "IssuedAt": time.Now().Unix(),
      } 
```

程序的内部验证逻辑查看`IssuedAt`和`ExpiresAt`声明，并尝试计算并查看给定的令牌是否已过期。如果是新鲜的，那么意味着令牌已验证。

现在，当令牌有效时，我们可以在`HealthCheckHandler`中读取有效载荷，解析作为 HTTP 请求标头的`access_token`字符串。`username`是我们为授权插入的自定义私有声明。因此，我们知道实际发送此请求的是谁。对于每个请求，不需要传递会话。每个 API 调用都是独立的且基于令牌的。信息已经编码在令牌中。

`token.Claims.(jwt.MapClaims)`返回一个值为接口而不是字符串的映射。为了将值转换为字符串，我们应该这样做`claims["username"].(string)`。

让我们通过 Postman 工具来看看这个程序是如何运行的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/41e2bbd3-3948-4935-856a-88236498565f.png)

这将返回一个包含 JWT 令牌的 JSON 字符串。将其复制到剪贴板。如果您尝试在不传递 JWT 令牌作为其中一个标头的情况下向健康检查 API 发出请求，您将收到此错误消息而不是 JSON：

```go
Access Denied; Please check the access token
```

现在，将该令牌复制回来，并进行`GET`请求，添加一个`access_token`标头，其值为令牌字符串。在 Postman 中，标头部分可用于添加标头和键值对。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/76d0689e-288d-49e2-a116-ca6449a14e69.png)

它将正确返回时间作为 API 响应的一部分。我们还可以看到这是哪个用户的 JWT 令牌。这证实了我们的 REST API 的授权部分。我们可以将令牌验证逻辑放在每个 API 处理程序中，也可以将其作为中间件，并将其应用于所有处理程序。请参阅第三章，*使用中间件和 RPC*，并修改前面的程序以具有验证 JWT 令牌的中间件。

基于令牌的认证通常不提供注销 API 或用于删除会话基础认证中提供的令牌的 API。只要 JWT 没有过期，服务器就会向客户端提供授权资源。一旦过期，客户端需要刷新令牌，也就是说，向服务器请求一个新令牌。

# 摘要

在本章中，我们介绍了认证的过程。我们看到了认证通常是如何工作的。认证可以分为两种类型：基于会话的认证和基于令牌的认证。基于会话的认证也被称为简单认证，客户端成功登录时会创建一个会话。该会话被保存在客户端并在每个请求中提供。这里有两种可能的情况。在第一种情况下，会话将保存在服务器的程序内存中。当应用程序重新启动时，这种会话将被清除。第二种情况是将会话 cookie 保存在 Redis 中。Redis 是一个可以作为任何 Web 应用程序缓存的内存数据库。Redis 支持存储一些数据类型，如字符串、列表、哈希等。我们探讨了一个名为`redistore`的包，它用于替换用于持久化会话 cookie 的内置会话包。

接下来，我们了解了 JWT。JWT 是执行一些步骤的输出的令牌字符串。首先，创建一个标头、有效载荷和签名。通过使用`base64URL`编码和应用诸如 HMAC 之类的加密算法，可以获得签名。在基于令牌的认证中，客户端需要一个 JWT 令牌来访问服务器资源。因此，最初，它请求服务器提供访问令牌（JWT 令牌）。一旦客户端获得此令牌，下次它使用 JWT 令牌进行 API 调用，并将服务器返回响应。

我们引入了 OAuth 2.0，一个认证框架。在 OAuth 2 中，客户端首先向资源所有者请求授权。一旦获得授权，它就会向认证服务器请求访问令牌。认证服务器会提供访问令牌，客户端可以用它来请求 API。我们用 JWT 实现了 OAuth 2 的第二步。

我们使用一个叫做 Postman 的工具来测试所有的 API。Postman 是一个很棒的工具，可以帮助我们在任何机器上快速测试我们的 API。CURL 只能在 Linux 和 macOS X 上使用。Postman 对于 Windows 来说是一个明智的选择，因为它拥有 CURL 的所有功能。

通过学习如何创建 HTTP 路由、中间件和处理程序，我们从第一章走了很长的路。然后我们将我们的应用程序与数据库连接起来，以存储资源数据。在掌握了基础知识之后，我们探索了微服务和 RPC 等性能调优方面。最后，我们学会了如何部署我们的 Web 服务，并使用认证来保护它们。
