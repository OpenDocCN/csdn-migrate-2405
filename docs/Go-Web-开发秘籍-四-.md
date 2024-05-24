# Go Web 开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC`](https://zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Go 和 Docker

在本章中，我们将涵盖以下内容：

+   构建你的第一个 Go Docker 镜像

+   运行你的第一个 Go Docker 容器

+   将你的 Docker 镜像推送到 Docker 注册表

+   创建你的第一个用户定义的桥接网络

+   在用户定义的桥接网络上运行 MySQL Docker 镜像

+   构建一个 Go web 应用的 Docker 镜像

+   在用户定义的桥接网络上运行一个与 MySQL Docker 容器链接的 web 应用 Docker 容器

# 介绍

随着组织向 DevOps 迈进，Docker 也开始变得流行起来。Docker 允许将应用程序及其所有依赖项打包成标准化的软件开发单元。如果该单元在您的本地机器上运行，我们可以保证它将在任何地方，从 QA 到暂存，再到生产环境中以完全相同的方式运行。通过本章涵盖的概念，我们将能够轻松编写 Docker 镜像并部署 Docker 容器。

在本章中，我们将学习如何创建一个 Docker 镜像和 Docker 容器来部署一个简单的 Go web 应用，之后我们将看看如何将容器保存为镜像并将其推送到 Docker 注册表，以及一些 Docker 网络的基本概念。

由于我们将要使用 Docker，我假设它已经安装并在您的本地机器上运行。

# 构建你的第一个 Go Docker 镜像

Docker 镜像是我们应用程序的文件系统和配置，进一步用于创建 Docker 容器。有两种方式可以创建 Docker 镜像，即从头开始或从父镜像创建。在这个示例中，我们将学习如何从父镜像创建 Docker 镜像。这意味着基本上创建的镜像是指其父级的内容，并且`Dockerfile`中的后续声明修改了父镜像的内容。

# 准备就绪…

通过执行以下命令验证`Docker`和`Docker Machine`是否已安装：

```go
$ docker --version
Docker version 18.03.0-ce, build 0520e24  $ docker-machine --version
docker-machine version 0.14.0, build 89b8332
```

# 操作步骤如下…

1.  创建`http-server.go`，在这里我们将创建一个简单的 HTTP 服务器，它将在浏览`http://docker-machine-ip:8080`或从命令行执行`curl -X GET http://docker-machine-ip:8080`时呈现 Hello World！

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func main() 
{
  http.HandleFunc("/", helloWorld)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  创建一个`DockerFile`，这是一个包含构建镜像所需的所有命令的文本文件。我们将使用`golang:1.9.2`作为基础或父镜像，我们在`Dockerfile`中使用`FROM`指令指定了这一点，如下所示：

```go
FROM golang:1.9.2
 ENV SRC_DIR=/go/src/github.com/arpitaggarwal/
 ENV GOBIN=/go/bin

 WORKDIR $GOBIN

 # Add the source code:
 ADD . $SRC_DIR

 RUN cd /go/src/;

 RUN go install github.com/arpitaggarwal/;
 ENTRYPOINT ["./arpitaggarwal"]

 EXPOSE 8080
```

一切就绪后，目录结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b05638b8-f7e8-4def-a9ad-9d7bd0942ae1.png)

1.  使用`-t`标志执行`docker build`命令构建一个名为`golang-image`的 Docker 镜像，如下所示：

```go
$ docker build --no-cache=true -t golang-image .
```

一旦前面的命令成功执行，它将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/cad5fe0a-9f6d-4cb3-971c-2acb0b1f758a.png)

如果您在公司代理后面构建镜像，您可能需要提供代理设置。您可以通过在`Dockerfile`中使用`ENV`语句添加环境变量来实现这一点，我们通常称之为运行时定制，如下所示：

```go
FROM golang:1.9.2
....
ENV http_proxy "http://proxy.corp.com:80"
ENV https_proxy "http://proxy.corp.com:80"
...
```

我们还可以使用`--build-arg <varname>=<value>`标志在构建时将代理设置传递给构建器，这被称为构建时定制。

```go
$ docker build --no-cache=true --build-arg http_proxy="http://proxy.corp.com:80" -t golang-image.
```

# 工作原理…

通过执行以下命令验证 Docker 镜像是否已成功创建：

```go
$ docker images
```

这将列出所有顶级镜像，它们的仓库、标签和大小，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/be6f1c2f-31f0-42c1-98a7-ee42c510de4c.png)

让我们了解我们创建的`Dockerfile`：

+   `FROM golang:1.9.2`: `FROM`指令指定了基础镜像，对我们来说是`golang:1.9.2`

+   `ENV SRC_DIR=/go/src/github.com/arpitaggarwal/`：在这里，我们使用`ENV`语句将 Go 源代码目录设置为环境变量

+   `ENV GOBIN=/go/bin`：在这里，我们使用`ENV`语句将`GOBIN`或生成可执行二进制文件的目录设置为环境变量。

+   `WORKDIR $GOBIN`：`WORKDIR`指令为我们的镜像设置了任何`RUN`、`CMD`、`ENTRYPOINT`、`COPY`和`ADD`语句的工作目录，对于我们的镜像来说，这个目录是`/go/bin`。

+   `ADD . $SRC_DIR`：在这里，我们使用`ADD`语句将当前目录中的`http-server.go`复制到`golang-image`的`/go/src/github.com/arpitaggarwal/`目录中。

+   `RUN cd /go/src/`：在这里，我们使用`RUN`语句将当前目录更改为`/go/src/`中的`golang-image`。

+   `RUN go install github.com/arpitaggarwal/`：在这里，我们编译`/go/src/github.com/arpitaggarwal/http-server.go`，并在`/go/bin`目录中生成可执行二进制文件。

+   `ENTRYPOINT ["./arpitaggarwal"]`：在这里，我们指定要作为可执行文件运行的可执行二进制文件。

+   `EXPOSE 8080`：`EXPOSE`指令通知 Docker，我们将从镜像创建的容器在运行时监听网络端口`8080`。

# 运行您的第一个 Go Docker 容器

Docker 容器包括一个应用程序及其所有依赖项。它与其他容器共享内核，并作为主机操作系统上用户空间中的隔离进程运行。要运行实际的应用程序，我们必须从镜像创建和运行容器，这将在本教程中介绍。

# 如何做…

执行`docker run`命令从`golang-image`创建并运行一个 Docker 容器，使用`-name`标志将容器命名为`golang-container`，如下所示：

```go
$ docker run -d -p 8080:8080 --name golang-container -it golang-image
 9eb53d8d41a237ac216c9bb0f76b4b47d2747fab690569ef6ff4b216e6aab486
```

`docker run`命令中指定的`-d`标志以守护进程模式启动容器，末尾的哈希字符串代表`golang-container`的 ID。

# 工作原理…

通过执行以下命令验证 Docker 容器是否已创建并成功运行：

```go
$ docker ps
```

一旦上述命令成功执行，它将给我们正在运行的 Docker 容器的详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9a846dfe-dc9b-4426-ac8f-f9d8d08c6ebd.png)

要列出所有 Docker 容器，无论它们是否正在运行，我们必须传递一个额外的标志`-a`，如`docker ps -a`。

浏览`http://localhost:8080/`或从命令行执行`GET`调用，如下所示：

```go
$ curl -X GET http://localhost:8080/
 Hello World!
```

这将给我们一个 Hello World!的响应，这意味着 HTTP 服务器在 Docker 容器内的端口`8080`上监听。

# 将您的 Docker 镜像推送到 Docker 注册表

一旦创建了 Docker 镜像，最佳做法是存储或保存该镜像，这样下次您要从自定义镜像启动容器时，就不必再去烦恼或记住之前创建它时执行的步骤。

您可以将镜像保存在本地计算机上，也可以保存在艺术工厂或任何公共或私有的 Docker 注册表中，例如 Docker Hub、Quay、Google 容器注册表、AWS 容器注册表等。在本教程中，我们将学习如何将我们在之前的教程中创建的镜像保存或推送到 Docker Hub。

查看*构建您的第一个 Go Docker 镜像*教程*.*

# 如何做…

1.  在 Docker Hub（`https://hub.docker.com/`）上创建您的帐户。

1.  通过执行`docker login`命令从命令行登录到 Docker Hub，如下所示：

```go
$ docker login --username arpitaggarwal --password XXXXX
 Login Succeeded
```

1.  为`golang-image`打标签：

```go
$ docker tag golang-image arpitaggarwal/golang-image
```

1.  通过执行`docker images`命令验证镜像是否已成功标记：

```go
$ docker images
```

执行上述命令将列出所有 Docker 镜像，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/40e5fcf6-d25b-4998-b6fc-5b91f72ca170.png)

1.  通过执行`docker push`命令将标记的镜像推送到 Docker Hub，如下所示：

```go
$ docker push arpitaggarwal/golang-image
 The push refers to a repository [docker.io/arpitaggarwal
 /golang-image]
 4db0afeaa6dd: Pushed
 4e648ebe6cf2: Pushed
 6bfc813a3812: Mounted from library/golang
 e1e44e9665b9: Mounted from library/golang
 1654abf914f4: Mounted from library/golang
 2a55a2194a6c: Mounted from library/golang
 52c175f1a4b1: Mounted from library/golang
 faccc7315fd9: Pushed
 e38b8aef9521: Mounted from library/golang
 a75caa09eb1f: Mounted from library/golang
 latest: digest: sha256:ca8f0a1530d3add72ad4e328e51235ef70c5fb8f38bde906a378d74d2b75c8a8 size: 2422
```

# 工作原理…

要验证图像是否已成功推送到 Docker Hub，请浏览`https://hub.docker.com/`，使用您的凭据登录，一旦登录，您将看到已标记的图像，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ee77a49d-e970-41bc-8a31-abdc1640fb86.png)

如果对 Docker 容器进行了任何更改，并且希望将其作为图像的一部分进行持久化，那么首先必须使用`docker commit`命令将更改提交到新图像或相同图像，然后将其标记并推送到 Docker Hub，如下所示：

**`$ docker commit <container-id> golang-image-new`**

**`$ docker tag golang-image-new arpitaggarwal/golang-image`**

**`$ docker push arpitaggarwal/golang-image`**

# 创建您的第一个用户定义的桥接网络

每当我们想要通过容器名称将一个 Docker 容器连接到另一个 Docker 容器时，首先我们必须创建一个用户定义的网络。这是因为 Docker 不支持在默认桥接网络上的自动服务发现。在本教程中，我们将学习如何创建自己的桥接网络。

# 如何做…

执行`docker network`命令创建一个名为`my-bridge-network`的桥接网络，如下所示：

```go
$ docker network create my-bridge-network
 325bca66cc2ccb98fb6044b1da90ed4b6b0f29b54c4588840e259fb7b6505331
```

# 它是如何工作的…

通过执行以下命令验证`my-bridge-network`是否已成功创建：

```go
$ docker network ls
 NETWORK ID NAME DRIVER
 20dc090404cb bridge bridge
 9fa39d9bb674 host host
 325bca66cc2c my-bridge-network bridge
 f36203e11372 none null
```

要查看有关`my-bridge-network`的详细信息，请运行`docker network inspect`命令，然后输入网络名称，如下所示：

```go
$ docker network inspect my-bridge-network
 [
 {
 "Name": "my-bridge-network",
 "Id": "325bca66cc2ccb98fb6044b1da90ed4b6b0
     f29b54c4588840e259fb7b6505331",
 "Scope": "local",
 "Driver": "bridge",
 "EnableIPv6": false,
 "IPAM": 
     {
 "Driver": "default",
 "Options": {},
 "Config": 
       [
 {
 "Subnet": "172.18.0.0/16",
 "Gateway": "172.18.0.1"
 }
 ]
 },
 "Internal": false,
 "Containers": {},
 "Options": {},
 "Labels": {}
 }
 ]
```

# 在用户定义的桥接网络上运行 MySQL Docker 图像

每当我们运行 Docker 图像创建和启动容器时，它都会使用默认的桥接网络，Docker 在安装期间创建。要在特定网络上运行图像，该网络可以是用户定义的，也可以是 Docker 自动创建的另外两个网络之一，即主机或无网络，我们必须在`docker run`命令的一部分中提供附加的`--net`标志，并将值作为网络名称。

在本教程中，我们将在上一个教程中创建的用户定义的桥接网络上运行 MySQL 图像，将`--net`标志值传递为`my-bridge-network`。

# 如何做…

执行`docker run`命令，从`mysql:latest`图像创建和运行 MySQL Docker 容器，并使用`--name`标志将容器名称分配为`mysql-container`，如下所示：

```go
$ docker run --net=my-bridge-network -p 3306:3306 --name mysql-container -e MYSQL_ROOT_PASSWORD=my-pass -d mysql:latest
 c3ca3e6f253efa40b1e691023155ab3f37eb07b767b1744266ac4ae85fca1722
```

`docker run`命令中指定的`--net`标志将`mysql-container`连接到`my-bridge-network`。`docker run`命令中指定的`-p`标志将容器的`3306`端口发布到主机的`3306`端口。`docker run`命令中指定的`-e`标志将`MYSQL_ROOT_PASSWORD`值设置为`my-pass`，这是`mysql:latest`图像的环境变量。`docker run`命令中指定的`-d`标志以守护进程模式启动容器，末尾的哈希字符串表示`mysql-container`的 ID。

# 它是如何工作…

通过执行以下命令验证 Docker 容器是否已成功创建并正在运行：

```go
$ docker ps
 CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
 f2ec80f82056 mysql:latest "docker-entrypoint.sh" 8 seconds ago Up 6 seconds 0.0.0.0:3306->3306/tcp mysql-container
```

再次检查`my-bridge-network`将在`Containers`部分显示`mysql-container`的详细信息，如下所示：

```go
$ docker network inspect my-bridge-network
[
 {
 "Name": "my-bridge-network",
 "Id": "325bca66cc2ccb98fb6044b1da90ed
    4b6b0f29b54c4588840e259fb7b6505331",
 "Scope": "local",
 "Driver": "bridge",
 "EnableIPv6": false,
 "IPAM": 
    {
 "Driver": "default",
 "Options": {},
 "Config": 
      [
 {
 "Subnet": "172.18.0.0/16",
 "Gateway": "172.18.0.1"
 }
 ]
 },
 "Internal": false,
 "Containers": 
    {
 "f2ec80f820566707ba7b18ce12ca7a65
      c87fa120fd4221e11967131656f68e59": 
      {
 "Name": "mysql-container",
 "EndpointID": "58092b80bd34135d94154e4d8a8f5806bad
        601257cfbe28e53b5d7161da3b350",
 "MacAddress": "02:42:ac:12:00:02",
 "IPv4Address": "172.18.0.2/16",
 "IPv6Address": ""
 }
 },
 "Options": {},
 "Labels": {}
 }
]
```

# 构建 Go Web 应用程序 Docker 图像

在本教程中，我们将构建一个 Docker 图像，该图像连接到单独运行的 MySQL 数据库实例的 Docker 容器。

# 如何做…

1.  创建`http-server.go`，在其中我们将创建一个简单的 HTTP 服务器和一个处理程序，该处理程序将为我们提供当前数据库详细信息，例如机器 IP、主机名、端口和所选数据库，如下所示：

```go
package main
import 
(
  "bytes"
  "database/sql"
  "fmt"
  "log"
  "net/http"
  "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
)
var db *sql.DB
var connectionError error
const 
(
  CONN_PORT = "8080"
  DRIVER_NAME = "mysql"
  DATA_SOURCE_NAME = "root:my-pass@tcp(mysql-container:3306)/mysql"
)
func init() 
{
  db, connectionError = sql.Open(DRIVER_NAME, DATA_SOURCE_NAME)
  if connectionError != nil 
  {
    log.Fatal("error connecting to database : ", connectionError)
  }
}
func getDBInfo(w http.ResponseWriter, r *http.Request) 
{
  rows, err := db.Query("SELECT SUBSTRING_INDEX(USER(), 
  '@', -1) AS ip, @@hostname as hostname, @@port as port,
  DATABASE() as current_database;")
  if err != nil 
  {
    log.Print("error executing database query : ", err)
    return
  }
  var buffer bytes.Buffer
  for rows.Next() 
  {
    var ip string
    var hostname string
    var port string
    var current_database string
    err = rows.Scan(&ip, &hostname, &port, &current_database)
    buffer.WriteString("IP :: " + ip + " | HostName :: " + 
    hostname + " | Port :: " + port + " | Current 
    Database :: " + current_database)
  }
  fmt.Fprintf(w, buffer.String())
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/", getDBInfo).Methods("GET")
  defer db.Close()
  err := http.ListenAndServe(":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  创建一个`DockerFile`，这是一个包含构建图像所需的所有命令的文本文件，如下所示：

```go
FROM golang:1.9.2

 ENV SRC_DIR=/go/src/github.com/arpitaggarwal/
 ENV GOBIN=/go/bin

 WORKDIR $GOBIN

 ADD . $SRC_DIR

 RUN cd /go/src/;
 RUN go get github.com/go-sql-driver/mysql;
 RUN go get github.com/gorilla/mux;

 RUN go install github.com/arpitaggarwal/;
 ENTRYPOINT ["./arpitaggarwal"]

 EXPOSE 8080
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f165d975-c3c5-4163-b580-0f4266b4ded8.png)

1.  从`Dockerfile`构建 Docker 图像，使用`-t`标志将图像名称设置为`web-application-image`，如下所示：

```go
$ docker build --no-cache=true -t web-application-image .
```

一旦上述命令成功执行，它将呈现以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/884a7e97-83a5-47dc-beeb-3dbcf5eb767f.png)

# 工作原理…

通过执行以下命令验证 Docker 镜像是否已成功创建：

```go
$ docker images
```

这将列出所有顶级镜像，它们的存储库、标签和大小，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/4a91e907-a6a4-4095-afa9-ad6fb5853bc6.png)

我们在这个教程中创建的`Dockerfile`与我们在之前的教程中创建的完全相同，除了在构建镜像时安装 Go MySQL Driver 和 Gorilla Mux URL 路由器的两个额外命令，如下：

```go
...
RUN go get github.com/go-sql-driver/mysql;
RUN go get github.com/gorilla/mux;
...
```

参见*构建您的第一个 Go Docker 镜像*教程。

# 在用户定义的桥接网络上运行与 MySQL Docker 容器链接的 Web 应用程序 Docker 容器

在这个教程中，我们将学习如何运行一个 Go Web 应用程序 Docker 镜像，创建一个容器，该容器将与在单独的 Docker 容器中运行的 MYSQL 数据库实例进行通信。

由于我们知道 Docker 不支持默认桥接网络上的自动服务发现，我们将使用我们在之前的教程中创建的用户定义网络来运行 Go Web 应用程序 Docker 镜像。

# 如何做…

执行`docker run`命令，从`web-application-image`创建一个 Web 应用程序 Docker 容器，使用`--name`标志将容器名称指定为`web-application-container`，命令如下：

```go
$ docker run --net=my-bridge-network -p 8090:8080 --name web-application-container -d web-application-image
 ef9c73396e9f9e04c94b7327e8f02cf57ce5f0cd674791e2805c86c70e5b9564
```

`docker run`命令中指定的`--net`标志将`mysql-container`连接到`my-bridge-network`。`docker run`命令中指定的`-p`标志将容器的`8080`端口发布到主机的`8080`端口。`docker run`命令中指定的`-d`标志以守护进程模式启动容器，末尾的哈希字符串表示`web-application-container`的 ID。

# 工作原理…

通过执行以下命令验证 Docker 容器是否已成功创建并正在运行：

```go
$ docker ps
```

这将呈现以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f2028534-abca-4878-b2fc-192464b36bb2.png)

浏览`http://localhost:8090/`将会给我们返回机器 IP、主机名、端口和当前数据库详情：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/96c2854b-5a25-492a-8c25-c9fb8b438d93.png)

此外，再次检查`my-bridge-network`将显示`mysql-container`和`web-application-container`的详细信息在`Containers`部分，如下：

```go
$ docker network inspect my-bridge-network
[
 {
 "Name": "my-bridge-network",
 "Id": "325bca66cc2ccb98fb6044b1da90ed4b6b0
    f29b54c4588840e259fb7b6505331",
 "Scope": "local",
 "Driver": "bridge",
 "EnableIPv6": false,
 "IPAM": 
    {
 "Driver": "default",
 "Options": {},
 "Config": 
      [
 {
 "Subnet": "172.18.0.0/16",
 "Gateway": "172.18.0.1"
 }
 ]
 },
 "Internal": false,
 "Containers": 
    {
 "08ce8f20c3205fa3e421083fa1077b
      673cdd10fd5be34f5ef431fead06219019": 
      {
 "Name": "web-application-container",
 "EndpointID": "d22f7076cf037ef0f0057ffb9fec
        0a07e07b44b442182544731db1ad10db87e4",
 "MacAddress": "02:42:ac:12:00:03",
 "IPv4Address": "172.18.0.3/16",
 "IPv6Address": ""
 },
 "f2ec80f820566707ba7b18ce12ca7a65
      c87fa120fd4221e11967131656f68e59": 
      {
 "Name": "mysql-container",
 "EndpointID": "58092b80bd34135d94154e4d8
        a8f5806bad601257cfbe28e53b5d7161da3b350",
 "MacAddress": "02:42:ac:12:00:02",
 "IPv4Address": "172.18.0.2/16",
 "IPv6Address": ""
 }
 },
 "Options": {},
 "Labels": {}
 }
]
```


# 第十章：保护 Go Web 应用程序

在本章中，我们将涵盖以下内容：

+   使用 OpenSSL 创建私钥和 SSL 证书

+   将 HTTP 服务器移动到 HTTPS

+   定义 REST API 和路由

+   创建 JSON Web 令牌

+   使用 JSON Web 令牌保护 RESTful 服务

+   在 Go Web 应用程序中防止跨站点请求伪造

# 介绍

保护 Web 应用程序是本章中我们将学习的最重要的方面之一，除了创建应用程序。应用程序安全是一个非常广泛的主题，可以以超出本章范围的各种方式实现。

在本章中，我们将专注于如何将我们的 Go Web 应用程序从 HTTP 协议移动到 HTTPS，通常称为**HTTP + TLS** **(传输层安全)**，以及使用**JSON Web 令牌** **(JWTs)**保护 Go Web 应用程序 REST 端点，并保护我们的应用程序免受**跨站点请求伪造（CSRF）**攻击。

# 使用 OpenSSL 创建私钥和 SSL 证书

将运行在 HTTP 上的服务器移动到 HTTPS，我们首先要做的是获取 SSL 证书，这可能是自签名的，也可能是由受信任的证书颁发机构（如 Comodo、Symantec 或 GoDaddy）签名的证书。

要获得由受信任的证书颁发机构签名的 SSL 证书，我们必须向他们提供**证书签名请求**（**CSR**），主要包括密钥对的公钥和一些附加信息，而自签名证书是您可以自行签发的证书，用自己的私钥签名。

自签名证书可以用于加密数据，也可以用 CA 签名的证书，但用户将收到一个警告，说证书未被他们的计算机或浏览器信任。因此，您不应该在生产或公共服务器上使用它们。

在这个教程中，我们将学习如何创建私钥、证书签名请求和自签名证书。

# 准备工作…

本教程假设您的机器上已安装了`openssl`。要验证是否已安装，请执行以下命令：

```go
$ openssl
OpenSSL> exit
```

# 如何做…

1.  使用`openssl`执行以下命令生成私钥和证书签名请求：

```go
$ openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr -subj "/C=IN/ST=Mumbai/L=Andheri East/O=Packt/CN=packtpub.com"
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e4195e84-d3b8-4163-b65e-2562c8c6e5e5.png)

1.  通过执行以下命令生成证书并用刚创建的私钥签名：

```go
$ openssl req -key domain.key -new -x509 -days 365 -out domain.crt -subj "/C=IN/ST=Mumbai/L=Andheri East/O=Packt/CN=packtpub.com"
```

# 工作原理…

一旦命令成功执行，我们可以看到生成了`domain.key`、`domain.csr`和`domain.crt`，其中`domain.key`是用于签署 SSL 证书的 2,048 位 RSA 私钥，而`domain.crt`和`domain.csr`是证书签名请求，包含了密钥对的公钥和一些附加信息，这些信息在签署证书时被插入。

让我们了解我们执行的生成证书签名请求的命令：

+   `-newkey rsa:2048`选项创建一个新的证书请求和一个新的私钥，应该是使用 RSA 算法生成的 2,048 位私钥。

+   `-nodes`选项指定创建的私钥不会使用密码短语加密。

+   `-keyout domain.key`选项指定要将新创建的私钥写入的文件名。

+   `-out domain.csr`选项指定要写入的输出文件名，或者默认情况下为标准输出。

+   `-subj`选项用指定的数据替换输入请求的主题字段，并输出修改后的请求。如果我们不指定此选项，则必须通过`OpenSSL`回答 CSR 信息提示以完成该过程。

接下来，我们将了解我们执行的生成证书并用私钥签名的命令，如下所示：

```go
openssl req -key domain.key -new -x509 -days 365 -out domain.crt -subj "/C=IN/ST=Mumbai/L=Andheri East/O=Packt/CN=packtpub.com"
```

`-key`选项指定从中读取私钥的文件。`-x509`选项输出自签名证书而不是证书请求。`-days 365`选项指定证书的认证天数。默认值为 30 天。

# 将 HTTP 服务器移动到 HTTPS

一旦 Web 应用程序开发结束，我们很可能会将其部署到服务器上。在部署时，建议始终在公开暴露的服务器上使用 HTTPS 协议运行 Web 应用程序，而不是 HTTP。在本教程中，我们将学习如何在 Go 中实现这一点。

# 如何做…

1.  创建`https-server.go`，在其中我们将定义一个处理程序，该处理程序将仅为所有 HTTPS 请求向 HTTP 响应流写入 Hello World！，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8443"
  HTTPS_CERTIFICATE = "domain.crt"
  DOMAIN_PRIVATE_KEY = "domain.key"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func main() 
{
  http.HandleFunc("/", helloWorld)
  err := http.ListenAndServeTLS(CONN_HOST+":"+CONN_PORT,
  HTTPS_CERTIFICATE, DOMAIN_PRIVATE_KEY, nil)
  if err != nil 
  {
    log.Fatal("error starting https server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run https-server.go
```

# 工作原理…

一旦我们运行程序，HTTPS 服务器将在本地监听端口`8443`上启动。

浏览`https://localhost:8443/`将从服务器获得 Hello World!作为响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b88936f9-4a85-446f-bcc1-41e96312da93.png)

此外，使用`curl`从命令行执行`GET`请求并传递`--insecure`标志将跳过证书验证，因为我们使用的是自签名证书：

```go
$ curl -X GET https://localhost:8443/ --insecure
 Hello World!
```

让我们了解我们编写的程序：

+   `const (CONN_HOST = "localhost" CONN_PORT = "8443" HTTPS_CERTIFICATE = "domain.crt" DOMAIN_PRIVATE_KEY = "domain.key")`：在这里，我们声明了四个常量—`CONN_HOST`的值为`localhost`，`CONN_PORT`的值为`8443`，`HTTPS_CERTIFICATE`的值为`domain.crt`或自签名证书，`DOMAIN_PRIVATE_KEY`的值为`domain.key`或我们在上一个教程中创建的私钥。

+   `func helloWorld(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "Hello World!") }`：这是一个 Go 函数，它以`ResponseWriter`和`Request`作为输入参数，并在 HTTP 响应流上写入`Hello World!`。

接下来，我们声明了`main()`，程序从这里开始执行。由于这个方法做了很多事情，让我们逐行理解它：

+   `http.HandleFunc("/", helloWorld)`: 在这里，我们使用`net/http`包的`HandleFunc`将`helloWorld`函数注册到 URL 模式`/`，这意味着每当我们访问 HTTPS URL 模式`/`时，`helloWorld`都会被执行，并将`(http.ResponseWriter, *http.Request)`作为输入传递给它。

+   `err := http.ListenAndServeTLS(CONN_HOST+":"+CONN_PORT, HTTPS_CERTIFICATE, DOMAIN_PRIVATE_KEY, nil)`: 在这里，我们调用`http.ListenAndServeTLS`来提供处理每个传入连接的 HTTPS 请求的请求。`ListenAndServeTLS`接受四个参数—服务器地址、SSL 证书、私钥和处理程序。在这里，我们将服务器地址传递为`localhost:8443`，我们的自签名证书、私钥和处理程序为`nil`，这意味着我们要求服务器使用`DefaultServeMux`作为处理程序。

+   `if err != nil { log.Fatal("error starting https server : ", err) return}`：在这里，我们检查启动服务器时是否有任何问题。如果有问题，则记录错误并以状态码 1 退出。

# 定义 REST API 和路由

在编写 RESTful API 时，很常见的是在允许用户访问之前对用户进行身份验证。身份验证用户的先决条件是创建 API 路由，我们将在本教程中介绍。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/mux`和`github.com/gorilla/handlers`包，如下所示：

```go
$ go get github.com/gorilla/mux
$ go get github.com/gorilla/handlers
```

1.  创建`http-rest-api.go`，在其中我们将定义三个路由—`/status`、`/get-token`和`/employees`—以及它们的处理程序，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "os"
  "github.com/gorilla/handlers"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Employee struct 
{
  Id int `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: 1, FirstName: "Foo", LastName: "Bar"},
    Employee{Id: 2, FirstName: "Baz", LastName: "Qux"},
  }
}
func getStatus(w http.ResponseWriter, r *http.Request) 
{
  w.Write([]byte("API is up and running"))
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func getToken(w http.ResponseWriter, r *http.Request) 
{ 
  w.Write([]byte("Not Implemented"))
}
func main() 
{
  router := mux.NewRouter().StrictSlash(true)
  router.HandleFunc("/status", getStatus).Methods("GET")
  router.HandleFunc("/get-token", getToken).Methods("GET")
  router.HandleFunc("/employees", getEmployees).Methods("GET")
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT,
  handlers.LoggingHandler(os.Stdout, router))
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-api.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`上启动。

接下来，您可以从命令行执行`GET`请求，如下所示：

```go
$ curl -X GET http://localhost:8080/status
 API is up and running
```

这将给您 REST API 的状态。您可以从命令行执行`GET`请求，如下所示：

```go
$ curl -X GET http://localhost:8080/employees
 [{"id":1,"firstName":"Foo","lastName":"Bar"},{"id":2,"firstName":"Baz","lastName":"Qux"}]
```

这将给你一个所有员工的列表。我们可以尝试通过命令行获取访问令牌：

```go
$ curl -X GET http://localhost:8080/get-token
```

我们将从服务器获取“Not Implemented”消息。

让我们了解我们编写的程序：

+   `import ("encoding/json" "log" "net/http" "os" “github.com/gorilla/handlers" "github.com/gorilla/mux")`：在这里，我们导入了`github.com/gorilla/mux`来创建一个 Gorilla Mux 路由器，以及`github.com/gorilla/handlers`来创建一个 Gorilla 日志处理程序，以 Apache Common Log Format 记录 HTTP 请求。

+   `func getStatus(w http.ResponseWriter, r *http.Request) { w.Write([]byte("API is up and running"))}`：这是一个处理程序，它只是向 HTTP 响应流写入 API 正在运行。

+   `func getEmployees(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(employees)}`：这是一个处理程序，它将一个静态员工数组写入 HTTP 响应流。

+   这是一个处理程序，它只是向 HTTP 响应流写入“Not Implemented”。

+   然后，我们定义了`main()`，在其中我们使用`NewRouter()`处理程序创建了一个`gorilla/mux`路由器实例，对新路由的尾随斜杠行为设置为`true`，添加路由并向其注册处理程序，最后调用`http.ListenAndServe`来处理每个传入连接的 HTTP 请求，每个连接在单独的 Goroutine 中处理。`ListenAndServe`接受两个参数——服务器地址和处理程序。在这里，我们将服务器地址传递为`localhost:8080`，处理程序为 Gorilla `LoggingHandler`，它以 Apache Common Log Format 记录 HTTP 请求。

# 创建 JSON Web 令牌

要保护您的 REST API 或服务端点，您必须编写一个在 Go 中生成 JSON Web 令牌或`JWT`的处理程序。

在这个示例中，我们将使用`https://github.com/dgrijalva/jwt-go`来生成`JWT`，尽管您可以在 Go 中实现许多第三方库中提供的任何库，例如`https://github.com/square/go-jose`和`https://github.com/tarent/loginsrv`。

# 如何做…

1.  使用`go get`命令安装`github.com/dgrijalva/jwt-go`、`github.com/gorilla/mux`和`github.com/gorilla/handlers`包，如下所示：

```go
$ go get github.com/dgrijalva/jwt-go
$ go get github.com/gorilla/handlers
$ go get github.com/gorilla/mux
```

1.  创建`create-jwt.go`，在其中我们将定义`getToken`处理程序来生成`JWT`，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "os"
  "time"
  jwt "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/handlers"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  CLAIM_ISSUER = "Packt"
  CLAIM_EXPIRY_IN_HOURS = 24
)
type Employee struct 
{
  Id int `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: 1, FirstName: "Foo", LastName: "Bar"},
    Employee{Id: 2, FirstName: "Baz", LastName: "Qux"},
  }
}
var signature = []byte("secret")
func getToken(w http.ResponseWriter, r *http.Request) 
{
  claims := &jwt.StandardClaims
  {
    ExpiresAt: time.Now().Add(time.Hour *
    CLAIM_EXPIRY_IN_HOURS).Unix(),
    Issuer: CLAIM_ISSUER,
  }
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
  tokenString, _ := token.SignedString(signature)
  w.Write([]byte(tokenString))
}
func getStatus(w http.ResponseWriter, r *http.Request) 
{
  w.Write([]byte("API is up and running"))
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  muxRouter.HandleFunc("/status", getStatus).Methods("GET")
  muxRouter.HandleFunc("/get-token", getToken).Methods("GET")
  muxRouter.HandleFunc("/employees", getEmployees).Methods("GET")
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT,
  handlers.LoggingHandler(os.Stdout, muxRouter))
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run create-jwt.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，我们从命令行执行一个`GET`请求：

```go
$ curl -X GET http://localhost:8080/status
 API is up and running
```

它将给你 API 的状态。接下来，我们从命令行执行一个`GET`请求：

```go
$ curl -X GET http://localhost:8080/employees
 [{"id":1,"firstName":"Foo","lastName":"Bar"},{"id":2,"firstName":"Baz","lastName":"Qux"}]
```

它将给你一个所有员工的列表。接下来，让我们尝试通过命令行获取 REST API 的访问令牌：

```go
$ curl -X GET http://localhost:8080/get-token
```

它将给我们生成的 JWT 令牌：

```go
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTM1MDY4ODEsImlzcyI6IlBhY2t0In0.95vuiR7lpWt4AIBDasBzOffL_Xv78_J9rcrKkeqSW08
```

接下来，浏览到`https://jwt.io/`，并将生成的令牌粘贴到 Encoded 部分，以查看其解码值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f3d84091-ec25-4d4a-a277-8a034edb5fd8.png)

让我们了解我们在这个示例中引入的更改：

+   `import ( "encoding/json" "log" "net/http" "os" "time" jwt "github.com/dgrijalva/jwt-go" "github.com/gorilla/handlers" "github.com/gorilla/mux")`：在这里，我们导入了一个额外的包——`github.com/dgrijalva/jwt-go`，它具有 JWT 的 Go 实现。

+   `const ( CONN_HOST = "localhost" CONN_PORT = "8080" CLAIM_ISSUER = "Packt" CLAIM_EXPIRY_IN_HOURS = 24 )`：在这里，我们引入了两个额外的常量——一个是`CLAIM_ISSUER`，用于标识发出 JWT 的主体，另一个是`CLAIM_EXPIRY_IN_HOURS`，用于标识 JWT 必须在到期时间之后多长时间内不被接受进行处理。

+   `var signature = []byte("secret")`：这是服务器保存的签名。使用这个签名，服务器将能够验证现有令牌并签发新令牌。

接下来，我们定义了一个`getToken`处理程序，在其中我们首先使用`JWT StandardClaims`处理程序准备了一个声明对象，然后使用`jwt NewWithClaims`处理程序生成了一个 JWT 令牌，并最终使用服务器签名对其进行签名，并将其写入 HTTP 响应流。

# 使用 JSON Web Token 保护 RESTful 服务

一旦我们有了 REST API 端点和 JWT 令牌生成处理程序，我们就可以轻松地使用 JWT 保护我们的端点，我们将在本教程中介绍。

# 如何做…

1.  使用`go get`命令安装`github.com/auth0/go-jwt-middleware`、`github.com/dgrijalva/jwt-go`、`github.com/gorilla/mux`和`github.com/gorilla/handlers`包，如下所示：

```go
$ go get github.com/auth0/go-jwt-middleware
$ go get github.com/dgrijalva/jwt-go
$ go get github.com/gorilla/handlers
$ go get github.com/gorilla/mux
```

1.  创建`http-rest-api-secured.go`，在其中我们将定义 JWT 中间件以检查 HTTP 请求中的 JWT，并将`/employees`路由包装在其中，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "os"
  "time"
  jwtmiddleware "github.com/auth0/go-jwt-middleware"
  jwt "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/handlers"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  CLAIM_ISSUER = "Packt"
  CLAIM_EXPIRY_IN_HOURS = 24
)
type Employee struct 
{
  Id int `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: 1, FirstName: "Foo", LastName: "Bar"},
    Employee{Id: 2, FirstName: "Baz", LastName: "Qux"},
  }
}
var signature = []byte("secret")
var jwtMiddleware = jwtmiddleware.New
(
  jwtmiddleware.Options
  {
    ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) 
    {
      return signature, nil
    },
    SigningMethod: jwt.SigningMethodHS256,
  }
)
func getToken(w http.ResponseWriter, r *http.Request) 
{
  claims := &jwt.StandardClaims
  {
    ExpiresAt: time.Now().Add(time.Hour *
    CLAIM_EXPIRY_IN_HOURS).Unix(),
    Issuer: CLAIM_ISSUER,
  }
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
  tokenString, _ := token.SignedString(signature)
  w.Write([]byte(tokenString))
}
func getStatus(w http.ResponseWriter, r *http.Request) 
{
  w.Write([]byte("API is up and running"))
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  muxRouter.HandleFunc("/status", getStatus).Methods("GET")
  muxRouter.HandleFunc("/get-token", getToken).Methods("GET")
  muxRouter.Handle("/employees", jwtMiddleware.Handler
  (http.HandlerFunc(getEmployees))).Methods("GET")
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT,
  handlers.LoggingHandler(os.Stdout, muxRouter))
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-api-secured.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，我们从命令行执行`GET`请求，如下所示：

```go
$ curl -X GET http://localhost:8080/status
 API is up and running
```

它将向我们显示 API 的状态。接下来，我们从命令行执行`GET`请求，如下所示：

```go
$ curl -X GET http://localhost:8080/employees
 Required authorization token not found
```

它将向我们显示 JWT 未在请求中找到的消息。因此，要获取所有员工的列表，我们必须获取 API 的访问令牌，可以通过执行以下命令获取：

```go
$ curl -X GET http://localhost:8080/get-token

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTM1MTI2NTksImlzcyI6IlBhY2t0In0.2r_q_82erdOmt862ofluiMGr3O5x5_c0_sMyW7Pi5XE
```

现在，再次调用员工 API，将 JWT 作为 HTTP`Authorization`请求头传递，如下所示：

```go
$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTM1MTI2NTksImlzcyI6IlBhY2t0In0.2r_q_82erdOmt862ofluiMGr3O5x5_c0_sMyW7Pi5XE" http://localhost:8080/employees
```

它将为您提供所有员工的列表，如下所示：

```go
[{"id":1,"firstName":"Foo","lastName":"Bar"},{"id":2,"firstName":"Baz","lastName":"Qux"}]
```

让我们了解本教程中引入的更改：

1.  使用`import（"encoding/json" "log" "net/http" "os" "time" jwtmiddleware "github.com/auth0/go-jwt-middleware" jwt "github.com/dgrijalva/jwt-go" "github.com/gorilla/handlers" "github.com/gorilla/mux"）`，我们导入了一个额外的包，`github.com/auth0/go-jwt-middleware`，别名为`jwtmiddleware`，它在 HTTP 请求中检查 JWT。

1.  然后，我们构建了一个新的安全实例`jwtmiddleware`，将`SigningMethod`设置为`HS256`，并将`ValidationKeyGetter`选项设置为一个返回用于验证 JWT 的密钥的 Go 函数。在这里，服务器签名被用作验证 JWT 的密钥。

1.  最后，我们在`main()`中使用`jwtmiddleware`处理程序包装了`/employees`路由，这意味着对于每个 URL 模式为`/employees`的请求，我们在提供响应之前检查并验证 JWT。

# 在 Go Web 应用程序中防止跨站点请求伪造

从恶意网站、电子邮件、博客、即时消息或程序攻击受信任的站点，用户当前已经认证，以防止不必要的操作，这是一种常见的做法。我们经常称之为跨站点请求伪造。

在 Go 中实现跨站点请求伪造非常容易，使用 Gorilla CSRF 包，我们将在本教程中介绍。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/csrf`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/csrf
$ go get github.com/gorilla/mux
```

1.  创建`sign-up.html`，其中包含名称和电子邮件输入文本字段，以及一个在提交 HTML 表单时调用的操作，如下所示：

```go
<html>
  <head>
    <title>Sign Up!</title>
  </head>
  <body>
    <form method="POST" action="/post" accept-charset="UTF-8">
      <input type="text" name="name">
      <input type="text" name="email">
      {{ .csrfField }}
      <input type="submit" value="Sign up!">
    </form>
  </body>
</html>
```

1.  创建`prevent-csrf.go`，在其中创建一个`signUp`处理程序，用于呈现注册 HTML 表单，以及一个`post`处理程序，每当提交 HTML 表单并且请求具有有效的 CSRF 令牌时执行，如下所示：

```go
package main
import 
(
  "fmt"
  "html/template"
  "log"
  "net/http"
  "github.com/gorilla/csrf"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8443"
  HTTPS_CERTIFICATE = "domain.crt"
  DOMAIN_PRIVATE_KEY = "domain.key"
)
var AUTH_KEY = []byte("authentication-key")
func signUp(w http.ResponseWriter, r *http.Request) 
{
  parsedTemplate, _ := template.ParseFiles("sign-up.html")
  err := parsedTemplate.Execute
  (
    w, map[string]interface{}
    {
      csrf.TemplateTag: csrf.TemplateField(r),
    }
  )
  if err != nil 
  {
    log.Printf("Error occurred while executing the 
    template : ", err)
    return
  }
}
func post(w http.ResponseWriter, r *http.Request) 
{
  err := r.ParseForm()
  if err != nil 
  {
    log.Print("error occurred while parsing form ", err)
  }
  name := r.FormValue("name")
  fmt.Fprintf(w, "Hi %s", name)
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  muxRouter.HandleFunc("/signup", signUp)
  muxRouter.HandleFunc("/post", post)
  http.ListenAndServeTLS(CONN_HOST+":"+CONN_PORT, 
  HTTPS_CERTIFICATE, DOMAIN_PRIVATE_KEY, csrf.Protect
  (AUTH_KEY)(muxRouter))
}
```

1.  使用以下命令运行程序：

```go
$ go run prevent-csrf.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8443`。

接下来，从命令行执行`POST`请求，如下所示：

```go
$ curl -X POST --data "name=Foo&email=aggarwalarpit.89@gmail.com" https://localhost:8443/post --insecure
```

它将向您显示`Forbidden - CSRF token invalid`消息作为服务器的响应，并禁止您提交 HTML 表单，因为服务器在请求中找不到有效的 CSRF 令牌：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9154e672-74b9-424e-8e39-62b5d6d5a274.png)

因此，要提交表单，首先我们必须注册，通过执行以下命令生成有效的 CSRF 令牌：

```go
$ curl -i -X GET https://localhost:8443/signup --insecure
```

这将给你一个 HTTP `X-CSRF-Token`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6a93d469-bc90-479c-90f4-948a2e81f13f.png)

现在，您必须将其作为 HTTP `X-CSRF-Token`请求头和 HTTP cookie 一起传递，以提交 HTML 表单，如下所示：

```go
$ curl -X POST --data "name=Foo&email=aggarwalarpit.89@gmail.com" -H "X-CSRF-Token: M9gqV7rRcXERvSJVRSYprcMzwtFmjEHKXRm6C8cDC4EjTLIt4OiNzVrHfYNB12nEx280rrKs8fqOgvfcJgQiFA==" --cookie "_gorilla_csrf=MTUyMzQzMjg0OXxJa1ZLVTFsbGJHODFMMHg0VEdWc0wxZENVRVpCWVZGU1l6bHVMMVZKVEVGM01EVjBUakVyUlVoTFdsVTlJZ289fJI5dumuyObaHVp97GN_CiZBCCpnbO0wlIwgSgvHL7-C;" https://localhost:8443/post --insecure

Hi Foo
```

让我们了解一下我们编写的程序：

+   `const (CONN_HOST = "localhost" CONN_PORT = "8443" HTTPS_CERTIFICATE = "domain.crt" DOMAIN_PRIVATE_KEY = "domain.key")`：在这里，我们声明了四个常量 - `CONN_HOST`的值为`localhost`，`CONN_PORT`的值为`8443`，`HTTPS_CERTIFICATE`的值为`domain.crt`或自签名证书，以及`DOMAIN_PRIVATE_KEY`的值为`domain.key`或我们在上一个示例中创建的私钥。

+   `var AUTH_KEY = []byte("authentication-key")`：这是用于生成 CSRF 令牌的身份验证密钥。

+   `signUp`：这是一个处理程序，解析`sign-up.html`并在表单中用 CSRF 令牌替换`{{ .csrfField }}`提供一个`<input>`字段。

+   `post`：这是一个处理程序，解析提交的表单，获取名称输入字段的值，并将其写入 HTTP 响应流。

最后，我们定义了`main()`，在这里我们使用`NewRouter()`处理程序创建了一个`gorilla/mux`路由器实例，对于新路由的尾随斜杠行为设置为`true`，注册了`/signup`路由与`signUp`处理程序以及`/post`路由与`post`处理程序，并调用了`http.ListenAndServeTLS`，将处理程序传递为`csrf.Protect(AUTH_KEY)(muxRouter)`，这样可以确保所有没有有效令牌的`POST`请求都会返回`HTTP 403 Forbidden`。


# 第十一章：将 Go Web 应用程序和 Docker 容器部署到 AWS

在本章中，我们将涵盖以下内容：

+   创建您的第一个 EC2 实例以运行 Go Web 应用程序

+   与您的第一个 EC2 实例交互

+   在您的第一个 EC2 实例上创建、复制和运行 Go Web 应用程序

+   设置 EC2 实例以运行 Docker 容器

+   在 AWS EC2 实例上从 Docker Hub 拉取 Docker 镜像

+   在 EC2 实例上运行您的 Go Docker 容器

# 介绍

如今，每个组织都在向 DevOps 转变，每个人都在谈论持续集成和持续部署，通常称为 CI 和 CD，这已经成为开发人员必须学习的技能。当我们谈论 CI/CD 时，我们在很高的层面上谈论通过持续集成工具（如 Jenkins 和 Bamboo）将容器部署到公共/私有云中。

在本章中，我们将学习如何将简单的 Go Web 应用程序和 Go Docker 容器部署到手动配置的 EC2 实例上。由于我们将使用 Docker 和 AWS，我假设您具有 Docker 和 AWS 的基本知识。

# 创建您的第一个 EC2 实例以运行 Go Web 应用程序

在 AWS 上创建 EC2 实例与获取新机器并安装所需软件以运行 Web 应用程序是一样的。在本教程中，我们将创建一个 EC2 实例，对其进行配置，并运行一个简单的 Go Web 应用程序。

# 准备工作…

要开始在 AWS EC2 实例上创建和部署，首先必须创建和激活 AWS 账户。由于这与本教程无关，我们将不在此处进行操作。

您可以按照以下链接中提供的详细说明来创建和激活 AWS 账户：`https://aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/`

# 操作步骤…

1.  登录到 AWS，转到 EC2 管理控制台，并在“创建实例”部分点击“启动实例”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/0b7216bc-c335-49db-810c-3bf19012c046.png)

1.  选择 Amazon Linux AMI 2017.09.1（HVM），SSD 卷类型，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/5b7fe94d-6d3d-462c-a44c-5138afc0c490.png)

1.  选择 t2.micro 实例类型，然后点击“下一步：配置实例详细信息”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/240f1ef5-9fe6-4ee2-99aa-e759f59e179c.png)

1.  在“配置实例详细信息”部分启用“自动分配公共 IP”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/1eb73f25-5ea4-4ba8-8774-7aaa94d41ba6.png)

1.  不要对添加存储和添加标签部分进行任何更改。

1.  添加 HTTP 和 HTTPS 规则，然后在配置安全组部分点击“Review and Launch”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e235e2dc-d91a-4057-bc40-270e30ba1cd2.png)

1.  从下拉菜单中选择“创建新的密钥对”，为密钥对命名，然后点击“下载密钥对”按钮。保存`my-first-ec2-instance.pem`文件，然后点击“启动实例”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/4e206edf-805a-4d7f-b758-7a238d6efa34.png)

# 工作原理…

点击“启动实例”后，它将在 AWS 上创建并启动一个 Linux 机器，并为实例分配 ID、公共 DNS 和公共 IP，通过这些信息我们可以访问它。

转到 EC2 仪表板的实例部分，您可以看到正在运行的实例，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/dbcb316a-24cd-43ae-aaf6-2f06ad1e15b6.png)

# 与您的第一个 EC2 实例交互

要在 EC2 实例上部署应用程序，我们首先必须登录并安装必要的软件包/软件，这可以通过 SSH 客户端（如 MobaXterm，Putty 等）轻松完成。在本教程中，我们将登录到之前创建的 EC2 实例，并使用 Red Hat 软件包管理器安装 Go。

# 操作步骤…

1.  将私钥文件`my-first-ec2-instance.pem`的权限设置为`400`，这意味着用户/所有者可以读取，但不能写入，也不能执行，而组和其他人都不能读取，不能写入，也不能执行，通过执行`chmod`命令，如下所示：

```go
$ chmod 400 my-first-ec2-instance.pem
```

1.  获取 EC2 实例的公共 DNS，并使用私钥文件作为`ec2-user`连接到它，如下所示执行`ssh`命令：

```go
$ ssh -i my-first-ec2-instance.pem ec2-user@ec2-172-31-34-99.compute-1.amazonaws.com
```

一旦命令成功执行，我们将登录到 EC2 实例，并且输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/43b1473d-ab5b-4cca-a5f5-f30c83772e46.png)

1.  通过执行`sudo`命令从`ec2-user`切换到`root`用户：

```go
[ec2-user@ip-172-31-34-99 ~]$ sudo su
```

1.  使用 Red Hat 软件包管理器`yum`安装`Go`，如下所示：

```go
[root@ip-172-31-34-99 ~]$ yum install -y go
```

# 工作原理…

通过执行`go version`命令验证`ec2-user`是否成功安装了`Go`，如下所示：

```go
[ec2-user@ip-172-31-34-99 ~]$ go version
go version go1.8.4 linux/amd64
```

# 在第一个 EC2 实例上创建、复制和运行 Go Web 应用程序

一旦我们准备好具有所需库的 EC2 实例，我们可以使用安全拷贝协议简单地复制应用程序，然后使用`go run`命令运行它，这将在本教程中介绍。

# 如何做…

1.  创建`http-server.go`，我们将创建一个简单的 HTTP 服务器，它将在`http://ec2-instance-public-dns:80`上呈现 Hello World!，或者从命令行执行`curl -X GET http://ec2-instance-public-dns:80`，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
)
const 
(
  CONN_PORT = "80"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func main() 
{ 
  http.HandleFunc("/", helloWorld)
  err := http.ListenAndServe(":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/1efd7ced-8473-4115-99e1-bfaa0826117b.png)

1.  使用安全拷贝或`scp`命令将`http-server.go`从本地机器目录复制到 EC2 用户主目录(`/home/ec2-user`)，如下所示：

```go
$ scp -i my-first-ec2-instance.pem http-server.go ec2-user@ec2-172-31-34-99.compute-1.amazonaws.com:/home/ec2-user
```

1.  使用私钥文件和公共 DNS 名称登录 EC2 实例，如下所示：

```go
$ ssh -i my-first-ec2-instance.pem ec2-user@ec2-172-31-34-99.compute-1.amazonaws.com
```

1.  在后台运行`http-server.go`，执行无挂起或`nohup`命令，如下所示：

```go
[ec2-user@ip-172-31-34-99 ~] $ nohup go run http-server.go &
```

# 工作原理…

一旦在 EC2 实例上运行程序，HTTP 服务器将在本地监听端口`80`。

接下来，从命令行执行`GET`请求：

```go
$ curl -i -X GET http://ec2-172-31-34-99.compute-1.amazonaws.com:80/
```

这将作为响应给出“Hello World!”，将给出以下输出：

```go
HTTP/1.1 200 OK
Date: Sat, 06 Jan 2018 10:59:38 GMT
Content-Length: 12
Content-Type: text/plain; charset=utf-8

Hello World!
```

# 设置 EC2 实例以运行 Docker 容器

要在 EC2 实例上运行 Docker 容器，我们首先必须设置一个带有 Docker 安装的实例，并将`ec2-user`添加到 Docker 组，以便我们可以以`ec2-user`而不是`root`用户执行 Docker 命令，这将在本教程中介绍。

# 如何做…

1.  通过执行以下命令从`ec2-user`用户切换到`root`用户：

```go
[ec2-user@ip-172-31-34-99 ~]$ sudo su
[root@ip-172-31-34-99 ec2-user]#
```

1.  安装`Docker`并通过执行以下命令更新 EC2 实例：

```go
[root@ip-172-31-34-99 ec2-user] yum install -y docker
[root@ip-172-31-34-99 ec2-user] yum update -y
```

1.  通过执行以下命令在 EC2 实例上启动`Docker`服务：

```go
[root@ip-172-31-34-99 ec2-user] service docker start
```

1.  将`ec2-user`添加到`docker`组，以便您可以在不使用`sudo`的情况下执行 Docker 命令，如下所示：

```go
[root@ip-172-31-34-99 ec2-user] usermod -a -G docker ec2-user
```

1.  通过执行以下命令退出 EC2 实例：

```go
[root@ip-172-31-34-99 ec2-user]# exit
 exit
[ec2-user@ip-172-31-34-99 ~]$ exit
 logout
Connection to ec2-172-31-34-99.compute-1.amazonaws.com closed.
```

1.  通过执行以下命令再次登录以获取新的 Docker 组权限：

```go
$ ssh -i my-first-ec2-instance.pem ec2-user@ec2-172-31-34-99.compute-1.amazonaws.com
```

这将在控制台上给出输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/19744d6c-1cb4-46f0-8538-976756388639.png)

# 工作原理…

登录 EC2 实例并通过执行以下命令验证`ec2-user`是否可以在不使用`sudo`的情况下运行 Docker 命令：

```go
[ec2-user@ip-54-196-74-162 ~]$ docker info
```

这将显示有关 Docker 安装的系统范围信息，如下输出所示：

```go
 Containers: 1
 Running: 1
 Paused: 0
 Stopped: 0
 Images: 1
 ...
 Kernel Version: 4.9.62-21.56.amzn1.x86_64
 Operating System: Amazon Linux AMI 2017.09
 ...
 Live Restore Enabled: false
```

# 从 Docker Hub 在 AWS EC2 实例上拉取 Docker 镜像

要运行 Docker 容器，我们需要有一个 Docker 镜像，可以从`DockerFile`构建，也可以从任何公共或私有 Docker 注册表中拉取，例如 Docker Hub、Quay、Google 容器注册表、AWS 容器注册表等等。

由于我们已经学习了如何从`DockerFile`创建 Docker 镜像并在第九章“使用 Go 和 Docker”中将其推送到 Docker Hub，因此我们不会在本教程中再次构建镜像。相反，我们将在 EC2 实例上从 Docker Hub 拉取预构建的镜像。

在第九章中查看*构建您的第一个 Go Docker 镜像*教程，与 Go 和 Docker 一起工作。

# 如何做…

1.  使用您的凭据从命令行登录到 Docker Hub，执行以下命令：

```go
$ docker login --username arpitaggarwal --password XXXXX
 Login Succeeded
```

1.  执行`docker pull`命令从 Docker Hub 拉取`arpitaggarwal/golang-image`，如下所示：

```go
$ docker pull arpitaggarwal/golang-image
```

这将导致以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/8883ec18-7b18-4cac-bfc2-f24ec5718ca9.png)

# 工作原理…

登录到 EC2 实例并通过执行以下命令验证是否成功从 Docker Hub 拉取了`arpitaggarwal/golang-image`：

```go
$ docker images
```

这将列出所有顶级镜像、它们的存储库、标签和大小，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/eb1282fa-47ba-4e7b-b1b2-db37c328f248.png)

# 在 EC2 实例上运行您的 Go Docker 容器

一旦我们在 EC2 实例上安装了 Docker 镜像和 Docker，那么您可以通过执行`docker run`命令来简单地运行 Docker 容器，我们将在本教程中介绍这一点。

# 如何做…

登录到 EC2 实例并执行`docker run`命令，从`arpitaggarwal/golang-image`创建和运行一个 Docker 容器，使用`--name`标志将容器名称分配为`golang-container`，如下所示：

```go
$ docker run -d -p 80:8080 --name golang-container -it arpitaggarwal/golang-image
 8a9256fcbffc505ad9406f5a8b42ae33ab3951fffb791502cfe3ada42aff781e
```

`docker run`命令中指定的`-d`标志以守护进程模式启动容器，末尾的哈希字符串表示`golang-container`的 ID。

`docker run`命令中指定的`-p`标志将容器的端口发布到主机。由于我们在 Docker 容器内的端口`8080`上运行 HTTP 服务器，并且我们为 E2C 实例的入站流量打开了端口`80`，因此我们将其映射为`80:8080`。

# 工作原理…

登录到 EC2 实例并通过执行以下命令验证 Docker 容器是否已创建并成功运行：

```go
$ docker ps
```

一旦前面的命令成功执行，它将给我们运行中的 Docker 容器的详细信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ccb92238-edb4-46df-8319-951abd427ea1.png)

获取 EC2 实例的公共 DNS，并从命令行执行`GET`请求：

```go
$ curl -i -X GET http://ec2-172-31-34-99.compute-1.amazonaws.com/
```

这将作为响应给出“Hello World!”，如下输出所示：

```go
 HTTP/1.1 200 OK
 Date: Sat, 06 Jan 2018 12:49:28 GMT
 Content-Length: 12
 Content-Type: text/plain; charset=utf-8
 Hello World!
```
