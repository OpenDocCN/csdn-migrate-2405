# Docker 学习手册第二版（三）

> 原文：[`zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8`](https://zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Docker 来加速自动化

在上一章中，我们介绍了通常用于允许开发人员在容器中演变、修改、调试和测试其代码的技术。我们还学习了如何对应用程序进行工具化，以便它们生成日志信息，这些信息可以帮助我们对在生产环境中运行的应用程序或应用服务的故障或异常行为进行根本原因分析。

在本章中，我们将展示如何使用工具执行管理任务，而无需在主机计算机上安装这些工具。我们还将说明托管和运行测试脚本或代码的容器，用于测试和验证在容器中运行的应用服务。最后，我们将指导读者构建一个基于 Docker 的简单 CI/CD 流水线。

这是本章中我们将涉及的所有主题的快速概述：

+   在容器中执行简单的管理员任务

+   使用测试容器

+   使用 Docker 来驱动 CI/CD 流水线

完成本章后，您将能够执行以下操作：

+   在容器中运行主机上不可用的工具

+   使用容器来运行测试脚本或代码来对应用服务进行测试

+   使用 Docker 构建一个简单的 CI/CD 流水线

# 技术要求

在本节中，如果您想跟着代码进行操作，您需要在 macOS 或 Windows 机器上安装 Docker for Desktop 和一个代码编辑器，最好是 Visual Studio Code。该示例也适用于安装了 Docker 和 VS Code 的 Linux 机器。

# 在容器中执行简单的管理员任务

假设您需要从文件中删除所有前导空格，并且您找到了以下方便的 Perl 脚本来做到这一点：

```
$ cat sample.txt | perl -lpe 's/^\s*//'
```

事实证明，您的工作机器上没有安装 Perl。你能做什么？在机器上安装 Perl 吗？嗯，这当然是一个选择，这也是大多数开发人员或系统管理员所做的。但等一下，您已经在机器上安装了 Docker。我们不能使用 Docker 来规避安装 Perl 的需要吗？是的，我们可以。这就是我们要做的：

1.  创建一个名为`ch07/simple-task`的文件夹，并导航到它：

```
$ mkdir -p ~/fod/ch07/simple-task && cd ~/fod/ch07/simple-task
```

1.  从这个文件夹中打开 VS Code：

```
$ code .
```

1.  在这个文件夹中，创建一个名为`sample.txt`的文件，内容如下：

```
1234567890
  This is some text
   another line of text
 more text
     final line
```

请注意每行开头的空格。保存文件。

1.  现在，我们可以运行一个安装了 Perl 的容器。幸运的是，Docker Hub 上有一个官方的 Perl 镜像。我们将使用镜像的 slim 版本：

```
$ docker container run --rm -it \
 -v $(pwd):/usr/src/app \
 -w /usr/src/app \
 perl:slim sh -c "cat sample.txt | perl -lpe 's/^\s*//'"
```

上面的命令以交互方式运行了一个 Perl 容器（`perl:slim`），将当前文件夹的内容映射到容器的`/usr/src/app`文件夹，并将容器内的工作文件夹设置为`/usr/src/app`。在容器内运行的命令是`sh -c "cat sample.txt | perl -lpe 's/^\s*//'"`，基本上是生成一个 Bourne shell 并执行我们想要的 Perl 命令。

上面的命令生成的输出应该如下所示：

```
1234567890
This is some text
another line of text
more text
final line
```

1.  无需在我们的机器上安装 Perl，我们就能实现我们的目标。

如果这还不能说服你，因为如果你在 macOS 上，你已经安装了 Perl，那么请考虑一下，你想要运行一个名为`your-old-perl-script.pl`的 Perl 脚本，它是旧的，不兼容你系统上已安装的最新版本的 Perl。你会尝试在你的机器上安装多个版本的 Perl 并可能破坏一些东西吗？不，你只需运行一个与你的脚本兼容的（旧）Perl 版本的容器，就像这个例子：

```
$ docker container run -it --rm \
-v $(pwd):/usr/src/app \
 -w /usr/src/app \
 perl:<old-version> perl your-old-perl-script.pl
```

这里，`<old-version>`对应于你需要运行你的脚本的 Perl 版本的标签。好处是，脚本运行后，容器将从你的系统中删除，不会留下任何痕迹，因为我们在`docker container run`命令中使用了`--rm`标志。

许多人使用快速而简单的 Python 脚本或迷你应用程序来自动化一些无法用 Bash 等编码的任务。现在，如果 Python 脚本是用 Python 3.7 编写的，而你只安装了 Python 2.7，或者根本没有在你的机器上安装任何版本，那么最简单的解决方案就是在容器内执行脚本。让我们假设一个简单的例子，Python 脚本统计给定文件中的行数、单词数和字母数，并将结果输出到控制台：

1.  在`ch07/simple-task`文件夹中添加一个`stats.py`文件，并添加以下内容：

```
import sys

fname = sys.argv[1]
lines = 0
words = 0
letters = 0

for line in open(fname):
    lines += 1
    letters += len(line)

    pos = 'out'
    for letter in line:
        if letter != ' ' and pos == 'out':
            words += 1
            pos = 'in'
        elif letter == ' ':
            pos = 'out'

print("Lines:", lines)
print("Words:", words)
print("Letters:", letters)
```

1.  保存文件后，您可以使用以下命令运行它：

```
$ docker container run --rm -it \
 -v $(pwd):/usr/src/app \
 -w /usr/src/app \
 python:3.7.4-alpine python stats.py sample.txt
```

请注意，在这个例子中，我们重用了之前的`sample.txt`文件。在我的情况下，输出如下：

```
Lines: 5
Words: 13
Letters: 81
```

这种方法的美妙之处在于，这个 Python 脚本现在可以在任何安装了任何操作系统的计算机上运行，只要这台机器是一个 Docker 主机，因此可以运行容器。

# 使用测试容器

对于每个严肃的软件项目，强烈建议进行大量的测试。有各种测试类别，如单元测试、集成测试、压力和负载测试以及端到端测试。我尝试在以下截图中可视化不同的类别：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f5d017fc-0214-43d4-9c0a-a701c9731c84.png)

应用程序测试的类别

单元测试断言整体应用程序或应用程序服务中的单个、孤立部分的正确性和质量。集成测试确保紧密相关的部分按预期工作在一起。压力和负载测试通常将应用程序或服务作为整体，并断言在各种边缘情况下的正确行为，例如通过服务处理的多个并发请求的高负载，或通过向服务发送大量数据来淹没服务。最后，端到端测试模拟真实用户与应用程序或应用程序服务的工作。用户通常会执行的任务被自动化。

受测试的代码或组件通常被称为**系统测试对象**（**SUT**）。

单元测试在其性质上与实际代码或 SUT 紧密耦合。因此，这些测试必须在与受测试代码相同的上下文中运行。因此，测试代码与 SUT 位于同一容器中。SUT 的所有外部依赖项都是模拟的或存根的。

另一方面，集成测试、压力和负载测试以及端到端测试作用于系统测试对象的公共接口，因此最常见的是在单独的容器中运行测试代码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3e2a02c0-87e7-412b-b912-4060b337280f.png)

使用容器的集成测试

在上图中，我们可以看到**测试代码**在其自己的**测试容器**中运行。**测试代码**访问也在专用容器中运行的**API**组件的公共接口。**API**组件具有外部依赖，如**其他** **服务**和**数据库**，它们分别在其专用容器中运行。在这种情况下，**API**，**其他** **服务**和**数据库**的整个集合是我们的系统测试对象，或 SUT。

压力和负载测试会是什么样子？想象一种情况，我们有一个 Kafka Streams 应用程序需要进行测试。以下图表给出了我们可以从高层次上测试的具体内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7b928ee2-e7df-4a26-9c6c-1504683653ee.png)

压力和负载测试 Kafka Streams 应用程序

简而言之，**Kafka Streams 应用程序**从存储在 Apache Kafka(R)中的一个或多个主题中消费数据。该应用程序过滤、转换或聚合数据。结果数据被写回 Kafka 中的一个或多个主题。通常，在使用 Kafka 时，我们处理实时数据流入 Kafka。现在测试可以模拟以下情况：

+   大量记录的大型主题

+   数据以非常高的频率流入 Kafka

+   应用程序在测试下分组的数据，其中有很多不同的键，每个键的基数很低

+   按时间窗口聚合的数据，窗口的大小很小，例如，每个窗口只有几秒钟

端到端测试通过使用诸如 Selenium Web Driver 之类的工具自动化与应用程序交互的用户，该工具提供了开发者手段来自动执行给定网页上的操作，例如填写表单字段或点击按钮。

# Node.js 应用程序的集成测试

现在让我们来看一个在 Node.js 中实现的样本集成测试。这是我们将要研究的设置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b2695574-24aa-48e3-9760-f0ab1e9e8247.png)

Express JS 应用程序的集成测试

以下是创建这样一个集成测试的步骤：

1.  让我们首先准备我们的项目文件夹结构。我们创建项目根目录并导航到它：

```
$ mkdir ~/fod/ch07/integration-test-node && \
    cd ~/fod/ch07/integration-test-node
```

1.  在这个文件夹中，我们创建三个子文件夹，`tests`，`api`和`database`：

```
$ mkdir tests api database
```

1.  现在，我们从项目根目录打开 VS Code：

```
$ code .
```

1.  在`database`文件夹中，添加一个`init-script.sql`文件，内容如下：

```
CREATE TABLE hobbies(
 hobby_id serial PRIMARY KEY,
 hobby VARCHAR (255) UNIQUE NOT NULL
);

insert into hobbies(hobby) values('swimming');
insert into hobbies(hobby) values('diving');
insert into hobbies(hobby) values('jogging');
insert into hobbies(hobby) values('dancing');
insert into hobbies(hobby) values('cooking');
```

上述脚本将在我们的 Postgres 数据库中创建一个`hobbies`表，并填充一些种子数据。保存文件。

1.  现在我们可以启动数据库。当然，我们将使用官方的 Docker 镜像来运行 Postgres 数据库。但首先，我们将创建一个 Docker 卷，数据库将在其中存储其文件。我们将称该卷为`pg-data`：

```
$ docker volume create pg-data
```

1.  现在，是时候运行数据库容器了。从项目根目录（`integration-test-node`）中运行以下命令：

```
$ docker container run -d \
 --name postgres \
 -p 5432:5432 \
 -v $(pwd)/database:/docker-entrypoint-initdb.d \
 -v pg-data:/var/lib/postgresql/data \
 -e POSTGRES_USER=dbuser \
 -e POSTGRES_DB=sample-db \
 postgres:11.5-alpine
```

请注意，运行上述命令的文件夹很重要，因为我们在数据库初始化脚本`init-script.sql`中使用了卷挂载。还要注意，我们正在使用环境变量来定义 Postgres 中数据库的名称和用户，并且我们正在将 Postgres 的端口`5432`映射到主机上的等效端口。

1.  在启动数据库容器后，通过检索其日志来双重检查它是否按预期运行：

```
$ docker container logs postgres
```

你应该看到类似于这样的东西：

```
...
server started
CREATE DATABASE

/usr/local/bin/docker-entrypoint.sh: running /docker-entrypoint-initdb.d/init-db.sql
CREATE TABLE
INSERT 0 1
INSERT 0 1
INSERT 0 1
INSERT 0 1
INSERT 0 1

...

PostgreSQL init process complete; ready for start up.

2019-09-07 17:22:30.056 UTC [1] LOG: listening on IPv4 address "0.0.0.0", port 5432
...
```

注意，我们已经缩短了输出以便更好地阅读。前面输出的重要部分是前几行，我们可以看到数据库已经接受了我们的初始化脚本，创建了`hobbies`表并用五条记录进行了填充。最后一行也很重要，告诉我们数据库已经准备好工作。当解决问题时，容器日志总是你的第一站！

有了这个，我们的 SUT 的第一部分就准备好了。让我们继续下一个部分，也就是我们在 Express JS 中实现的 API：

1.  在终端窗口中，导航到`api`文件夹：

```
$ cd ~/fod/ch07/integration-test-node/api
```

1.  然后，运行`npm init`来初始化 API 项目。只接受所有默认值：

```
$ npm init
```

生成的`package.json`文件应该是这样的：

```
{
  "name": "api",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}
```

1.  修改上述文件的`scripts`节点，使其包含一个启动命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6c851736-d5d7-4656-b565-8666cd016cf8.png) 在 package.json 文件中添加一个启动脚本

1.  然后我们需要安装 Express JS，可以使用以下命令来完成：

```
$ npm install express --save
```

这将安装库及其所有依赖项，并在我们的`package.json`文件中添加一个类似于这样的依赖项节点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6d01c027-f5be-4de4-be22-57af5ff422e0.png)

将 Express JS 添加为 API 的依赖项

1.  在`api`文件夹中，创建一个`server.js`文件，并添加以下代码片段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/55518a75-754f-4ef7-98bf-e93eb73332a7.png)

简单的 Express JS API

这是一个简单的 Express JS API，只实现了`/`端点。它作为我们探索集成测试的起点。请注意，API 将在端口`3000`上监听，在容器内的所有端点(`0.0.0.0`)。

1.  现在我们可以使用`npm start`启动 API，然后使用`curl`测试主页端点，例如：

```
$ curl localhost:3000
Sample API
```

经过所有这些步骤，我们已经准备好搭建测试环境了。

1.  我们将使用`jasmine`来编写我们的测试。导航到`tests`文件夹并运行`npm init`来初始化测试项目：

```
$ cd ~/fod/ch07/integration-test-node/tests && \
    npm init
```

接受所有默认值。

1.  接下来，将`jasmine`添加到项目中：

```
$ npm install --save-dev jasmine
```

1.  然后为这个项目初始化`jasmine`：

```
$ node node_modules/jasmine/bin/jasmine init
```

1.  我们还需要更改我们的`package.json`文件，使得脚本块看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f06ce569-69d4-47ab-9346-700ec2fa8eaf.png)

为我们的集成测试添加一个测试脚本

1.  我们不能随时通过在`tests`文件夹中执行`npm test`来运行测试。第一次运行时，我们会收到错误提示，因为我们还没有添加任何测试：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/fa888ef5-069b-4297-a38e-2af3a671686c.png)

第一次运行失败，因为没有找到测试

1.  现在在项目的`spec/support`子文件夹中，让我们创建一个`jasmine.json`文件。这将包含`jasmine`测试框架的配置设置。将以下代码片段添加到此文件并保存：

```
{
  "spec_dir": "spec",
  "spec_files": [
    "**/*[sS]pec.js"
  ],
  "stopSpecOnExpectationFailure": false,
  "random": false
}
```

1.  由于我们将要编写集成测试，我们希望通过其公共接口访问 SUT，而在我们的情况下，这是一个 RESTful API。因此，我们需要一个客户端库来允许我们这样做。我的选择是 Requests 库。让我们将其添加到我们的项目中：

```
$ npm install request --save-dev
```

1.  在项目的`spec`子文件夹中添加一个`api-spec.js`文件。它将包含我们的测试函数。让我们从第一个开始：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6f2f86bd-53a7-4447-ac3d-171f7955d2de.png)

API 的示例测试套件

我们正在使用`request`库来对我们的 API 进行 RESTful 调用（第 1 行）。然后，在第 3 行，我们定义了 API 正在监听的基本 URL。请注意，我们使用的代码允许我们使用环境变量`BASE_URL`来覆盖默认的`http://localhost:3000`。第 5 行定义了我们的测试套件，第 6 行有一个`GET /`的测试。然后我们断言两个结果，即`GET`调用`/`的状态码为`200`（OK），并且响应主体中返回的文本等于`Sample API`。

1.  如果我们现在运行测试，将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/11d9290c-3d06-4c15-84ac-ae664f87ad9b.png)

成功运行基于 Jasmine 的集成测试

我们有两个规范——测试的另一个词——正在运行；所有这些都是成功的，因为我们没有报告任何失败。

1.  在继续之前，请停止 API 并使用`docker container rm -f postgres`删除 Postgres 容器。

到目前为止一切顺利，但现在让我们把容器引入讨论。这是我们最感兴趣的部分，不是吗？我们很兴奋地运行所有东西，包括容器中的测试代码。如果你还记得，我们将处理三个容器，数据库、API 和包含测试代码的容器。对于数据库，我们只是使用标准的 Postgres Docker 镜像，但是对于 API 和测试，我们将创建自己的镜像：

1.  让我们从 API 开始。在`api`文件夹中，添加一个`Dockerfile`文件，内容如下：

```
FROM node:alpine
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD npm start
```

这只是创建一个基于 Node.js 的应用程序的容器镜像的非常标准的方法。这里没有什么特别的。

1.  将`tests`文件夹中添加一个具有以下内容的 Dockerfile：

```
FROM node:alpine
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install
COPY . .
CMD npm test
```

1.  现在，我们准备按正确的顺序运行所有三个容器。为了简化这个任务，让我们创建一个 shell 脚本来做到这一点。将`test.sh`文件添加到`integration-test-node`文件夹中，我们的项目根文件夹。将以下内容添加到这个文件中并保存：

```
docker image build -t api-node api
docker image build -t tests-node tests

docker network create test-net

docker container run --rm -d \
 --name postgres \
 --net test-net \
 -v $(pwd)/database:/docker-entrypoint-initdb.d \
 -v pg-data:/var/lib/postgresql/data \
 -e POSTGRES_USER=dbuser \
 -e POSTGRES_DB=sample-db \
 postgres:11.5-alpine

docker container run --rm -d \
 --name api \
 --net test-net \
api-node

echo "Sleeping for 5 sec..."
sleep 5

docker container run --rm -it \
 --name tests \
 --net test-net \
 -e BASE_URL="http://api:3000" \
 tests-node
```

在脚本的前两行，我们确保 API 和测试的两个容器镜像都使用最新的代码构建。然后，我们创建一个名为`test-net`的 Docker 网络，我们将在这个网络上运行所有三个容器。暂时不用担心这个的细节，因为我们将在第十章中详细解释网络，*单主机网络*。暂且可以说，如果所有容器都在同一个网络上运行，那么在这些容器内运行的应用程序可以像在主机上本地运行一样看到彼此，并且它们可以通过名称相互调用。

下一个命令启动数据库容器，然后是启动 API 的命令。然后，我们暂停几秒钟，让数据库和 API 完全启动和初始化，然后我们启动第三个和最后一个容器，即测试容器。

1.  使用以下命令将此文件设置为可执行文件：

```
$ chmod +x ./test.sh 
```

1.  现在你可以运行它：

```
$ ./test.sh
```

如果一切按预期运行，你应该看到类似以下内容的东西（为了便于阅读而缩短）：

```
...
Successfully built 44e0900aaae2
Successfully tagged tests-node:latest
b4f233c3578898ae851dc6facaa310b014ec86f4507afd0a5afb10027f10c79d
728eb5a573d2c3c1f3a44154e172ed9565606af8e7653afb560ee7e99275ecf6
0474ea5e0afbcc4d9cd966de17e991a6e9a3cec85c53a934545c9352abf87bc6
Sleeping for 10 sec...

> tests@1.0.0 test /usr/src/app
> jasmine

Started
..

2 specs, 0 failures
Finished in 0.072 seconds
```

1.  我们还可以创建一个在测试后进行清理的脚本。为此，添加一个名为`cleanup.sh`的文件，并以与`test.sh`脚本相同的方式将其设置为可执行文件。将以下代码片段添加到这个文件中：

```
docker container rm -f postgres api
docker network rm test-net
docker volume rm pg-data
```

第一行删除`postgres`和`api`容器。第 2 行删除我们用于第三个容器的网络，最后，第 3 行删除 Postgres 使用的卷。在每次测试运行后，使用`./cleanup.sh`执行此文件。

现在你可以开始向你的 API 组件添加更多的代码和更多的集成测试。每次你想要测试新的或修改过的代码，只需运行`test.sh`脚本。

挑战：你如何进一步优化这个过程，以便需要更少的手动步骤？

使用我们在第六章中学到的内容，*在容器中运行代码调试*。

# Testcontainers 项目

如果您是 Java 开发人员，那么有一个名为 Testcontainers 的不错的项目（[`testcontainers.org`](https://testcontainers.org)）。用他们自己的话来说，该项目可以总结如下：

"Testcontainers 是一个支持 JUnit 测试的 Java 库，提供常见数据库、Selenium Web 浏览器或任何可以在 Docker 容器中运行的轻量级一次性实例。"要尝试 Testcontainer，请跟随以下步骤：

1.  首先创建一个`testcontainer-node`文件夹并导航到它：

```
$ mkdir ~/fod/ch07/testcontainer-node && cd ~/fod/ch07/testcontainer-node
```

1.  接下来，使用`code .`从该文件夹中打开 VS Code。在同一文件夹中创建三个子文件夹，`database`，`api`和`tests`。向`api`文件夹中添加一个`package.json`文件，并添加以下内容：

！[](assets/7eb83bfd-88b9-4891-9349-2098351469b2.png)

API 的 package.json 内容

1.  向`api`文件夹添加一个`server.js`文件，并添加以下内容：

！[](assets/e1dd1426-e8cf-48fb-8cc7-f79f5b4f6c95.png)

使用 pg 库访问 Postgres 的示例 API

在这里，我们创建一个在端口`3000`监听的 Express JS 应用程序。该应用程序使用`pg`库，这是一个用于 Postgres 的客户端库，用于访问我们的数据库。在第`8`到`15`行，我们正在定义一个连接池对象，它将允许我们连接到 Postgres 并检索或写入数据。在第`21`到`24`行，我们正在定义一个`GET`方法，它位于`/hobbies`端点上，该端点通过 SQL 查询`SELECT hobby FROM hobbies`从数据库中检索到的爱好列表。

1.  现在在同一文件夹中添加一个 Dockerfile，并添加以下内容：

！[](assets/b63beff8-619f-435f-801c-7fe06c7a1333.png)

API 的 Dockerfile

这与我们在上一个示例中使用的定义完全相同。有了这个，API 已经准备好使用了。现在让我们继续进行使用`testcontainer`库来简化基于容器的测试的测试。

1.  在您的终端中，导航到我们之前创建的`tests`文件夹，并使用`npm init`将其初始化为一个 Node.js 项目。接受所有默认值。接下来，使用`npm`安装`request`库和`testcontainers`库：

```
$ npm install request --save-dev
$ npm install testcontainers --save-dev
```

其结果是一个`package.json`文件，应该看起来类似于这样：

！[](assets/d2880fcf-f231-45d2-878b-3b4b2289f79f.png)

测试项目的 package.json 文件

1.  现在，在`tests`文件夹中，创建一个`tests.js`文件，并添加以下代码片段：

```
const request = require("request");
const path = require('path');
const dns = require('dns');
const os = require('os');
const { GenericContainer } = require("testcontainers");

(async () => {
 // TODO
})();
```

注意我们正在请求一个新对象，比如`request`对象，它将帮助我们访问示例 API 组件的 RESTful 接口。我们还从`testcontainers`库请求`GenericContainer`对象，它将允许我们构建和运行任何容器。

然后，我们定义一个异步自调用函数，它将作为我们设置和测试代码的包装器。它必须是一个异步函数，因为在其中，我们将等待其他异步函数，比如从`testcontainers`库使用的各种方法。

1.  作为非常重要的一步，我们想使用`testcontainers`库来创建一个带有必要种子数据的 Postgres 容器。让我们在`//TODO`之后添加这段代码片段：

```
const localPath = path.resolve(__dirname, "../database");
const dbContainer = await new GenericContainer("postgres")
 .withName("postgres")
 .withExposedPorts(5432)
 .withEnv("POSTGRES_USER", "dbuser")
 .withEnv("POSTGRES_DB", "sample-db")
 .withBindMount(localPath, "/docker-entrypoint-initdb.d")
 .withTmpFs({ "/temp_pgdata": "rw,noexec,nosuid,size=65536k" })
 .start();
```

前面的代码片段与 Docker 的`run`命令有一些相似之处。这并非偶然，因为我们正在指示`testcontainers`库做的正是这样，为我们运行一个 PostgreSQL 实例。

1.  接下来，我们需要找出暴露端口`5432`映射到哪个主机端口。我们可以用以下逻辑来做到这一点：

```
const dbPort = dbContainer.getMappedPort(5432);
```

我们将需要这些信息，因为 API 组件将需要通过这个端口访问 Postgres。

1.  我们还需要知道主机在容器内可达的 IP 地址是哪个——注意，本地主机在容器内不起作用，因为这将映射到容器自己网络堆栈的环回适配器。我们可以这样获取主机 IP 地址：

```
const myIP4 = await lookupPromise();
```

`lookupPromise`函数是一个包装函数，使正常的异步`dns.lookup`函数返回一个 promise，这样我们就可以`await`它。这是它的定义：

```
async function lookupPromise(){
 return new Promise((resolve, reject) => {
 dns.lookup(os.hostname(), (err, address, family) => {
 if(err) throw reject(err);
 resolve(address);
 });
 });
};
```

1.  现在，有了这些信息，我们准备指示`testcontainer`库首先为 API 构建容器镜像，然后从该镜像运行容器。让我们从构建开始：

```
const buildContext = path.resolve(__dirname, "../api");
const apiContainer = await GenericContainer
 .fromDockerfile(buildContext)
 .build();
```

注意这个命令如何使用我们在`api`子文件夹中定义的 Dockerfile。

1.  一旦我们有了引用新镜像的`apiContainer`变量，我们就可以使用它来从中运行一个容器：

```
const startedApiContainer = await apiContainer
 .withName("api")
 .withExposedPorts(3000)
 .withEnv("DB_HOST", myIP4)
 .withEnv("DB_PORT", dbPort)
 .start();
```

1.  再一次，我们需要找出 API 组件的暴露端口`3000`映射到哪个主机端口。`testcontainer`库使这变得轻而易举：

```
const apiPort = startedApiContainer.getMappedPort(3000);
```

1.  通过这最后一行，我们已经完成了测试设置代码，现在终于可以开始实现一些测试了。我们首先定义要访问的 API 组件的基本 URL。然后，我们使用`request`库向`/hobbies`端点发出 HTTP GET 请求：

```
const base_url = `http://localhost:${apiPort}`
request.get(base_url + "/hobbies", (error, response, body) => {
 //Test code here...
})
```

1.  现在让我们在`//Test code here...`注释之后实现一些断言：

```
console.log("> expecting status code 200");
if(response.statusCode != 200){
 logError(`Unexpected status code ${response.statusCode}`);
}
```

首先，当运行测试时，我们将我们的期望记录到控制台作为反馈。然后，我们断言返回的状态码是`200`，如果不是，我们会记录一个错误。`logError`辅助函数只是将给定的消息以红色写入控制台，并在前面加上`***ERR`。这是这个函数的定义：

```
function logError(message){
 console.log('\x1b[31m%s\x1b[0m', `***ERR: ${message}`);
}
```

1.  让我们再添加两个断言：

```
const hobbies = JSON.parse(body);
console.log("> expecting length of hobbies == 5");
if(hobbies.length != 5){
 logError(`${hobbies.length} != 5`);
}
console.log("> expecting first hobby == swimming");
if(hobbies[0].hobby != "swimming"){
 logError(`${hobbies[0].hobby} != swimming`);
}
```

我把确切的断言做什么留给你，亲爱的读者，去找出来。

1.  在断言结束时，我们必须进行清理，以便为下一次运行做好准备：

```
await startedApiContainer.stop()
await dbContainer.stop();
```

我们要做的就是停止 API 和数据库容器。这将自动将它们从内存中删除。

1.  现在我们可以使用以下命令在`tests`子文件夹中运行这个测试套件：

```
$ node tests.js 
```

在我的情况下，输出看起来是这样的（注意，我在代码中添加了一些`console.log`语句，以更容易地跟踪到底在某个时间点发生了什么）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ba68b227-ae11-4625-9b29-b37915043c4f.png)

运行基于 testcontainer 的集成测试

完整的代码在您从 GitHub 克隆的示例代码存储库中提供。如果您在运行测试时遇到问题，请将您的实现与给定的示例解决方案进行比较。

现在我们已经很好地了解了如何使用容器来运行我们的集成测试，我们将继续进行另一个非常流行的基于容器的自动化用例，即构建持续集成和持续部署或交付（CI/CD）流水线。

# 使用 Docker 来支持 CI/CD 流水线

本节的目标是构建一个类似于以下的 CI/CD 流水线：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6e8eff3d-22ee-4c18-9b2b-30f7745a3e91.png)

使用 Jenkins 的简单 CI/CD 流水线

我们将使用 Jenkins（[`jenkins.io`](https://jenkins.io)）作为我们的自动化服务器。其他自动化服务器，如 TeamCity（[`www.jetbrains.com/teamcity`](https://www.jetbrains.com/teamcity)）同样有效。在使用 Jenkins 时，中心文档是`Jenkinsfile`，其中包含了具有多个阶段的流水线的定义。

一个简单的`Jenkinsfile`与`Build`、`Test`、`Deploy to Staging`和`Deploy to Production`阶段可能是这样的：

```
pipeline {
    agent any
    options {
        skipStagesAfterUnstable()
    }
    stages {
        stage('Build') {
            steps {
                echo 'Building'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing'
            }
        }
        stage('Deploy to Staging') {
            steps {
                echo 'Deploying to Staging'
            }
        }
        stage('Deploy to Production') {
            steps {
                echo 'Deploying to Production'
            }
        }
    }
}
```

当然，前面的流水线只是在每个阶段输出一条消息，什么也不做。尽管如此，它作为一个起点是有用的，可以从中构建我们的流水线。

1.  创建一个名为`jenkins-pipeline`的项目文件夹并导航到它：

```
$ mkdir ~/fod/ch07/jenkins-pipeline && cd ~/fod/ch07/jenkins-pipeline
```

1.  现在，让我们在 Docker 容器中运行 Jenkins。使用以下命令来执行：

```
$ docker run --rm -d \
 --name jenkins \
 -u root \
-p 8080:8080 \
-v jenkins-data:/var/jenkins_home \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -v "$HOME":/home \
 jenkinsci/blueocean
```

请注意，我们正在作为容器内的`root`用户运行，并且我们正在将 Docker 套接字挂载到容器中（`-v /var/run/docker.sock:/var/run/docker.sock`），以便 Jenkins 可以从容器内访问 Docker。Jenkins 生成和使用的数据将存储在 Docker 卷`jenkins-data`中。

1.  我们可以使用以下命令自动由 Jenkins 生成的初始管理员密码：

```
$ docker container exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

在我的情况下，这将输出`7f449293de5443a2bbcb0918c8558689`。保存这个密码，因为您将在下一步中使用它。

1.  在浏览器中，导航至`http://localhost:8080`以访问 Jenkins 的图形界面。

1.  使用前面的命令检索的管理员密码解锁 Jenkins。

1.  接下来，选择安装建议的插件，让 Jenkins 自动安装最有用的插件。插件包括 GitHub 集成，电子邮件扩展，Maven 和 Gradle 集成等等。

1.  一旦插件安装完成，创建您的第一个管理员帐户。在要求重新启动 Jenkins 时，这样做。

1.  一旦您配置了 Jenkins 服务器，首先创建一个新项目；您可能需要在主菜单中点击**新项目**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f64e3315-eaf5-43c9-8ffc-d8fd63e0cd4e.png)

在 Jenkins 中添加一个新项目

1.  给项目命名为`sample-pipeline`，选择`Pipeline`类型，然后点击确定。

1.  在配置视图中，选择 Pipeline 标签，并将前面的管道定义添加到脚本文本框中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b96d4516-0374-453f-b7a2-b419e6815a24.png)

在我们的名为 sample-pipeline 的 Jenkins 项目中定义管道

1.  点击保存，然后在 Jenkins 的主菜单中选择立即构建。过一会儿，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/009185ff-8c65-4336-82f3-1fb4673adc22.png)

在 Jenkins 中运行我们的示例管道

1.  现在我们已经准备好了 Jenkins，我们可以开始集成我们的示例应用程序。让我们从构建步骤开始。首先，我们将`jenkins-pipeline`项目文件夹初始化为 Git 项目：

```
$ cd ~/fod/ch07/jenkins-pipeline && git init
```

1.  向此文件夹添加一个`package.json`文件，内容如下：

```
{
  "name": "jenkins-pipeline",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "test": "jasmine"
  },
  "dependencies": {
    "express": "⁴.17.1"
  },
  "devDependencies": {
    "jasmine": "³.4.0"
  }
}
```

在这个文件中没有什么特别的，除了通常的外部依赖列表，这种情况下是`express`和`jasmine`。还要注意我们为`npm`定义的两个脚本`start`和`test`。

1.  向项目添加一个`hobbies.js`文件，该文件实现了作为 JavaScript 模块`hobbies`调用的爱好检索逻辑：

```
const hobbies = ["jogging","cooking","diving","swimming","reading"];

exports.getHobbies = () => {
    return hobbies;
}

exports.getHobby = id => {
    if(id<1 || id > hobbies.length)
        return null;
    return hobbies[id-1];
}
```

这段代码显然是通过提供存储在`hobbies`数组中的预先准备好的数据来模拟数据库。我们之所以这样做是为了简单起见。

1.  接下来，在文件夹中添加一个`server.js`文件，该文件定义了一个具有三个端点`GET /`、`GET /hobbies`和`GET /hobbies/:id`的 RESTful API。该代码使用`hobbies`模块中定义的逻辑来检索数据：

```
const hobbies = require('./hobbies');
const express = require('express');
const app = express();

app.listen(3000, '0.0.0.0', () => {
    console.log('Application listening at 0.0.0.0:3000');
})

app.get('/', (req, res) => {
    res.send('Sample API');
})

app.get('/hobbies', async (req, res) => {
    res.send(hobbies.getHobbies());
})

app.get('/hobbies/:id', async (req, res) => {
    const id = req.params.id;
    const hobby = hobbies.getHobby(id);
    if(!hobby){
        res.status(404).send("Hobby not found");
        return;
    }
    res.send();
})
```

1.  现在我们需要定义一些单元测试。在项目中创建一个`spec`子文件夹，并向其中添加`hobbies-spec.js`文件，其中包含以下代码，用于测试`hobbies`模块：

```
const hobbies = require('../hobbies');
describe("API unit test suite", () => {
    describe("getHobbies", () => {
        const list = hobbies.getHobbies();
        it("returns 5 hobbies", () => {
            expect(list.length).toEqual(5);
        });
        it("returns 'jogging' as first hobby", () => {
            expect(list[0]).toBe("jogging");
        });
    })
})
```

1.  最后一步是添加一个`support/jasmine.json`文件来配置我们的测试框架 Jasmine。添加以下代码片段：

```
{
    "spec_dir": "spec",
    "spec_files": [
      "**/*[sS]pec.js"
    ],
    "stopSpecOnExpectationFailure": false,
    "random": false
}
```

这是我们目前所需要的所有代码。

我们现在可以开始构建 CI/CD 管道：

1.  使用以下命令提交本地创建的代码：

```
$ git add -A && git commit -m "First commit"
```

1.  为了避免所有的 node 模块都保存到 GitHub 上，向项目的`root`文件夹中添加一个`.gitignore`文件，并包含以下内容：

```
node_modules
```

1.  现在，我们需要在 GitHub 上定义一个存储库。在[`github.com`](https://github.com)上登录您的 GitHub 帐户。

1.  在那里创建一个新的存储库，并将其命名为`jenkins-pipeline`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/5bd043cb-4a05-4e38-b286-30d4c48a7b40.png)

为 Jenkins 管道示例应用程序创建一个新的 GitHub 存储库请注意，我的 GitHub 帐户是`gnschenker`。在您的情况下，将是您自己的帐户。

1.  在您点击了绿色按钮“创建存储库”之后，回到您的项目，并在项目的`root`文件夹中执行以下两个命令：

```
$ git remote add origin https://github.com/gnschenker/jenkins-pipeline.git
$ git push -u origin master
```

确保您在第一行中用您自己的 GitHub 帐户名替换`gnschenker`。完成此步骤后，您的代码将可在 GitHub 上供进一步使用。其中一个用户将是 Jenkins，它将从该存储库中拉取代码，我们将很快展示。

1.  下一步是返回 Jenkins（`localhost:8080`）并修改项目的配置。如果需要，请登录 Jenkins 并选择您的项目`sample-pipeline`。

1.  然后，在主菜单中选择配置。选择 Pipeline 选项卡，并修改设置，使其看起来类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c975f0de-984a-4fc0-b092-e4e848fd34dd.png)

配置 Jenkins 以从 GitHub 拉取源代码

使用这个，我们配置 Jenkins 从 GitHub 拉取代码，并使用`Jenkinsfile`来定义流水线。预计`Jenkinsfile`应该在项目的`根目录`中找到。请注意，对于存储库 URL 路径，我们需要给出相对路径到我们项目所在的`/home`目录。请记住，当运行 Jenkins 容器时，我们将我们自己的主机上的主目录映射到 Jenkins 容器内的`/home`目录，方法是：`-v "$HOME":/home`。

1.  点击绿色的保存按钮以接受更改。

1.  我们已经定义了`Jenkinsfile`需要在项目的`根目录`中。这是**Pipeline-as-Code**的基础，因为流水线定义文件将与其余代码一起提交到 GitHub 存储库中。因此，请在`jenkins-pipeline`文件夹中添加一个名为`Jenkinsfile`的文件，并将以下代码添加到其中：

```
pipeline {
    environment {
        registry = "gnschenker/jenkins-docker-test"
        DOCKER_PWD = credentials('docker-login-pwd')
    }
    agent {
        docker {
            image 'gnschenker/node-docker'
            args '-p 3000:3000'
            args '-w /app'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }
    options {
        skipStagesAfterUnstable()
    }
    stages {
        stage("Build"){
            steps {
                sh 'npm install'
            }
        }
        stage("Test"){
            steps {
                sh 'npm test'
            }
        }
        stage("Build & Push Docker image") {
            steps {
                sh 'docker image build -t $registry:$BUILD_NUMBER .'
                sh 'docker login -u gnschenker -p $DOCKER_PWD'
                sh 'docker image push $registry:$BUILD_NUMBER'
                sh "docker image rm $registry:$BUILD_NUMBER"
            }
        }
    }
}
```

好的，让我们一次解决这个文件的一部分。在顶部，我们定义了两个环境变量，它们将在流水线的每个阶段中都可用。我们将在`Build & Push Docker image`阶段中使用这些变量：

```
environment {
    registry = "gnschenker/jenkins-docker-test"
    DOCKER_PWD = credentials('docker-login-pwd')
}
```

第一个变量`registry`只包含我们最终将生成并推送到 Docker Hub 的容器镜像的完整名称。用您自己的 GitHub 用户名替换`gnschenker`。第二个变量`DOCKER_PWD`更有趣一些。它将包含登录到我的 Docker Hub 帐户的密码。当然，我不想在这里将值硬编码在代码中，因此，我使用 Jenkins 的凭据功能，它让我访问存储在 Jenkins 中名称为`docker-login-pwd`的秘密。

接下来，我们定义要在其上运行 Jenkins 流水线的代理。在我们的情况下，它是基于 Docker 镜像的。我们使用`gnschenker/node-docker`镜像来实现这一目的。这是一个基于`node:12.10-alpine`的镜像，其中安装了 Docker 和`curl`，因为我们将在某些阶段需要这两个工具：

```
agent {
    docker {
        image 'gnschenker/node-docker'
        args '-v /var/run/docker.sock:/var/run/docker.sock'
    }
}
```

通过`args`参数，我们还将 Docker 套接字映射到容器中，以便我们可以在代理内部使用 Docker。

暂时忽略选项部分。然后我们定义了三个阶段：

```
stages {
    stage("Build"){
        steps {
            sh 'npm install'
        }
    }
    stage("Test"){
        steps {
            sh 'npm test'
        }
    }
    stage("Build & Push Docker image") {
        steps {
            sh 'docker image build -t $registry:$BUILD_NUMBER .'
            sh 'docker login -u gnschenker -p $DOCKER_PWD'
            sh 'docker image push $registry:$BUILD_NUMBER'
            sh "docker image rm $registry:$BUILD_NUMBER"
        }
    }
}
```

第一个阶段`Build`只是运行`npm install`，以确保我们应用程序的所有外部依赖项都可以安装。例如，如果这是一个 Java 应用程序，我们可能还会在这一步中编译和打包应用程序。

在第二阶段`Test`中，我们运行`npm test`，这将运行我们为示例 API 定义的单元测试。

第三阶段，`构建和推送 Docker 镜像`，有点更有趣。现在我们已经成功构建并测试了我们的应用程序，我们可以为它创建一个 Docker 镜像并将其推送到注册表中。我们使用 Docker Hub 作为我们的注册表，但任何私有或公共注册表都可以使用。在这个阶段，我们定义了四个步骤：

1.  我们使用 Docker 来构建镜像。我们使用了在 Jenkinsfile 的第一部分中定义的`$registry`环境变量。`$BUILD_NUMBER`变量是由 Jenkins 自己定义的。

1.  在我们可以将某些东西推送到注册表之前，我们需要登录。在这里，我使用了之前定义的`$DOCKER_PWD`变量。

1.  一旦我们成功登录到注册表，我们就可以推送镜像。

1.  由于镜像现在在注册表中，我们可以从本地缓存中删除它，以避免浪费空间。

请记住，所有阶段都在我们的`gnschenker/node-docker`构建器容器内运行。因此，我们在 Docker 内部运行 Docker。但是，由于我们已经将 Docker 套接字映射到了构建器中，Docker 命令会在主机上执行。

让我们在流水线中再添加两个阶段。第一个看起来像这样：

```
stage('Deploy and smoke test') {
    steps{
        sh './jenkins/scripts/deploy.sh'
    }
}
```

将其添加到`构建和推送 Docker 镜像`阶段之后。这个阶段只是执行位于`jenkins/scripts`子文件夹中的`deploy.sh`脚本。我们的项目中还没有这样的文件。

因此，请将这个文件添加到你的项目中，并包含以下内容：

```
#!/usr/bin/env sh

echo "Removing api container if it exists..."
docker container rm -f api || true
echo "Removing network test-net if it exists..."
docker network rm test-net || true

echo "Deploying app ($registry:$BUILD_NUMBER)..."
docker network create test-net

docker container run -d \
    --name api \
    --net test-net \
    $registry:$BUILD_NUMBER

# Logic to wait for the api component to be ready on port 3000

read -d '' wait_for << EOF
echo "Waiting for API to listen on port 3000..."
while ! nc -z api 3000; do 
  sleep 0.1 # wait for 1/10 of the second before check again
  printf "."
done
echo "API ready on port 3000!"
EOF

docker container run --rm \
    --net test-net \
    node:12.10-alpine sh -c "$wait_for"

echo "Smoke tests..."
docker container run --name tester \
    --rm \
    --net test-net \
    gnschenker/node-docker sh -c "curl api:3000"
```

好的，所以这段代码做了以下几件事。首先，它试图移除可能残留在之前失败的流水线运行中的任何残留物。然后，它创建了一个名为`test-net`的 Docker 网络。接下来，它从我们在上一步中构建的镜像中运行一个容器。这个容器是我们的 Express JS API，相应地被称为`api`。

这个容器和其中的应用可能需要一些时间才能准备好。因此，我们定义了一些逻辑，使用`netcat`或`nc`工具来探测端口`3000`。一旦应用程序在端口`3000`上监听，我们就可以继续进行烟雾测试。在我们的情况下，烟雾测试只是确保它可以访问我们 API 的`/`端点。我们使用`curl`来完成这个任务。在一个更现实的设置中，你可能会在这里运行一些更复杂的测试。

作为最后阶段，我们添加了一个`Cleanup`步骤：

1.  在你的`Jenkinsfile`中添加以下片段作为最后一个阶段：

```
stage('Cleanup') {
    steps{
        sh './jenkins/scripts/cleanup.sh'
    }
}
```

再次，这个`Cleanup`阶段使用了位于`jenkins/script`子文件夹中的脚本。

1.  请向你的项目添加一个包含以下内容的文件：

```
#!/usr/bin/env sh

docker rm -f api
docker network rm test-net
```

该脚本删除了我们用来运行容器的`api`容器和 Docker 网络`test-net`。

1.  现在，我们准备好了。使用`git`提交您的更改并将其推送到您的存储库：

```
$ git -a . && git commit -m "Defined code based Pipeline"
$ git push origin master
```

代码推送到 GitHub 后，返回 Jenkins。

1.  选择您的`sample-pipeline`项目并在主菜单中点击立即构建。Jenkins 将开始构建流水线。如果一切顺利，您应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/09e00d85-9229-40a2-bad3-1fbf4e92e1bc.png)

在 Jenkins 中运行我们的完整基于代码的流水线

我们的流水线已成功执行，现在有六个步骤。从 GitHub 检出已自动添加为第一个启用步骤。要访问流水线执行期间生成的日志，可以点击构建历史下运行左侧的小球图标。在前面的屏幕截图中，它是**#26**左侧的蓝色图标。如果流水线步骤失败，这将特别有帮助，可以快速找到失败的根本原因。

总之，我们已经构建了一个简单的 CI/CD 流水线，其中包括自动化服务器 Jenkins 在内的所有内容都在容器中运行。我们只是触及了可能性的表面。

# 概要

在本章中，我们学习了如何使用 Docker 容器来优化各种自动化任务，从运行简单的一次性任务到构建容器化的 CI/CD 流水线。

在下一章中，我们将介绍在容器化复杂的分布式应用程序或使用 Docker 自动化复杂任务时有用的高级技巧、技巧和概念。

# 问题

1.  列出在容器中运行一次性任务的几个优缺点。

1.  列出在容器中运行测试的两三个优点。

1.  勾画一个以容器化的 CI/CD 流水线为起点的高层次图，从用户生成代码到代码部署到生产环境。

# 进一步阅读

+   使用 Docker 编写可维护的集成测试 [`www.docker.com/blog/maintainable-integration-tests-with-docker/`](https://www.docker.com/blog/maintainable-integration-tests-with-docker/)

+   .NET 开发人员的 Docker 工作流程-第二部分（集成测试）[`gabrielschenker.com/index.php/2019/10/09/a-docker-workflow-for-net-developers-part-2/`](https://gabrielschenker.com/index.php/2019/10/09/a-docker-workflow-for-net-developers-part-2/)

+   Docker Hub 上的 Jenkins [`hub.docker.com/_/jenkins/`](https://hub.docker.com/_/jenkins/)

+   Jenkins 教程概述在[`jenkins.io/doc/tutorials/`](https://jenkins.io/doc/tutorials/)。


# 第八章：高级 Docker 使用场景

在上一章中，我们向您展示了如何使用工具执行管理任务，而无需在主机计算机上安装这些工具。我们还说明了容器的使用，这些容器托管和运行用于测试和验证在容器中运行的应用程序服务的测试脚本或代码。最后，我们指导您构建了一个使用 Jenkins 作为自动化服务器的基于 Docker 的简单 CI/CD 流水线的任务。

在本章中，我们将介绍在将复杂的分布式应用程序容器化或使用 Docker 自动化复杂任务时有用的高级技巧、窍门和概念。

这是本章中我们将涉及的所有主题的快速概述：

+   所有 Docker 专业人士的技巧和窍门

+   在远程容器中运行终端并通过 HTTPS 访问它

+   在容器内运行开发环境

+   在远程容器中运行代码编辑器并通过 HTTPS 访问它

完成本章后，您将能够执行以下操作：

+   在完全混乱后成功恢复您的 Docker 环境

+   在容器中运行远程终端，并通过 HTTPS 在浏览器中访问它

+   通过 HTTPS 在浏览器中使用 Visual Studio Code 远程编辑代码

# 技术要求

在本章中，如果您想跟着代码进行操作，您需要在 Mac 或 Windows 机器上安装 Docker for Desktop 和 Visual Studio Code 编辑器。该示例也适用于安装了 Docker 和 Visual Studio Code 的 Linux 机器。Docker Toolbox 在本章中不受支持。

# 所有 Docker 专业人士的技巧和窍门

在本节中，我将介绍一些非常有用的技巧和窍门，这些技巧和窍门可以让高级 Docker 用户的生活变得更加轻松。我们将从如何保持 Docker 环境清洁开始。

# 保持您的 Docker 环境清洁

首先，我们想学习如何删除悬空镜像。根据 Docker 的说法，悬空镜像是与任何已标记镜像没有关联的层。这样的镜像层对我们来说肯定是无用的，并且可能会很快地填满我们的磁盘——最好定期将它们删除。以下是命令：

```
$ docker image prune -f
```

请注意，我已经向`prune`命令添加了`-f`参数。这是为了防止 CLI 询问我们是否真的要删除那些多余的层。

停止的容器也会浪费宝贵的资源。如果您确定不再需要这些容器，那么您应该使用以下命令逐个删除它们：

```
$ docker container rm <container-id>
```

或者，您可以使用以下命令批量删除它们：

```
$ docker container prune --force
```

值得再次提到的是，除了`<container-id>`，我们还可以使用`<container-name>`来标识容器。

未使用的 Docker 卷也可能很快填满磁盘空间。在开发或 CI 环境中，特别是在创建大量临时卷的情况下，妥善处理您的卷是一个好习惯。但是我必须警告您，Docker 卷是用来存储数据的。通常，这些数据的生存周期必须比容器的生命周期长。这在生产或类似生产环境中尤其如此，那里的数据通常是至关重要的。因此，在使用以下命令清理 Docker 主机上的卷时，请务必百分之百确定自己在做什么：

```
$ docker volume prune
WARNING! This will remove all local volumes not used by at least one container.
Are you sure you want to continue? [y/N]
```

我建议不要使用`-f`（或`--force`）标志的这个命令。这是一个危险的终端操作，最好给自己第二次机会来重新考虑您的行动。没有这个标志，CLI 会输出您在上面看到的警告。您必须通过输入`y`并按下*Enter*键来明确确认。

在生产或类似生产系统中，您应该避免使用上述命令，而是使用以下命令逐个删除不需要的卷：

```
$ docker volume rm <volume-name>
```

我还应该提到有一个命令可以清理 Docker 网络。但由于我们尚未正式介绍网络，我将把这个推迟到[第十章]，*单主机网络*。

在下一节中，我们将展示如何可以从容器内部自动化 Docker。

# 在 Docker 中运行 Docker

有时，我们可能想要运行一个托管应用程序的容器，该应用程序自动化执行某些 Docker 任务。我们该怎么做呢？Docker 引擎和 Docker CLI 已安装在主机上，但应用程序在容器内运行。早期，Docker 就提供了一种将 Linux 套接字从主机绑定到容器的方法。在 Linux 上，套接字被用作在同一主机上运行的进程之间非常高效的数据通信端点。Docker CLI 使用套接字与 Docker 引擎通信；它通常被称为 Docker 套接字。如果我们可以将 Docker 套接字授予在容器内运行的应用程序访问权限，那么我们只需在此容器内安装 Docker CLI，然后我们将能够在相同的容器中运行使用本地安装的 Docker CLI 自动化特定于容器的任务的应用程序。

重要的是要注意，这里我们不是在谈论在容器内运行 Docker 引擎，而是只运行 Docker CLI 并将 Docker 套接字从主机绑定到容器中，以便 CLI 可以与主机计算机上运行的 Docker 引擎进行通信。这是一个重要的区别。在容器内运行 Docker 引擎虽然可能，但不建议。

假设我们有以下脚本，名为`pipeline.sh`，自动化构建、测试和推送 Docker 镜像：

```
#! /bin/bash
# *** Sample script to build, test and push containerized Node.js applications *
# build the Docker image
docker image build -t $HUB_USER/$REPOSITORY:$TAG .
# Run all unit tests
docker container run $HUB_USER/$REPOSITORY:$TAG npm test
# Login to Docker Hub
docker login -u $HUB_USER -p $HUB_PWD
# Push the image to Docker Hub
docker image push $HUB_USER/$REPOSITORY:$TAG
```

请注意，我们正在使用四个环境变量：`$HUB_USER`和`$HUB_PWD`是 Docker Hub 的凭据，`$REPOSITORY`和`$TAG`是我们要构建的 Docker 镜像的名称和标签。最终，我们将不得不在`docker run`命令中传递这些环境变量的值。

我们想要在一个构建器容器内运行该脚本。由于该脚本使用 Docker CLI，我们的构建器容器必须安装 Docker CLI，并且要访问 Docker 引擎，构建器容器必须将 Docker 套接字绑定。让我们开始为这样一个构建器容器创建一个 Docker 镜像：

1.  首先，创建一个`builder`文件夹并导航到它：

```
$ mkdir builder && cd builder
```

1.  在这个文件夹里，创建一个看起来像这样的`Dockerfile`：

```
FROM alpine:latest
RUN apk update && apk add docker
WORKDIR /usr/src/app
COPY . .
CMD ./pipeline.sh
```

1.  现在在`builder`文件夹中创建一个`pipeline.sh`文件，并将我们在前面文件中呈现的流水线脚本添加为内容。

1.  保存并使文件可执行：

```
$ chmod +x ./pipeline.sh
```

1.  构建镜像很简单：

```
$ docker image build -t builder .
```

我们现在准备使用一个真实的 Node.js 应用程序来尝试`builder`，例如我们在`ch08/sample-app`文件夹中定义的示例应用程序。确保您用 Docker Hub 的自己的凭据替换`<user>`和`<password>`：

```
$ cd ~/fod/ch08/sample-app
$ docker container run --rm \
 --name builder \
 -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD":/usr/src/app \
 -e HUB_USER=<user> \
 -e HUB_PWD=<password>@j \
 -e REPOSITORY=ch08-sample-app \
 -e TAG=1.0 \
 builder
```

请注意，在上述命令中，我们使用`-v /var/run/docker.sock:/var/run/docker.sock`将 Docker 套接字挂载到容器中。如果一切顺利，您应该已经为示例应用程序构建了一个容器镜像，测试应该已经运行，并且镜像应该已经推送到 Docker Hub。这只是许多用例中的一个，其中能够绑定挂载 Docker 套接字非常有用。

特别注意，所有想尝试 Windows 容器的人。在 Windows 上的 Docker 中，您可以通过绑定挂载 Docker 的**命名管道**来创建类似的环境，而不是一个套接字。在 Windows 上，命名管道与基于 Unix 的系统上的套接字大致相同。假设您正在使用 PowerShell 终端，运行 Windows 容器托管 Jenkins 时，绑定挂载命名管道的命令如下：

`**PS>** **docker container run `** **--name jenkins `** **-p 8080:8080 `** **-v \\.\pipe\docker_engine:\\.\pipe\docker_engine `

friism/jenkins**`

注意特殊的语法`\\.\pipe\docker_engine`，用于访问 Docker 的命名管道。

# 格式化常见 Docker 命令的输出

有时您是否希望您的终端窗口是无限宽的，因为像`docker container ps`这样的 Docker 命令的输出会在每个项目上跨越多行？不用担心，因为您可以根据自己的喜好自定义输出。几乎所有产生输出的命令都有一个`--format`参数，它接受一个所谓的 Go 模板作为参数。如果您想知道为什么是 Go 模板，那是因为 Docker 的大部分代码都是用这种流行的低级语言编写的。让我们看一个例子。假设我们只想显示`docker container ps`命令输出的容器名称、镜像名称和容器状态，用制表符分隔。格式将如下所示：

```
$ docker container ps -a \
--format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
```

请注意，`format`字符串是区分大小写的。还要注意添加`-a`参数以包括已停止的容器在输出中。示例输出可能如下所示：

```
NAMES              IMAGE            STATUS
elated_haslett     alpine           Up 2 seconds
brave_chebyshev    hello-world      Exited (0) 3 minutes ago
```

这绝对比未格式化的输出更好，即使在窄窄的终端窗口上也是如此，未格式化的输出会在多行上随意散开。

# 过滤常见 Docker 命令的输出

与我们在上一节中所做的内容类似，通过美化 Docker 命令的输出，我们也可以筛选输出内容。支持许多过滤器。请在 Docker 在线文档中找到每个命令的完整列表。过滤器的格式很简单，是`--filter <key>=<value>`的类型。如果我们需要结合多个过滤器，我们可以结合多个这些语句。让我们以`docker image ls`命令为例，因为我在我的工作站上有很多镜像：

```
$ docker image ls --filter dangling=false --filter "reference=*/*/*:latest"
```

前面的过滤器只输出不悬空的镜像，也就是真实的镜像，其完全限定名称的形式为`<registry>/<user|org><repository>:<tag>`，并且标签等于`latest`。我的机器上的输出如下：

```
REPOSITORY                                  TAG     IMAGE ID      CREATED   SIZE
docker.bintray.io/jfrog/artifactory-cpp-ce  latest  092f11699785  9 months  ago 900MB
docker.bintray.io/jfrog/artifactory-oss     latest  a8a8901c0230  9 months  ago 897MB
```

在展示了如何美化和筛选 Docker CLI 生成的输出之后，现在是时候再次谈论构建 Docker 镜像以及如何优化这个过程了。

# 优化构建过程

许多 Docker 初学者在编写他们的第一个`Dockerfile`时会犯以下错误：

```
FROM node:12.10-alpine
WORKDIR /usr/src/app
COPY . .
RUN npm install
CMD npm start
```

你能发现这个典型的 Node.js 应用程序的`Dockerfile`中的薄弱点吗？在第四章中，*创建和管理容器镜像*，我们已经学到镜像由一系列层组成。`Dockerfile`中的每一行（逻辑上）都创建一个层，除了带有`CMD`和/或`ENTRYPOINT`关键字的行。我们还学到 Docker 构建器会尽力缓存层，并在后续构建之间重用它们。但是缓存只使用在第一个更改的层之前出现的缓存层。所有后续层都需要重新构建。也就是说，`Dockerfile`的前面结构破坏了镜像层缓存！

为什么？嗯，从经验上来说，你肯定知道在一个典型的具有许多外部依赖的 Node.js 应用程序中，`npm install` 可能是一个非常昂贵的操作。执行此命令可能需要几秒钟到几分钟。也就是说，每当源文件之一发生变化，我们知道在开发过程中这经常发生，`Dockerfile` 中的第 3 行会导致相应的镜像层发生变化。因此，Docker 构建器无法重用缓存中的此层，也无法重用由 `RUN npm install` 创建的随后的层。代码的任何微小变化都会导致完全重新运行 `npm install`。这是可以避免的。包含外部依赖列表的 `package.json` 文件很少改变。有了所有这些信息，让我们修复 `Dockerfile`：

```
FROM node:12.10-alpine
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install
COPY . .
CMD npm start
```

这一次，在第 3 行，我们只将 `package.json` 文件复制到容器中，这个文件很少改变。因此，随后的 `npm install` 命令也需要同样很少地执行。第 5 行的 `COPY` 命令是一个非常快速的操作，因此在一些代码改变后重新构建镜像只需要重新构建这最后一层。构建时间减少到几乎只有一小部分秒数。

同样的原则适用于大多数语言或框架，比如 Python、.NET 或 Java。避免破坏你的镜像层缓存！

# 限制容器消耗的资源

容器的一个很棒的特性，除了封装应用程序进程外，还可以限制单个容器可以消耗的资源。这包括 CPU 和内存消耗。让我们来看看如何限制内存（RAM）的使用：

```
$ docker container run --rm -it \
    --name stress-test \
 --memory 512M \
 ubuntu:19.04 /bin/bash
```

一旦进入容器，安装 `stress` 工具，我们将用它来模拟内存压力：

```
/# apt-get update && apt-get install -y stress
```

打开另一个终端窗口并执行 `docker stats` 命令。你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8a674500-7732-44f7-98fd-a13d1aa38450.png)

docker stats 显示了一个资源受限的容器

观察 `MEM USAGE` 和 `LIMIT`。目前，容器只使用了 `1.87MiB` 的内存，限制为 `512MB`。后者对应我们为这个容器配置的内容。现在，让我们使用 `stress` 来模拟四个尝试以 `256MB` 为块的工作进程。在容器内运行此命令以执行：

```
/# stress -m 4
```

在运行 Docker stats 的终端中，观察 `MEM USAGE` 的值如何接近但从未超过 `LIMIT`。这正是我们从 Docker 期望的行为。Docker 使用 Linux `cgroups` 来强制执行这些限制。

我们可以通过`--cpu`开关类似地限制容器可以消耗的 CPU 数量。

通过这种操作，工程师可以避免在繁忙的 Docker 主机上出现嘈杂的邻居问题，即一个容器通过消耗过多的资源使其他所有容器陷入困境。

# 只读文件系统

为了保护您的应用免受恶意黑客攻击，通常建议将容器的文件系统或部分文件系统定义为只读。这对于无状态服务来说是最有意义的。假设您在作为分布式、关键任务应用的一部分运行的容器中有一个计费服务。您可以按以下方式运行计费服务：

```
$ docker container run -d --rm \
 --name billing \
 --read-only \
 acme/billing:2.0
```

`--read-only`标志将容器的文件系统挂载为只读。如果黑客成功进入您的计费容器并试图恶意更改应用程序，比如用一个受损的二进制文件替换其中一个，那么这个操作将失败。我们可以通过以下命令轻松演示：

```
$ docker container run --tty -d \
    --name billing \
    --read-only \
    alpine /bin/sh 
$ docker container exec -it billing \
 sh -c 'echo "You are doomed!" > ./sample.txt' sh: can't create ./sample.txt: Read-only file system
```

第一个命令以只读文件系统运行容器，第二个命令尝试在该容器中执行另一个进程，该进程应该向文件系统写入一些东西——在这种情况下是一个简单的文本文件。这会失败，正如我们在前面的输出中看到的，出现了错误消息`只读文件系统`。

加强容器中运行应用程序安全性的另一种方法是避免以`root`身份运行它们。

# 避免以 root 身份运行容器化应用

大多数运行在容器内的应用或应用服务不需要 root 访问权限。为了加强安全性，在这些情况下以最小必要权限运行这些进程是有帮助的。这些应用不应该以`root`身份运行，也不应该假设它们具有`root`级别的权限。

再次，让我们通过一个例子来说明我们的意思。假设我们有一个包含绝密内容的文件。我们希望在我们的基于 Unix 的系统上使用`chmod`工具来保护这个文件，以便只有具有 root 权限的用户才能访问它。假设我以`dev`主机上的`gabriel`身份登录，因此我的提示符是`gabriel@dev $`。我可以使用`sudo su`来冒充超级用户。不过我必须输入超级用户密码：

```
gabriel@dev $ sudo su
Password: <root password>
root@dev $
```

现在，作为`root`用户，我可以创建一个名为`top-secret.txt`的文件并保护它：

```
root@dev $ echo "You should not see this." > top-secret.txt
root@dev $ chmod 600 ./top-secret.txt
root@dev $ exit
gabriel@dev $
```

如果我尝试以`gabriel`的身份访问文件，会发生以下情况：

```
gabriel@dev $ cat ./top-secret.txt
cat: ./top-secret.txt: Permission denied
```

我得到了`Permission denied`，这正是我们想要的。除了`root`之外，没有其他用户可以访问这个文件。现在，让我们构建一个包含这个受保护文件的 Docker 镜像，当从中创建一个容器时，尝试输出它的内容。`Dockerfile`可能是这样的：

```
FROM ubuntu:latest
COPY ./top-secret.txt /secrets/
# simulate use of restricted file
CMD cat /secrets/top-secret.txt
```

我们可以使用以下命令从该 Dockerfile 构建一个镜像（以`root`身份！）：

```
gabriel@dev $ sudo su
Password: <root password>
root@dev $ docker image build -t demo-image .
root@dev $ exit
gabriel@dev $
```

然后，从该镜像运行一个容器，我们得到：

```
gabriel@dev $ docker container run demo-image You should not see this.
```

好的，尽管我在主机上冒充`gabriel`用户并在该用户账户下运行容器，但容器内运行的应用程序自动以`root`身份运行，因此可以完全访问受保护的资源。这很糟糕，所以让我们来修复它！我们不再使用默认设置，而是在容器内定义一个显式用户。修改后的`Dockerfile`如下：

```
FROM ubuntu:latest
RUN groupadd -g 3000 demo-group |
 && useradd -r -u 4000 -g demo-group demo-user
USER demo-user
COPY ./top-secret.txt /secrets/
# simulate use of restricted file
CMD cat /secrets/top-secret.txt
```

我们使用`groupadd`工具来定义一个新的组，`demo-group`，ID 为`3000`。然后，我们使用`useradd`工具向这个组添加一个新用户，`demo-user`。用户在容器内的 ID 为`4000`。最后，通过`USER demo-user`语句，我们声明所有后续操作应该以`demo-user`身份执行。

重新构建镜像——再次以`root`身份——然后尝试从中运行一个容器：

```
gabriel@dev $ sudo su
Password: <root password>
root@dev $ docker image build -t demo-image .
root@dev $ exit
gabriel@dev $ docker container run demo-image cat: /secrets/top-secret.txt: Permission denied
```

正如您在最后一行所看到的，容器内运行的应用程序以受限权限运行，无法访问需要 root 级别访问权限的资源。顺便问一下，如果我以`root`身份运行容器会发生什么？试一试吧！

这些是一些对专业人士有用的日常容器使用技巧。还有很多。去 Google 搜索一下。值得的。

# 在远程容器中运行您的终端并通过 HTTPS 访问它

有时您需要访问远程服务器，只能使用浏览器进行访问。您的笔记本电脑可能被雇主锁定，因此不允许您例如`ssh`到公司域之外的服务器。

要测试这种情况，请按照以下步骤进行：

1.  在 Microsoft Azure、GCP 或 AWS 上创建一个免费账户。然后，创建一个虚拟机，最好使用 Ubuntu 18.04 或更高版本作为操作系统，以便更容易跟随操作。

1.  一旦您的虚拟机准备就绪，就可以通过 SSH 登录。执行此操作的命令应该类似于这样：

```
$ ssh gnschenker@40.115.4.249
```

要获得访问权限，您可能需要首先为虚拟机打开`22`端口以进行入口。

我在虚拟机配置期间定义的用户是`gnschenker`，我的虚拟机的公共 IP 地址是`40.115.4.249`。

1.  使用此处找到的说明在 VM 上安装 Docker：[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)。

1.  特别注意，不要忘记使用以下命令将您的用户（在我的情况下是`gnschenker`）添加到 VM 上的`docker`组中：

```
$ sudo usermod -aG docker <user-name>
```

通过这样做，您可以避免不断使用`sudo`执行所有 Docker 命令。您需要注销并登录到 VM 以使此更改生效。

1.  现在，我们准备在 VM 上的容器中运行**Shell in a Box**（[`github.com/shellinabox/shellinabox`](https://github.com/shellinabox/shellinabox)）。有很多人将 Shell in a Box 容器化。我们使用的是 Docker 镜像，`sspreitzer/shellinabox`。在撰写本文时，这是 Docker Hub 上迄今为止最受欢迎的版本。使用以下命令，我们将以用户`gnschenker`、密码`top-secret`、启用用户的`sudo`和自签名证书运行应用程序：

```
$ docker container run --rm \
    --name shellinabox \
 -p 4200:4200 \
    -e SIAB_USER=gnschenker \
 -e SIAB_PASSWORD=top-secret \
 -e SIAB_SUDO=true \
 -v `pwd`/dev:/usr/src/dev \
 sspreitzer/shellinabox:latest
```

请注意，最初我们建议以交互模式运行容器，以便您可以跟踪发生的情况。一旦您更熟悉该服务，考虑使用`-d`标志在后台运行它。还要注意，我们将主机的`~/dev`文件夹挂载到容器内的`/usr/src/dev`文件夹。如果我们想要远程编辑我们从 GitHub 克隆的代码，这将非常有用，例如，克隆到`~/dev`文件夹中。

还要注意，我们将 Shell in a Box 的端口`4200`映射到主机端口`4200`。这是我们将能够使用浏览器和 HTTPS 访问 shell 的端口。因此，您需要在 VM 上为入口打开端口`4200`。作为协议，选择 TCP。

1.  一旦容器正在运行，并且您已经为入口打开了端口`4200`，请打开一个新的浏览器窗口，导航到`https://<public-IP>:4200`，其中`<public-IP>`是您的 VM 的公共 IP 地址。由于我们使用的是自签名证书，您将收到一个警告，如在使用 Firefox 时所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/110c91ea-409e-47e7-b670-c5ab08fda9ba.png)

由于使用自签名证书而导致的浏览器警告

1.  在我们的情况下，这不是问题；我们知道原因——就是自签名证书。因此，点击**高级...**按钮，然后接受风险并继续。现在，您将被重定向到登录屏幕。使用您的用户名和密码登录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6758f0cc-3405-4ede-b37e-8a0f2930a147.png)

使用 HTTPS 从浏览器登录到远程 VM

我们已经登录到运行在远程 VM 上的**Shell in a Box**应用程序，使用 HTTPS 协议。

1.  现在，我们可以完全访问，例如，从主机 VM 映射到`/usr/src/dev`的文件和文件夹。例如，我们可以使用`vi`文本编辑器来创建和编辑文件，尽管我们必须首先安装 vi，方法如下：

```
$ sudo apt-get update && sudo apt-get install -y vim
```

1.  可能性几乎是无穷无尽的。请尝试使用这个设置。例如，使用挂载了 Docker 套接字的 Shell in a Box 容器，安装容器内的 Docker，然后尝试从容器内使用 Docker CLI。这真的很酷，因为你可以在浏览器内完成所有这些操作！

1.  如果你打算经常使用这个 Shell in a Box 容器，并且需要安装一些额外的软件，请毫不犹豫地创建你自己的自定义 Docker 镜像，继承自`sspreitzer/shellinabox`。

接下来，我们将看到如何在容器内运行你的开发环境。

# 在容器内运行开发环境

想象一下，你只能访问安装了 Docker for Desktop 的工作站，但无法在这台工作站上添加或更改任何其他内容。现在你想做一些概念验证，并使用 Python 编写一些示例应用程序。不幸的是，你的计算机上没有安装 Python。你能做什么？如果你能在容器内运行整个开发环境，包括代码编辑器和调试器，同时仍然可以在主机上拥有你的代码文件呢？

容器很棒，聪明的工程师已经提出了解决这种问题的解决方案。

让我们尝试一下 Python 应用程序：

1.  我们将使用我们最喜欢的代码编辑器 Visual Studio Code，来展示如何在容器内运行完整的 Python 开发环境。但首先，我们需要安装必要的 Visual Studio Code 扩展。打开 Visual Studio Code 并安装名为 Remote Development 的扩展：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/9cd9233c-6976-4204-b2ed-9a00693a4547.png)

Visual Studio Code 的 Remote Development 扩展

1.  然后，点击 Visual Studio Code 窗口左下角的绿色快速操作状态栏项。在弹出窗口中，选择**Remote-Containers: Open Folder in Container...**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/32c52f7a-da9f-4d2f-b82c-14343336162d.png)

在远程容器中打开一个项目

1.  选择要在容器中使用的项目文件夹。在我们的案例中，我们选择了`~/fod/ch08/remote-app`文件夹。Visual Studio Code 将开始准备环境，这在第一次可能需要几分钟左右。在此期间，您将看到如下消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/00fddd11-d359-4cae-8003-bf8206513e2c.png)

Visual Studio Code 正在准备开发容器

默认情况下，此开发容器以非根用户身份运行，我们的情况下称为`python`。我们在之前的部分中了解到，这是一个强烈推荐的最佳实践。您可以通过注释掉`.devcontainer/devcontainer.json`文件中的`"runArgs": [ "-u", "python" ]`行来更改，并以`root`身份运行。

1.  使用*Shift* + *Ctrl* + *`*在 Visual Studio Code 内打开一个终端，并使用`env FLASK_APP=main.py flask run`命令运行 Flask 应用程序。您应该会看到如下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/d410a8ba-00c4-4722-a958-fba0fff9fcda.png)

从 Visual Studio Code 在容器内运行的 Python Flask 应用程序开始

`python@df86dceaed3d:/workspaces/remote-app$`提示表明我们**不是**直接在我们的 Docker 主机上运行，而是在 Visual Studio Code 为我们启动的开发容器内运行。Visual Studio Code 本身的远程部分也运行在该容器内。只有 Visual Studio Code 的客户端部分——UI——继续在我们的主机上运行。

1.  通过按*Shift+Ctrl+`*在 Visual Studio Code 内打开另一个终端窗口。然后，使用`curl`测试应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6fb04349-0556-43fa-a13b-bc21d70cfe9f.png)

测试远程 Flask 应用程序

1.  按下*Ctrl* + *C*停止 Flask 应用程序。

1.  我们也可以像在主机上直接工作时那样调试应用程序。打开`.vscode/launch.json`文件，了解 Flask 应用程序是如何启动的以及调试器是如何附加的。

1.  打开`main.py`文件，并在`home()`函数的`return`语句上设置一个断点。

1.  然后，切换到 Visual Studio Code 的调试视图，并确保在下拉菜单中选择启动任务`Python: Flask`。

1.  接下来，按下绿色的启动箭头开始调试。终端中的输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/63424e41-5a80-476c-8a90-0415284ac839.png)

在容器中运行的远程应用程序开始调试

1.  使用*Shift* + *Ctrl* + *`*打开另一个终端，并通过运行`curl localhost:9000/`命令来测试应用程序。调试器应该会触发断点，您可以开始分析：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8d6e30fd-ec53-4dce-ae48-d9ec94e1d718.png)

在容器内运行的 Visual Studio Code 中逐行调试

我无法强调这有多酷。Visual Studio Code 的后端（非 UI 部分）正在容器内运行，Python、Python 调试器和 Python Flask 应用程序也是如此。同时，源代码从主机挂载到容器中，Visual Studio Code 的 UI 部分也在主机上运行。这为开发人员在受限制最严格的工作站上打开了无限的可能性。您可以对所有流行的语言和框架执行相同的操作，比如.NET、C#、Java、Go、Node.js 和 Ruby。如果某种语言不受支持，您可以创建自己的开发容器，然后它将与我们展示的 Python 相同的方式工作。

如果您在没有安装 Docker for Desktop 并且受到更严格限制的工作站上工作，该怎么办？您有哪些选择？

# 在远程容器中运行您的代码编辑器，并通过 HTTPS 访问它

在本节中，我们将展示如何使用 Visual Studio Code 在容器内启用远程开发。当您在工作站上受限时，这是很有趣的。让我们按照以下步骤进行：

1.  下载并提取最新版本的`code-server`。您可以通过导航到[`github.com/cdr/code-server/releases/latest`](https://github.com/cdr/code-server/releases/latest)来找到 URL。在撰写本文时，它是`1.1156-vsc1.33.1`：

```
$ VERSION=<version>
$ wget https://github.com/cdr/code-server/releases/download/${VERSION}/code-server${VERSION}-linux-x64.tar.gz
$ tar -xvzf code-server${VERSION}-linux-x64.tar.gz
```

确保用您的特定版本替换`<version>`

1.  导航到提取的二进制文件所在的文件夹，使其可执行，并启动它：

```
$ cd code-server${VERSION}-linux-x64
$ chmod +x ./code-server
$ sudo ./code-server -p 4200
```

输出应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ea928591-0b62-4b04-9281-7d2ac4e551b7.png)

在远程 VM 上启动 Visual Studio Code 远程服务器

Code Server 使用自签名证书来保护通信，因此我们可以通过 HTTPS 访问它。请确保您记下屏幕上的`Password`输出，因为在浏览器中访问 Code Server 时需要它。还要注意，我们使用端口`4200`在主机上暴露 Code Server，原因是我们已经为 VM 上的入口打开了该端口。当然，您可以选择任何端口 - 只需确保您为入口打开它。

1.  打开一个新的浏览器页面，导航到`https://<public IP>:4200`，其中`<public IP>`是您的 VM 的公共 IP 地址。由于我们再次使用自签名证书，浏览器会出现警告，类似于我们在本章前面使用 Shell in a Box 时发生的情况。接受警告，您将被重定向到 Code Server 的登录页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/d465a2e6-484a-44ef-98e5-f2a793ed4f9e.png)

Code Server 的登录页面

1.  输入您之前记录的密码，然后点击“进入 IDE”。现在您将能够通过安全的 HTTPS 连接远程使用 Visual Studio Code：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/119fd2f9-696d-40d1-a25c-8292f546b98e.png)

在浏览器上运行的 Visual Studio Code 通过 HTTPS

1.  现在，您可以从 Chrome Book 或受限制的工作站等设备进行开发，而不受限制。但等一下，您可能会说！这与容器有什么关系？您是对的——到目前为止，没有涉及到容器。不过，我可以说，如果您的远程 VM 安装了 Docker，您可以使用 Code Server 来进行任何与容器相关的开发，我就可以解决问题了。但那将是一个廉价的答案。

1.  让我们在一个容器中运行 Code Server 本身。这应该很容易，不是吗？尝试使用这个命令，将内部端口`8080`映射到主机端口`4200`，并将包含 Code Server 设置和可能包含您的项目的主机文件夹挂载到容器中：

```
$ docker container run -it \
 -p 4200:8080 \
 -v "${HOME}/.local/share/code-server:/home/coder/.local/share/code-server" \
 -v "$PWD:/home/coder/project" \
 codercom/code-server:v2
```

请注意，前面的命令以不安全模式运行 Code Server，如输出所示：

```
info Server listening on http://0.0.0.0:8080
info - No authentication
info - Not serving HTTPS
```

1.  您现在可以在浏览器中访问`http://<public IP>:4200`中的 Visual Studio Code。请注意 URL 中的`HTTP`而不是`HTTPS`！与在远程 VM 上本地运行 Code Server 时类似，您现在可以在浏览器中使用 Visual Studio Code：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c7e66138-3253-4388-a724-f50fe7f064fc.png) 在浏览器中进行开发

通过这个，我希望您对容器的使用提供了近乎无限的可能性有所了解。

# 摘要

在本章中，我们展示了一些高级 Docker 用户的技巧和窍门，可以让您的生活更加高效。我们还展示了如何利用容器来提供在远程服务器上运行并可以通过安全的 HTTPS 连接从浏览器中访问的整个开发环境。

在下一章中，我们将介绍分布式应用架构的概念，并讨论运行分布式应用所需的各种模式和最佳实践。除此之外，我们还将列出在生产环境或类似生产环境中运行此类应用所需满足的一些问题。

# 问题

1.  列出你想在容器内运行完整开发环境的原因。

1.  为什么应该避免以`root`身份在容器内运行应用程序？

1.  为什么要将 Docker 套接字绑定到容器中？

1.  在清理 Docker 资源以释放空间时，为什么需要特别小心处理卷？

# 进一步阅读

+   在 CI 中不要在 Docker 中使用 Docker：在[`jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/`](http://jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/)中使用 Docker

+   在[`github.com/shellinabox/shellinabox`](https://github.com/shellinabox/shellinabox)上的 Shell in a Box

+   在[`code.visualstudio.com/docs/remote/ssh`](https://code.visualstudio.com/docs/remote/ssh)上使用 SSH 进行远程开发

+   在[`code.visualstudio.com/docs/remote/containers`](https://code.visualstudio.com/docs/remote/containers)中在容器内开发


# 第三部分：编排基础知识和 Docker Swarm

在这一部分，您将熟悉 docker 化的分布式应用程序的概念，以及容器编排器，并使用 Docker Swarm 部署和运行您的应用程序。

本节包括以下章节：

+   第九章，*分布式应用程序架构*

+   第十章，*单主机网络*

+   第十一章，*Docker Compose*

+   第十二章，*编排器*

+   第十三章，*介绍 Docker Swarm*

+   第十四章，*零停机部署和秘密*


# 第九章：分布式应用架构

在上一章中，我们讨论了在容器化复杂的分布式应用程序或使用 Docker 自动化复杂任务时有用的高级技巧和概念。

在本章中，我们将介绍分布式应用架构的概念，并讨论运行分布式应用所需的各种模式和最佳实践。最后，我们将讨论在生产环境中运行此类应用所需满足的额外要求。

在本章中，我们将涵盖以下主题：

+   理解分布式应用架构

+   模式和最佳实践

+   在生产环境中运行

完成本章后，您将能够做到以下事情：

+   至少列出分布式应用架构的四个特征

+   列出需要在生产环境中实施的三到四种模式

# 理解分布式应用架构

在本节中，我们将解释当我们谈论分布式应用架构时的含义。首先，我们需要确保我们使用的所有单词或首字母缩写都有意义，并且我们都在说同样的语言。

# 定义术语

在本章和后续章节中，我们将谈论许多可能不为所有人熟悉的概念。为了确保我们都在说同样的语言，让我们简要介绍和描述这些概念或词语中最重要的：

| 术语 | 解释 |
| --- | --- |
| 虚拟机 | 虚拟机的缩写。这是一台虚拟计算机。 |
| 节点 | 用于运行应用程序的单个服务器。这可以是物理服务器，通常称为裸金属，也可以是虚拟机。可以是大型机、超级计算机、标准业务服务器，甚至是树莓派。节点可以是公司自己数据中心或云中的计算机。通常，节点是集群的一部分。 |
| 集群 | 由网络连接的节点组成，用于运行分布式应用。 |
| 网络 | 集群中各个节点之间的物理和软件定义的通信路径，以及在这些节点上运行的程序。 |
| 端口 | 应用程序（如 Web 服务器）监听传入请求的通道。 |
| 服务 | 不幸的是，这是一个非常负载的术语，它的真正含义取决于它所使用的上下文。如果我们在应用程序的上下文中使用术语*服务*，那么通常意味着这是一个实现了一组有限功能的软件，然后被应用程序的其他部分使用。随着我们在本书中的进展，将讨论具有稍微不同定义的其他类型的服务。 |

天真地说，分布式应用架构是单片应用架构的反义词，但首先看看这种单片架构也并非不合理。传统上，大多数业务应用都是以这种方式编写的，结果可以看作是一个单一的、紧密耦合的程序，运行在数据中心的某个命名服务器上。它的所有代码都被编译成一个单一的二进制文件，或者几个非常紧密耦合的二进制文件，在运行应用程序时需要共同定位。服务器，或者更一般的主机，应用程序运行的这一事实具有明确定义的名称或静态 IP 地址，在这种情况下也是重要的。让我们看下面的图表，更清楚地说明这种类型的应用架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/56242555-ab5b-4055-8cb5-e3e4b2e3f83f.png)单片应用架构

在前面的图表中，我们可以看到一个名为`blue-box-12a`的**服务器**，具有`172.52.13.44`的**IP**地址，运行一个名为`pet-shop`的应用程序，它是一个由主模块和几个紧密耦合的库组成的单片。

现在，让我们看一下以下的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/425c8d7b-efb8-48e3-8791-cb2d99ee8862.png)分布式应用架构

在这里，突然之间，我们不再只有一个命名的服务器；相反，我们有很多服务器，它们没有人类友好的名称，而是一些可以是类似于**通用唯一标识符**（**UUID**）的唯一 ID。突然之间，宠物商店应用程序也不再只是由一个单一的单片块组成，而是由许多相互作用但松散耦合的服务组成，例如**pet-api**、**pet-web**和**pet-inventory**。此外，每个服务在这个服务器或主机集群中运行多个实例。

你可能会想为什么我们在一本关于 Docker 容器的书中讨论这个问题，你问得对。虽然我们要调查的所有主题同样适用于容器尚未存在的世界，但重要的是要意识到，容器和容器编排引擎可以以更高效和直接的方式解决所有这些问题。在容器化的世界中，以前在分布式应用架构中很难解决的大多数问题变得相当简单。

# 模式和最佳实践

分布式应用架构具有许多引人注目的好处，但与单片应用架构相比，它也有一个非常重要的缺点——前者要复杂得多。为了控制这种复杂性，该行业提出了一些重要的最佳实践和模式。在接下来的章节中，我们将更详细地研究其中一些最重要的内容。

# 松散耦合的组件

解决复杂问题的最佳方法一直是将其分解为更易管理的较小子问题。举个例子，一步到位地建造一座房子将会非常复杂。将房子从简单的部件组合成最终结果会更容易。

同样适用于软件开发。如果我们将这个应用程序分解成相互协作并构成整体应用程序的较小组件，那么开发一个非常复杂的应用程序就会变得更容易。现在，如果这些组件之间的耦合度较低，那么单独开发这些组件就会变得更容易。这意味着组件 A 不会对组件 B 和 C 的内部工作做任何假设，而只关心它如何通过明确定义的接口与这两个组件进行通信。

如果每个组件都有一个明确定义且简单的公共接口，通过该接口与系统中的其他组件和外部世界进行通信，那么这将使我们能够单独开发每个组件，而不会对其他组件产生隐式依赖。在开发过程中，系统中的其他组件可以很容易地被存根或模拟替换，以便我们测试我们的组件。

# 有状态与无状态

每个有意义的业务应用程序都会创建、修改或使用数据。在 IT 中，数据的同义词是“状态”。创建或修改持久数据的应用服务称为有状态组件。典型的有状态组件是数据库服务或创建文件的服务。另一方面，不创建或修改持久数据的应用组件称为无状态组件。

在分布式应用架构中，无状态组件比有状态组件更容易处理。无状态组件可以轻松地进行扩展和缩减。此外，它们可以快速而轻松地在集群的完全不同节点上关闭和重新启动，因为它们与持久数据没有关联。

鉴于这一事实，有助于以大多数应用服务为无状态的方式设计系统。最好将所有有状态组件推到应用程序的边界并限制它们的数量。管理有状态组件很困难。

# 服务发现

构建应用程序时，通常由许多个体组件或相互通信的服务组成，我们需要一种机制，允许个体组件在集群中找到彼此。找到彼此通常意味着您需要知道目标组件在哪个节点上运行，以及它在哪个端口上监听通信。大多数情况下，节点由 IP 地址和端口标识，端口只是一个在明确定义范围内的数字。

从技术上讲，我们可以告诉想要与目标“服务 B”通信的“服务 A”，目标的 IP 地址和端口是什么。例如，这可以通过配置文件中的条目来实现。

组件是硬连线的

在单体应用程序的上下文中，这可能非常有效，该应用程序在一个或仅有几个知名和精心策划的服务器上运行，但在分布式应用程序架构中完全失效。首先，在这种情况下，我们有许多组件，手动跟踪它们变成了一场噩梦。这绝对不可扩展。此外，**服务 A**通常不应该或永远不会知道其他组件在集群的哪个节点上运行。它们的位置甚至可能不稳定，因为组件 B 可能由于应用程序外部的各种原因从节点 X 移动到另一个节点 Y。因此，我们需要另一种方式，**服务 A**可以找到**服务 B**，或者其他任何服务。最常用的是一个外部机构，它在任何给定时间都了解系统的拓扑结构。

这个外部机构或服务知道当前属于集群的所有节点和它们的 IP 地址；它知道所有正在运行的服务以及它们在哪里运行。通常，这种服务被称为**DNS 服务**，其中**DNS**代表**域名系统**。正如我们将看到的，Docker 实现了一个作为底层引擎的 DNS 服务。Kubernetes - 首要的容器编排系统，我们将在第十二章中讨论，*编排器* - 也使用**DNS 服务**来促进集群中运行的组件之间的通信。 

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3aa74eff-0e86-46e9-bb4b-dd356a97a816.png)组件咨询外部定位器服务

在前面的图表中，我们可以看到**服务 A**想要与**服务 B**通信，但它无法直接做到这一点。首先，它必须查询外部机构，一个注册表服务（这里称为**DNS 服务**），询问**服务 B**的下落。注册表服务将回答所请求的信息，并提供**服务 A**可以用来到达**服务 B**的 IP 地址和端口号。**服务 A**然后使用这些信息并与**服务 B**建立通信。当然，这只是一个关于低级别实际发生情况的天真图像，但它是一个帮助我们理解服务发现架构模式的好图像。

# 路由

路由是将数据包从源组件发送到目标组件的机制。路由被分类为不同类型。所谓的 OSI 模型（有关更多信息，请参阅本章的*进一步阅读*部分中的参考资料）用于区分不同类型的路由。在容器和容器编排的上下文中，第 2、3、4 和 7 层的路由是相关的。我们将在后续章节中更详细地讨论路由。在这里，让我们只说第 2 层路由是最低级别的路由类型，它将 MAC 地址连接到另一个 MAC 地址，而第 7 层路由，也称为应用级路由，是最高级别的路由。后者例如用于将具有目标标识符（即 URL）的请求路由到我们系统中的适当目标组件。

# 负载均衡

负载均衡在服务 A 需要与服务 B 通信时使用，比如在请求-响应模式中，但后者运行在多个实例中，如下图所示：

服务 A 的请求被负载均衡到服务 B

如果我们的系统中运行着多个服务 B 的实例，我们希望确保每个实例都被分配了相等的工作负载。这是一个通用的任务，这意味着我们不希望调用者进行负载均衡，而是希望一个外部服务拦截调用并决定将调用转发给目标服务实例的部分。这个外部服务被称为负载均衡器。负载均衡器可以使用不同的算法来决定如何将传入的调用分发给目标服务实例。最常用的算法称为轮询。这个算法只是以重复的方式分配请求，从实例 1 开始，然后是 2，直到实例 n。在最后一个实例被服务后，负载均衡器重新从实例 1 开始。

在前面的例子中，负载均衡器还有助于高可用性，因为来自服务 A 的请求将被转发到健康的服务 B 实例。负载均衡器还承担定期检查 B 的每个实例健康状况的角色。

# 防御性编程

在开发分布式应用程序的服务时，重要的是要记住这个服务不会是独立的，它依赖于其他应用程序服务，甚至依赖于第三方提供的外部服务，比如信用卡验证服务或股票信息服务，仅举两个例子。所有这些其他服务都是我们正在开发的服务的外部服务。我们无法控制它们的正确性或它们在任何给定时间的可用性。因此，在编码时，我们总是需要假设最坏的情况，并希望最好的结果。假设最坏的情况意味着我们必须明确处理潜在的故障。

# 重试

当外部服务可能暂时不可用或响应不够及时时，可以使用以下程序。当对其他服务的调用失败或超时时，调用代码应以一种结构化的方式进行，以便在短暂的等待时间后重复相同的调用。如果再次失败，下一次尝试前等待时间应稍长。应重复调用，直到达到最大次数，每次增加等待时间。之后，服务应放弃并提供降级服务，这可能意味着返回一些陈旧的缓存数据或根据情况根本不返回数据。

# 日志记录

对服务执行的重要操作应始终记录。日志信息需要分类，才能具有真正的价值。常见的分类列表包括调试、信息、警告、错误和致命。日志信息应由中央日志聚合服务收集，而不应存储在集群的单个节点上。聚合日志易于解析和过滤相关信息。这些信息对于快速定位由许多运行在生产环境中的移动部件组成的分布式系统中的故障或意外行为的根本原因至关重要。

# 错误处理

正如我们之前提到的，分布式应用程序中的每个应用服务都依赖于其他服务。作为开发人员，我们应该始终预料到最坏的情况，并采取适当的错误处理措施。最重要的最佳实践之一是快速失败。以这样的方式编写服务，使得不可恢复的错误尽早被发现，如果检测到这样的错误，立即使服务失败。但不要忘记记录有意义的信息到`STDERR`或`STDOUT`，以便开发人员或系统操作员以后可以用来跟踪系统的故障。同时，向调用者返回有用的错误信息，尽可能准确地指出调用失败的原因。

快速失败的一个示例是始终检查调用者提供的输入值。这些值是否在预期范围内并且完整？如果不是，那么不要尝试继续处理；而是立即中止操作。

# 冗余

一个使命关键的系统必须全天候、全年无休地可用。停机是不可接受的，因为它可能导致公司机会或声誉的巨大损失。在高度分布式的应用程序中，至少有一个涉及的组件失败的可能性是不可忽视的。我们可以说问题不在于一个组件是否会失败，而在于失败将在何时发生。

为了避免系统中的许多组件之一出现故障时停机，系统的每个单独部分都需要是冗余的。这包括应用程序组件以及所有基础设施部分。这意味着，如果我们的应用程序中有一个支付服务，那么我们需要冗余地运行这个服务。最简单的方法是在集群的不同节点上运行这个服务的多个实例。同样，对于边缘路由器或负载均衡器也是如此。我们不能承受它出现故障的风险。因此，路由器或负载均衡器必须是冗余的。

# 健康检查

我们已经多次提到，在分布式应用程序架构中，由于其许多部分，单个组件的故障是非常可能的，而且只是时间问题。因此，我们将系统的每个单个组件都运行冗余。代理服务然后在服务的各个实例之间平衡流量。

但现在，又出现了另一个问题。代理或路由器如何知道某个服务实例是否可用？它可能已经崩溃或者无响应。为了解决这个问题，我们可以使用所谓的健康检查。代理或代理的其他系统服务定期轮询所有服务实例并检查它们的健康状况。基本上问题是，你还在吗？你健康吗？对每个服务的答案要么是是，要么是否，或者如果实例不再响应，则健康检查超时。

如果组件回答“否”或发生超时，那么系统将终止相应的实例并在其位置上启动一个新的实例。如果所有这些都是以完全自动化的方式发生的，那么我们可以说我们有一个自愈系统。

代理定期轮询组件的状态的责任可以被转移。组件也可以被要求定期向代理发送活动信号。如果一个组件在预定义的延长时间内未能发送活动信号，就被认为是不健康或已死亡。

有时候，上述的任一方式更为合适。

# 断路器模式

断路器是一种机制，用于避免分布式应用因许多重要组件的级联故障而崩溃。断路器有助于避免一个故障组件以多米诺效应拖垮其他依赖服务。就像电气系统中的断路器一样，它通过切断电源线来保护房屋免受由于插入式设备故障而导致的火灾，分布式应用中的断路器在**服务 A**到**服务 B**的连接中断，如果后者没有响应或者发生故障。

这可以通过将受保护的服务调用包装在断路器对象中来实现。该对象监视故障。一旦故障次数达到一定阈值，断路器就会跳闸。所有随后对断路器的调用都将返回错误，而根本不会进行受保护的调用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7f511703-df7b-4e5c-af03-f8fc19876a73.png)断路器模式

在前面的图表中，我们有一个断路器，在调用**服务 B**时收到第二个超时后会跳闸。

# 在生产中运行

要成功地在生产环境中运行分布式应用程序，我们需要考虑在前面部分介绍的最佳实践和模式之外的一些方面。一个特定的领域是内省和监控。让我们详细介绍最重要的方面。

# 日志记录

一旦分布式应用程序投入生产，就不可能进行实时调试。但是我们如何找出应用程序故障的根本原因呢？解决这个问题的方法是应用程序在运行时产生丰富而有意义的日志信息。开发人员需要以这样的方式对其应用程序服务进行工具化，以便输出有用的信息，例如发生错误时或遇到潜在的意外或不需要的情况时。通常，这些信息输出到`STDOUT`和`STDERR`，然后由系统守护进程收集并将信息写入本地文件或转发到中央日志聚合服务。

如果日志中有足够的信息，开发人员可以使用这些日志来追踪系统中错误的根本原因。

在分布式应用程序架构中，由于其许多组件，日志记录甚至比在单体应用程序中更为重要。单个请求通过应用程序的所有组件的执行路径可能非常复杂。还要记住，这些组件分布在一个节点集群中。因此，记录所有重要信息并向每个日志条目添加诸如发生时间、发生组件和运行组件的节点等信息是有意义的。此外，日志信息应聚合在一个中央位置，以便开发人员和系统操作员可以进行分析。

# 跟踪

跟踪用于查找单个请求如何通过分布式应用程序进行传递，以及请求总共花费多少时间以及每个单独组件的时间。如果收集了这些信息，可以将其用作显示系统行为和健康状况的仪表板的信息源之一。

# 监控

运维工程师喜欢有仪表板，显示系统的关键指标，让他们一目了然地了解应用程序的整体健康状况。这些指标可以是非功能指标，如内存和 CPU 使用情况，系统或应用程序组件的崩溃次数，节点的健康状况，以及功能和因此特定于应用程序的指标，如订单系统中的结账次数或库存服务中缺货商品的数量。

大多数情况下，用于聚合仪表板使用的基础数据是从日志信息中提取的。这可以是系统日志，主要用于非功能指标，或者应用程序级别的日志，用于功能指标。

# 应用程序更新

公司的竞争优势之一是能够及时对不断变化的市场情况做出反应。其中一部分是能够快速调整应用程序以满足新的和变化的需求，或者添加新的功能。我们更新应用程序的速度越快，越好。如今，许多公司每天都会推出新的或更改的功能多次。

由于应用程序更新频繁，这些更新必须是非中断的。在升级时，我们不能允许系统进行维护而停机。所有这些都必须无缝、透明地进行。

# 滚动更新

更新应用程序或应用程序服务的一种方法是使用滚动更新。这里的假设是需要更新的特定软件运行在多个实例中。只有在这种情况下，我们才能使用这种类型的更新。

系统停止当前服务的一个实例，并用新服务的实例替换它。一旦新实例准备就绪，它将提供流量服务。通常，新实例会被监视一段时间，以查看它是否按预期工作，如果是，那么当前服务的下一个实例将被关闭并替换为新实例。这种模式重复进行，直到所有服务实例都被替换。

由于总是有一些实例在任何给定时间运行，当前或新的，应用程序始终处于运行状态。不需要停机时间。

# 蓝绿部署

在蓝绿部署中，应用服务的**当前**版本称为**蓝色**，处理所有应用流量。然后我们在生产系统上安装应用服务的新版本，称为**绿色**。新服务尚未与其余应用程序连接。

一旦安装了**绿色**，我们可以对这项新服务执行**烟雾测试**，如果测试成功，路由器可以配置为将以前发送到**蓝色**的所有流量引导到新服务**绿色**。然后密切观察**绿色**的行为，如果所有成功标准都得到满足，**蓝色**可以被废弃。但是，如果由于某种原因**绿色**显示出一些意外或不需要的行为，路由器可以重新配置以将所有流量返回到蓝色。然后可以移除绿色并修复，然后可以使用修正版本执行新的蓝绿部署：

蓝绿部署

接下来，让我们看看金丝雀发布。

# 金丝雀发布

金丝雀发布是指在系统中并行安装当前版本的应用服务和新版本的发布。因此，它们类似于蓝绿部署。起初，所有流量仍然通过当前版本路由。然后我们配置路由器，使其将整体流量的一小部分，比如 1%，引导到应用服务的新版本。随后，密切监视新服务的行为，以找出它是否按预期工作。如果满足了所有成功标准，那么就配置路由器，使其通过新服务引导更多的流量，比如这次是 5%。再次密切监视新服务的行为，如果成功，就会将更多的流量引导到它，直到达到 100%。一旦所有流量都被引导到新服务，并且它已经稳定了一段时间，旧版本的服务就可以被废弃。

为什么我们称之为金丝雀发布？这是以煤矿工人为名，他们会在矿井中使用金丝雀作为早期警报系统。金丝雀对有毒气体特别敏感，如果这样的金丝雀死亡，矿工们就知道他们必须立即离开矿井。

# 不可逆的数据更改

如果我们的更新过程中包括在我们的状态中执行不可逆转的更改，比如在支持关系数据库中执行不可逆转的模式更改，那么我们需要特别小心处理这个问题。如果我们采用正确的方法，就可以在没有停机时间的情况下执行这些更改。重要的是要认识到，在这种情况下，我们不能同时部署需要新数据结构的代码更改和数据更改。相反，整个更新必须分为三个不同的步骤。在第一步中，我们推出一个向后兼容的模式和数据更改。如果这成功了，那么我们在第二步中推出新代码。同样，如果这成功了，我们在第三步中清理模式并删除向后兼容性：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/987dac84-2498-490e-af50-2f9bb870d341.png)推出不可逆转的数据或模式更改

前面的图表显示了数据及其结构的更新，然后是应用程序代码的更新，最后，在第三步中，数据和数据结构是如何清理的。

# 回滚

如果我们的应用服务在生产中运行并经常更新，迟早会出现其中一个更新的问题。也许开发人员在修复错误时引入了一个新错误，这个错误没有被所有自动化测试和可能的手动测试捕捉到，因此应用程序表现异常，迫切需要将服务回滚到之前的良好版本。在这方面，回滚是从灾难中恢复。

同样，在分布式应用程序架构中，问题不是是否会需要回滚，而是何时需要回滚。因此，我们必须确保我们始终可以回滚到我们应用程序中组成的任何服务的先前版本。回滚不能是事后想到的，它们必须是我们部署过程中经过测试和证明的一部分。

如果我们正在使用蓝绿部署来更新我们的服务，那么回滚应该是相当简单的。我们所需要做的就是将路由器从新的绿色版本的服务切换回之前的蓝色版本。

# 总结

在本章中，我们了解了分布式应用程序架构是什么，以及哪些模式和最佳实践对于成功运行分布式应用程序是有帮助或需要的。最后，我们讨论了在生产中运行这样的应用程序还需要什么。

在下一章中，我们将深入讨论仅限于单个主机的网络。我们将讨论同一主机上的容器如何相互通信，以及外部客户端如何在必要时访问容器化应用程序。

# 问题

请回答以下问题，以评估您对本章内容的理解：

1.  分布式应用架构中的每个部分何时何地需要冗余？用几句话解释。

1.  为什么我们需要 DNS 服务？用三到五句话解释。

1.  什么是断路器，为什么需要它？

1.  单体应用程序和分布式或多服务应用程序之间的一些重要区别是什么？

1.  什么是蓝绿部署？

# 进一步阅读

以下文章提供了关于本章内容的更深入信息：

+   断路器：[`bit.ly/1NU1sgW`](https://bit.ly/2pBENyP)

+   OSI 模型解释：[`bit.ly/1UCcvMt`](https://bit.ly/2BIRpJY)

+   蓝绿部署：[`bit.ly/2r2IxNJ`](http://bit.ly/2r2IxNJ)
