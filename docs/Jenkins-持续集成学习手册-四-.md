# Jenkins 持续集成学习手册（四）

> 原文：[`zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17`](https://zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Jenkins 进行持续交付

我们将从一个覆盖以下领域的持续交付设计开始本章：

+   分支策略

+   持续交付工具列表

+   一个 Jenkins 流水线结构

**持续交付**（**CD**）设计将作为一个蓝图，指导读者回答 CD 的如何、为什么和在哪里实施的问题。设计将涵盖实施端到端 CD 流水线所涉及的所有必要步骤。

在本章讨论的 CD 设计应被视为实施 CD 的模板，而不是一个完整和最终的模型。所有使用的工具都可以修改和替换以适应目的。

# Jenkins CD 设计

在这一节中，我们将介绍一个非常通用的 CD 设计。

# 分支策略

在第七章 *Jenkins 使用持续集成* 中，我们遵循了以下的分支策略：

+   主分支

+   集成分支

+   功能分支

这个分支策略是 *GitFlow 工作流* 分支模型的一个精简版。

虽然 CI 可以在集成/开发分支或功能分支上执行，但 CD 只在集成和发布分支上执行。

# 发布分支

一些团队采用有发布分支的策略。发布分支是在成功测试的代码从主分支中发布到生产环境（分发给客户）后创建的。创建发布分支的目的是支持对相应发布的错误修复：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/37e7abda-0552-457b-a75c-a61fceddf129.png)

分支策略

# CD 流水线

我们现在来到了 CD 设计的核心。我们不会创建一个新的流水线；相反，我们将在 Jenkins 中基于现有的 CI 多分支流水线上构建。新的 CD 流水线将包括以下阶段：

1.  在推送事件（CI 流水线的初始化）上从**版本控制系统**（**VCS**）获取代码。

1.  构建和单元测试代码；在 Jenkins 上发布单元测试报告。

1.  对代码进行静态代码分析并将结果上传到 SonarQube。如果错误数量超过质量门限定义的阈值，则流水线失败。

1.  执行集成测试；在 Jenkins 上发布单元测试报告。

1.  将构建好的产物与一些有意义的属性一起上传到 Artifactory。

1.  将二进制文件部署到测试环境。

1.  执行测试（质量分析）。

1.  推广解决方案到 Artifactory 并将其标记为发布候选版本。

上述 CD 流水线的目的是自动化持续部署、测试（QA）并推动构建产物到二进制存储库的过程。每个步骤都会报告失败/成功。让我们详细讨论这些流水线及其组成部分。

在现实世界中，QA 可能包含多个测试阶段，例如性能测试、用户验收测试、组件测试等。为了简化问题，我们将在示例 CD 流水线中仅执行性能测试。

# CD 工具集

我们正在实施 CI 的示例项目是一个简单的 Maven 项目。因此，我们将看到 Jenkins 与许多其他工具密切配合。

以下表格包含我们将要看到的所有工具和技术的列表：

| **工具/技术** | **描述** |
| --- | --- |
| Java | 主要用于编码的编程语言 |
| Maven | 构建工具 |
| JUnit | 单元测试和集成测试工具 |
| Jenkins | CI 工具 |
| GitHub | 版本控制系统 |
| SonarQube | 静态代码分析工具 |
| Artifactory | 二进制仓库管理器 |
| Apache Tomcat | 用于托管解决方案的应用服务器 |
| Apache JMeter | 性能测试工具 |

# 创建 Docker 镜像 - 性能测试

在本节中，我们将为我们的**性能测试**（**PT**）创建一个 Docker 镜像。这个 Docker 镜像将被 Jenkins 用来创建 Docker 容器，在其中我们将部署我们构建的解决方案并执行我们的性能测试。按照以下步骤进行：

1.  登录到您的 Docker 服务器。执行以下命令以检查可用的 Docker 镜像：

```
 sudo docker images
```

1.  从以下截图中，您可以看到我已经在我的 Docker 服务器上有三个 Docker 镜像（`ubuntu`、`hello-world` 和 `maven-build-slave-0.1`）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/cd806558-9290-422f-843b-89af36ee38a2.png)

列出 Docker 镜像

1.  我们将使用 Ubuntu Docker 镜像构建一个新的 Docker 镜像来运行我们的 PT。

1.  让我们升级我们的 Ubuntu Docker 镜像，添加我们运行测试所需的所有必要应用程序，如下所示：

    +   Java JDK（最新版）

    +   Apache Tomcat（8.5）

    +   Apache JMeter

    +   用于登录 Docker 容器的用户账号

    +   OpenSSH 守护程序（接受 SSH 连接）

    +   Curl

1.  执行以下命令以使用 Ubuntu Docker 镜像运行 Docker 容器。这将创建一个容器并打开其 bash shell：

```
sudo docker run -i -t ubuntu /bin/bash
```

1.  现在，安装所有所需的应用程序，就像您在任何普通的 Ubuntu 机器上做的一样。让我们从创建一个`jenkins`用户开始：

    1.  执行以下命令，并按照以下所示的用户创建步骤进行：

```
adduser jenkins
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/f509ecad-31db-44c1-9812-d40924045d39.png)

创建用户

1.  1.  使用切换用户命令检查新用户：

```
su jenkins
```

1.  输入`exit`切换回`root`用户。

1.  接下来，我们将安装 SSH 服务器。按照以下命令的顺序执行：

```
apt-get update 
apt-get install openssh-server 
mkdir /var/run/sshd 
```

1.  按照以下步骤安装 Java：

    1.  更新软件包索引：

```
apt-get update
```

1.  1.  接下来，安装 Java。执行以下命令将安装**Java 运行时环境**（**JRE**）：

```
apt-get install default-jre
```

1.  安装 Tomcat 8.5 的最佳方法是下载最新的二进制版本，然后手动配置它：

    1.  移动到 `/tmp` 目录，并下载 Apache Tomcat 8.5，使用以下命令：

```
cd /tmp 
wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.11/bin/apache-tomcat-8.5.11.tar.gz
```

1.  1.  我们将在 `home/jenkins/` 目录中安装 Tomcat。为此，请首先切换到 `jenkins` 用户。在 `/home/jenkins/` 中创建一个 `tomcat` 目录：

```
su jenkins 
mkdir /home/jenkins/tomcat
```

1.  1.  然后将存档解压到其中：

```
tar xzvf apache-tomcat-8*tar.gz \
-C /home/jenkins/tomcat --strip-components=1
```

1.  输入 `exit` 切换回 `root` 用户。

1.  Apache JMeter 是执行性能测试的好工具。它是免费和开源的。它可以在 GUI 和命令行模式下运行，这使其成为自动化性能测试的合适选择：

    1.  切换到 `/tmp` 目录：

```
cd /tmp
```

1.  1.  从 [`jmeter.apache.org/download_jmeter.cgi`](http://jmeter.apache.org/download_jmeter.cgi) 下载 `apache-jmeter-3.1.tgz`，或者是最新的稳定版本：

```
wget https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-3.1.tgz
```

1.  1.  我们将 JMeter 安装在 `opt/jmeter/` 目录中。为此，请在 `/opt` 中创建一个 `jmeter` 目录：

```
mkdir /opt/jmeter
```

1.  1.  然后将存档解压到 `/opt/jmeter/` 目录，并为其分配适当的权限：

```
tar xzvf apache-jmeter-3*.tgz \
-C /opt/jmeter --strip-components=1
 chown -R jenkins:jenkins /opt/jmeter/
 chmod -R 777 /opt/jmeter/
```

1.  按照给定步骤安装 `curl`：

```
apt-get install curl
```

1.  按照给定的步骤保存我们对 Docker 镜像所做的所有更改：

    1.  输入 `exit` 退出容器。

    1.  我们需要保存（`commit`）我们对 Docker 容器所做的所有更改。

    1.  通过列出所有非活动容器，获取我们最近使用的容器的 `CONTAINER ID`，如下屏幕截图中在命令之后所示：

```
sudo docker ps -a
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/326c64cd-d3bf-4fa2-8020-d8731154e286.png)

列出非活动容器

1.  1.  注意 `CONTAINER ID`，并执行以下命令保存（`commit`）我们对容器所做的更改：

```
sudo docker commit <CONTAINER ID> <new name for the container>
```

1.  1.  我已将我的容器命名为 `performance-test-agent-0.1`，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/62e687de-76e9-4bab-991c-729c89603e8c.png)

Docker commit 命令

1.  1.  提交更改后，将创建一个新的 Docker 镜像。

1.  1.  执行以下 `docker` 命令以列出镜像，如下屏幕截图中在命令之后所示：

```
sudo docker images
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/4e968dab-db63-4073-aedd-8995d881c7ec.png)

列出 Docker 镜像

1.  1.  您可以看到我们的新 Docker 镜像，名称为 `performance-test-agent-0.1`。我们现在将配置我们的 Jenkins 服务器使用 `performance-test-agent-0.1` Docker 镜像来创建 Jenkins 从节点（构建代理）。

# 在 Jenkins 中添加 Docker 容器凭据

按照给定的步骤在 Jenkins 中添加凭据，以允许其与 Docker 通信：

1.  从 Jenkins 仪表板导航到**凭据** | **系统** | **全局凭据（不受限制）**。

1.  单击左侧菜单上的**添加凭据**链接以创建新的凭据（参见以下屏幕截图）。

1.  选择**类型**为**用户名与密码**。

1.  将**范围**字段保留为其默认值。

1.  在**用户名**字段下为您的 Docker 镜像（按照我们的示例，为 `jenkins`）添加一个用户名。

1.  在**密码**字段下面添加密码。

1.  在**ID**字段下添加一个 ID，并在**描述**字段下添加描述。

1.  完成后，单击**OK**按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/47b38548-a70f-4df2-8ca8-25e3525af551.png)

在 Jenkins 内创建凭据

# 更新 Jenkins 内的 Docker 设置

按照给定的步骤更新 Jenkins 内的 Docker 设置：

1.  从 Jenkins 仪表板中，点击**管理 Jenkins** | **配置系统**。

1.  滚动到**云**部分的底部。

1.  在 Cloud 部分下，点击**添加 Docker 模板**按钮，然后选择**Docker 模板**。

1.  你将看到很多要配置的设置（参见下面的截图）。然而，为了保持这个演示简单，让我们坚持重要的设置。

1.  在**Docker 镜像**字段下，输入我们之前创建的 Docker 镜像的名称。在我的情况下，它是`performance-test-agent-0.1`。

1.  在**标签**字段下，添加一个标签。使用此标签，您的 Jenkins 管道将识别 Docker 容器。我添加了`docker_pt`标签。

1.  **启动方法**应为 Docker SSH 计算机启动器。

1.  在**凭据**字段下，选择我们创建的用于访问 Docker 容器的凭据。

1.  确保拉取策略选项设置为永不拉取。

1.  将其余选项保持为默认值。

1.  完成后，点击**应用**，然后点击**保存**：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/792f399f-263f-45c0-98b2-8431a6e73315.png)

为集成测试创建 Docker 模板

# 使用 JMeter 创建性能测试

在本节中，我们将学习如何使用 JMeter 工具创建一个简单的性能测试。所述步骤应在您的本地机器上执行。以下步骤在具有 Ubuntu 16.04 的机器上执行。

# 安装 Java

按照给定步骤安装 Java：

1.  更新软件包索引：

```
sudo apt-get update
```

1.  接下来，安装 Java。以下命令将安装 JRE：

```
sudo apt-get install default-jre
```

1.  要设置`JAVA_HOME`环境变量，首先获取 Java 安装位置。通过执行以下命令来执行此操作：

```
sudo update-alternatives --config java
```

1.  复制结果路径并更新`/etc/environment`文件中的`JAVA_HOME`变量。

# 安装 Apache JMeter

按照给定步骤安装 Apache JMeter：

1.  进入`/tmp`目录：

```
cd /tmp
```

1.  从[`jmeter.apache.org/download_jmeter.cgi`](http://jmeter.apache.org/download_jmeter.cgi)下载`apache-jmeter-3.1.tgz`，或者是最新的稳定版本：

```
wget https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-3.1.tgz
```

1.  我们将在`/opt`目录下安装 JMeter。为此，在`/opt`内创建一个`jmeter`目录：

```
mkdir /opt/jmeter
```

1.  然后将归档文件解压到其中：

```
tar xzvf apache-jmeter-3*.tgz \
-C /opt/jmeter --strip-components=1
```

# 启动 JMeter

按照给定步骤启动 JMeter：

1.  要启动 JMeter，请移动到 JMeter 安装目录并运行`jmeter.sh`脚本，使用以下命令：

```
cd /opt/jmeter/bin 
./jmeter.sh
```

1.  JMeter GUI 实用程序将在一个新窗口中打开。

# 创建性能测试用例

默认情况下，您将看到一个示例测试计划。我们将通过修改现有模板来创建一个新的测试计划：

1.  将测试计划重命名为`Hello_World_Test_Plan`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a956195c-a5df-4d44-915a-e6d07b529020.png)

创建测试计划

1.  点击菜单项中的保存按钮或点击*Ctrl* + *S*，将其保存在`examples`文件夹内，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7b1dafe8-34ef-48f6-a714-94b9fde90f54.png)

保存测试计划

# 创建一个线程组

按照给定步骤创建一个线程组：

1.  添加一个线程组。要这样做，请右键单击`Hello_World_Test_Plan`，然后选择**添加** | **线程（用户）** | **线程组**：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/141ed30d-e9c4-4c9e-99b4-aaddef0ec338.png)

创建一个线程组

1.  在生成的页面中，为你的线程组命名并填写以下选项：

    1.  选择**继续**以进行 **采样器错误后要执行的操作**。

    1.  将**线程数（用户）**添加为`1`。

    1.  将**上升时间（秒）**添加为`1`。

    1.  将**循环次数**添加为`1`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a53d3e48-1049-44b7-9afd-f6af7bddaf20.png)

配置一个线程组

# 创建一个采样器

按照给定步骤创建一个采样器：

1.  右键单击`Hello_World_Test_Plan`，然后选择**添加** | **采样器** | **HTTP 请求**：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6b05ed69-1771-48e8-a77b-e3ec50e0dae7.png)

添加一个采样器

1.  适当命名 HTTP 请求并填写以下选项：

    1.  将**服务器名称或 IP**添加为`<您的测试服务器机器的 IP 地址>`。

    1.  添加端口号为`8080`。

    1.  将**路径**添加为`/hello.0.0.1/`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/bf85ab3c-ee78-483f-930b-00c251dbadfc.png)

配置采样器

# 添加一个监听器

按照给定步骤添加一个监听器：

1.  右键单击`Hello_World_Test_Plan`，然后选择**添加** | **监听器** | **查看结果树**：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5b778cfb-8997-45e4-a40b-912e5322b473.png)

添加一个监听器

1.  什么都不做；将所有字段保持原样。

1.  点击菜单项中的保存按钮或点击*Ctrl* + *S*保存整个配置。

1.  从`/opt/jmeter/bin/examples`*.*复制`.jmx`文件。

1.  在你的 Maven 项目下，创建一个名为`pt`的文件夹，在`src`目录中，并将`.jmx`文件放入其中。

1.  将代码上传到 GitHub。

# **CD 管道**

我们拥有所有必需的工具，Docker 镜像已准备就绪。在本节中，我们将在 Jenkins 中创建一个管道，描述我们的 CD 过程。

# 为 CD 编写 Jenkinsfile

我们将在之前创建的 CI 管道基础上进行。让我们首先重新审视我们的 CI 管道，然后我们将作为 CD 过程的一部分添加一些新的阶段。

# 重新审视 CI 管道的代码

以下是作为 CI 的一部分的完整组合代码：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project
    -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
          "pattern": "target/hello-0.0.1.war",
          "target": "example-project/${BUILD_NUMBER}/",
          "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
}
```

# 用于存储构建产物的管道代码

Jenkins 管道使用称为 `stash` 的功能在节点之间传递构建产物。在接下来的步骤中，我们将 `stash` 一些希望传递到`docker_pt`节点的构建产物：

```
stash includes: 'target/hello-0.0.1.war,src/pt/Hello_World_Test_Plan.jmx', name: 'binary'
```

在上述代码中：

+   `name`：存储的名称

+   `includes`：要包含的逗号分隔文件

# 生成一个 Docker 容器 - 性能测试

首先，让我们创建一个管道代码，该代码将使用`performance-test-agent-0.1` Docker 镜像为性能测试创建一个 Docker 容器（Jenkins 从节点）：

```
node('docker_pt') {
}
```

其中`docker_pt`是`performance-test-agent-0.1` Docker 模板的标签。

我们想要在`docker_pt`节点上执行以下任务：

1.  启动 Tomcat。

1.  将构建产物部署到测试环境上的 Tomcat。

1.  执行性能测试。

1.  在 Artifactory 中提升构建工件。

所有前述任务都是我们 CD 管道的各个阶段。让我们为每一个阶段编写管道代码。

# 启动 Apache Tomcat 的管道代码

在性能测试代理上启动 Apache Tomcat 的管道代码是一个简单的 shell 脚本，将运行 Tomcat 安装目录中存在的 `./startup.sh` 脚本：

```
sh '''cd /home/jenkins/tomcat/bin
./startup.sh''';
```

将上述步骤包装在名为 `启动 Tomcat` 的 `stage` 中：

```
stage ('Start Tomcat'){
    sh '''cd /home/jenkins/tomcat/bin
    ./startup.sh''';
}
```

# 部署构建工件的管道代码

部署构建工件的管道代码分为两个步骤。首先，我们将从上一个节点 Docker 块中存储的二进制包取出。然后，我们将未存储的文件部署到我们的测试环境中 Tomcat 安装目录下的 `webapps` 文件夹中。代码如下：

```
unstash 'binary'
sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
```

将上述步骤包装在名为 `部署` 的 `stage` 中：

```
stage ('Deploy){
    unstash 'binary'
    sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
}
```

# 运行性能测试的管道代码

执行性能测试的管道代码是一个简单的 shell 脚本，调用 `jmeter.sh` 脚本并将 `.jmx` 文件传递给它。测试结果存储在一个 `.jtl` 文件中，然后进行归档。代码如下：

```
sh '''cd /opt/jmeter/bin/
./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l $WORKSPACE/test_report.jtl''';

step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
```

以下表格给出了上述代码片段的描述：

| **代码** | **描述** |
| --- | --- |
| `./jmeter.sh -n -t <.jmx 文件的路径> -l <保存 .jtl 文件的路径>` | 这是执行性能测试计划（`.jmx` 文件）并生成测试结果（`.jtl` 文件）的 `jmeter` 命令。 |
| `step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])` | 此行代码将归档所有扩展名为 `.jtl` 的文件。 |

将上一步包装在名为 `性能测试` 的 `stage` 中：

```
stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
}
```

# 在 Artifactory 中提升构建工件的管道代码

我们将在 Artifactory 中提升构建工件的方式是使用属性（键值对）功能。所有通过性能测试的构建都将应用一个 `Performance-Tested=Yes` 标签。代码如下：

```
withCredentials([usernameColonPassword(credentialsId: 'artifactory-account', variable: 'credentials')]) {
    sh 'curl -u${credentials} -X PUT "http://172.17.8.108:8081/artifactory/api/storage/example-project/${BUILD_NUMBER}/hello-0.0.1.war?properties=Performance-Tested=Yes"';
}
```

以下表格给出了上述代码片段的描述：

| **代码** | **描述** |
| --- | --- |
| `withCredentials([usernameColonPassword(credentialsId: 'artifactory-account', variable: 'credentials')]) {``}` | 我们在 Jenkins 中使用 `withCredentials` 插件将 Artifactory 凭据传递给 `curl` 命令。 |
| `curl -u<用户名>:密码 -X PUT "<artifactory 服务器 URL>/api/storage/<artifactory 存储库名称>?properties=key-value"` | 这是更新 Artifactory 中构建工件属性（键值对）的 `curl` 命令。`curl` 命令利用了 Artifactory 的 REST API 功能。 |

将上一步包装在名为 `在 Artifactory 中提升构建` 的 `stage` 中：

```
stage ('Promote build in Artifactory'){
    withCredentials([usernameColonPassword(credentialsId: 'artifactory-account', variable: 'credentials')]) {
        sh 'curl -u${credentials} -X PUT "http://172.17.8.108:8081/artifactory/api/storage/example-project/${BUILD_NUMBER}/hello-0.0.1.war?properties=Performance-Tested=Yes"';
    }
}
```

# 组合 CD 管道代码

以下是完整的组合代码，将在 `docker_pt` 节点中运行：

```
node('docker_pt') {
  stage ('Start Tomcat'){
    sh '''cd /home/jenkins/tomcat/bin
    ./startup.sh''';
  }
  stage ('Deploy '){
    unstash 'binary'
    sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
  }
  stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l
    $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
  }
  stage ('Promote build in Artifactory'){
    withCredentials([usernameColonPassword(credentialsId:
      'artifactory-account', variable: 'credentials')]) {
        sh 'curl -u${credentials} -X PUT
        "http://172.17.8.108:8081/artifactory/api/storage/example-project/
        ${BUILD_NUMBER}/hello-0.0.1.war?properties=Performance-Tested=Yes"';
      }
  }
}
```

让我们将上述代码与 CI 的管道代码结合起来，得到完整的 CD 管道代码，如下所示：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
          "pattern": "target/hello-0.0.1.war",
          "target": "example-project/${BUILD_NUMBER}/",
          "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
  stash includes: 'target/hello-0.0.1.war,src/pt/Hello_World_Test_Plan.jmx',
  name: 'binary'
}
node('docker_pt') {
  stage ('Start Tomcat'){
    sh '''cd /home/jenkins/tomcat/bin
    ./startup.sh''';
  }
  stage ('Deploy '){
    unstash 'binary'
    sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
  }
  stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l
    $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
  }
  stage ('Promote build in Artifactory'){
    withCredentials([usernameColonPassword(credentialsId:
      'artifactory-account', variable: 'credentials')]) {
        sh 'curl -u${credentials} -X PUT
        "http://172.17.8.108:8081/artifactory/api/storage/example-project/
        ${BUILD_NUMBER}/hello-0.0.1.war?properties=Performance-Tested=Yes"';
      }
  }
}
```

# CD 运行情况

在您的 GitHub 代码上进行一些更改，或者仅从 Jenkins 仪表板触发 Jenkins 流水线：

1.  登录到 Jenkins，并从 Jenkins 仪表板单击您的 Multibranch Pipeline。您应该会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/254111d5-9f2e-4f30-9332-c02d289e5f0b.png)

Jenkins CD 流水线实践

1.  登录到 Artifactory 服务器，查看代码是否已使用下列属性上传和推广：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/2e2b9422-cd5c-4416-b89b-a217114f070f.png)

构建产物正在 Artifactory 中推广

1.  让我们在 Jenkins Blue Ocean 中看看我们的 CD 流水线。要做到这一点，请导航到您的 Jenkins Multibranch CD 流水线（<`Jenkins URL>/job/<Jenkins multibranch pipeline name>/`）。

1.  在流水线页面上，单击左侧菜单中的 Open Blue Ocean 链接。

1.  您将被带到 Blue Ocean 中的 Multibranch Pipeline 页面，如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d9717ae3-3dd7-4a38-bf60-9a40464a1d42.png)

1.  单击主分支以查看其流水线。您应该会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/83069db0-08c4-4210-8b28-c951e83858ec.png)

# 总结

在本章中，我们学习了如何创建一个端到端的 CD 流水线，在推送事件上触发，执行构建、静态代码分析和集成测试，将成功测试的二进制产物上传到 Artifactory，部署代码到测试环境，执行一些自动化测试，并在 Artifactory 中推广二进制产物。

书中讨论的 CD 设计可以修改以满足任何类型项目的需求。用户只需识别可以与 Jenkins 配合使用的正确工具和配置。

在下一章中，我们将学习有关持续部署的内容，它与持续交付有何不同，以及更多。


# 第九章：使用 Jenkins 进行持续部署

本章首先定义和解释了持续部署。我们还将尝试区分持续部署和持续交付。持续部署是持续交付流水线的一个简单、微调版本。因此，我们不会看到任何主要的 Jenkins 配置更改或任何新工具。

本章将涵盖以下主题：

+   创建一个生产服务器

+   在生产服务器上安装 Jenkins 从属节点

+   创建一个 Jenkins 持续部署流水线

+   持续交付的实施

# 什么是持续部署？

将生产就绪特性持续部署到生产环境或最终用户的过程称为**持续部署**。

从整体上看，持续部署意味着，*使生产就绪的特性立即上线，无需任何干预*。这包括以敏捷方式构建特性、持续集成和测试，并将其部署到生产环境中，而无需任何中断。

持续部署从字面上讲意味着，*在任何给定环境中持续部署任何给定包的任务*。因此，将包部署到测试服务器和生产服务器的任务传达了持续部署的字面意义。

# 持续部署与持续交付的区别

首先，特性被开发，然后它们经历一个循环，或持续集成，或各种测试。任何通过各种测试的东西都被视为生产就绪的特性。然后，这些生产就绪的特性被标记为 Artifactory（本书未显示）中的标签，或者被保持分开，以将它们与非生产就绪的特性区分开。

这类似于制造生产线。原始产品经历修改和测试阶段。最终，成品被包装并存放在仓库中。根据订单，从仓库发货到各个地方。产品在包装后不会立即发货。

我们可以安全地称这种实践为持续交付。以下插图描述了**持续交付**的生命周期：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/00f3b49d-a8dc-401f-8462-5540e3faed4e.png)

持续交付流水线

另一方面，**持续部署**的生命周期看起来有些如下所示。部署阶段是立即进行的，没有任何中断。生产就绪的特性立即部署到生产环境：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6d1df560-8ff6-4bce-9cc9-fac015f8c960.png)

持续部署流水线

# 谁需要持续部署？

人们可能会心里想着以下几个问题：*我如何在我的组织中实现持续部署*，*可能会面临什么挑战*，*需要多少测试来进行并自动化*？问题不胜枚举。

然而，技术挑战只是一方面。更重要的是要决定我们是否真的需要它。我们真的需要持续部署吗？

答案是，*并不总是以及不完全是每种情况*。因为从我们对持续部署的定义以及前一个主题的理解来看，生产可用的功能会立即部署到生产环境中。

在许多组织中，业务部门决定是否将一个功能上线，或何时上线一个功能。因此，将持续部署视为一个选项，而不是强制性的。

另一方面，持续交付；这意味着以连续方式创建可供生产使用的功能，应该是任何组织的座右铭。

# 创建一个生产服务器

在接下来的部分中，让我们创建一个承载我们*hello world*应用程序的生产服务器。稍后我们将扩展我们的持续交付流程，自动在我们的生产服务器上部署完全测试的二进制文件。

在以下示例中，我们的生产服务器是一个简单的 Tomcat 服务器。让我们使用 Vagrant 创建一个。

# 安装 Vagrant

在本节中，我们将在 Ubuntu 上安装 Vagrant。请确保以`root`用户或具有 root 权限（`sudo`访问）的帐户执行这些步骤：

1.  打开终端并输入以下命令以下载 Vagrant：

```
wget https://releases.hashicorp.com/vagrant/1.8.5/vagrant_1.8.5_x86_64.deb
```

或者，你也可以从 Vagrant 网站上下载最新的 Vagrant 软件包：[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/051e5837-2fba-4fb7-a108-9005364b8dc6.png)

Vagrant 下载网页

使用可用的最新版本的 Vagrant 和 VirtualBox。使用旧版本的 Vagrant 与新版本的 VirtualBox 或反之可能在创建 VM 时导致问题。

1.  下载完成后，你应该会看到一个`.deb`文件。

1.  执行以下命令使用下载的软件包文件安装 Vagrant。可能需要输入密码：

```
sudo dpkg -i vagrant_1.8.5_x86_64.deb 
sudo apt-get install -f
```

1.  安装完成后，通过执行以下命令检查已安装的 Vagrant 版本：

```
vagrant --version
```

1.  你应该会看到类似的输出：

```
Vagrant 1.8.5
```

# 安装 VirtualBox

Vagrant 需要 Oracle VirtualBox 来创建虚拟机。然而，并不仅限于 Oracle VirtualBox，你也可以使用 VMware。按照以下步骤在你的机器上安装 VirtualBox：

要使用 VMware 或 AWS 运行 Vagrant，请访问[`www.vagrantup.com/docs/getting-started/providers.html`](https://www.vagrantup.com/docs/getting-started/providers.html)。

1.  将以下行添加到`sources.list`文件中，该文件位于`/etc/apt`目录中：

```
deb http://download.virtualbox.org/virtualbox/debian \
xenial contrib
```

根据你的 Ubuntu 发行版，用`xenial`替换为`vivid`、`utopic`、`trusty`、`raring`、`quantal`、`precise`、`lucid`、`jessie`、`wheezy`或`squeeze`。

1.  使用以下命令下载并注册密钥。你应该期望两个命令都输出：`OK`。

```
wget -q \
https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | 
sudo apt-key add - 
wget -q \
https://www.virtualbox.org/download/oracle_vbox.asc -O- | 
sudo apt-key add –

```

1.  要安装 VirtualBox，请执行以下命令：

```
sudo apt-get update 
sudo apt-get install virtualbox-5.1
```

1.  执行以下命令以查看已安装的 VirtualBox 版本：

```
VBoxManage –-version
```

1.  您应该看到类似的输出：

```
5.1.6r110634
```

Ubuntu/Debian 用户可能希望安装`dkms`软件包，以确保在下次`apt-get upgrade`期间 Linux 内核版本更改时，VirtualBox 主机内核模块（`vboxdrv`、`vboxnetflt`和`vboxnetadp`）得到正确更新。对于 Debian 来说，它在 Lenny backports 中可用，在 Squeeze 及更高版本的正常仓库中可用。可以通过 Synaptic 软件包管理器或通过以下命令安装`dkms`软件包：

`**sudo apt-get install dkms**`

# 使用 Vagrant 创建一个虚拟机

在接下来的部分中，我们将使用 Vagrant 和 VirtualBox 生成一个将充当我们生产服务器的虚拟机。

# 创建一个 Vagrantfile

我们将创建一个 Vagrantfile 来描述我们的虚拟机。请按照以下步骤操作：

1.  使用以下命令创建一个名为`Vagrantfile`的新文件：

```
sudo nano Vagrantfile
```

1.  将以下代码粘贴到文件中：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure(2) do |config|
config.vm.box = "ubuntu/xenial64"

config.vm.define :node1 do |node1_config|
node1_config.vm.network "private_network", ip:"192.168.56.31"
node1_config.vm.provider :virtualbox do |vb|
vb.customize ["modifyvm", :id, "--memory", "2048"]
vb.customize ["modifyvm", :id, "--cpus", "2"]
end
end
end
```

根据需要选择 IP 地址、内存和 CPU 数量。

1.  键入*Ctrl* + *X*，然后 *Y* 保存文件。

# 使用 Vagrant 生成一个虚拟机

在本节中，我们将使用刚刚创建的`Vagrantfile`创建一个虚拟机：

1.  键入以下命令使用上述的`Vagrantfile`生成一个虚拟机：

```
 vagrant up node1
```

1.  Vagrant 将花费一些时间来启动机器。一旦完成，执行以下命令登录到新的虚拟机：

```
 vagrant ssh node1
```

输出如下：

```
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-83-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 Get cloud support with Ubuntu Advantage Cloud Guest:
 http://www.ubuntu.com/business/services/cloud
0 packages can be updated.
0 updates are security updates.

ubuntu@ubuntu-xenial:~$
```

1.  我们现在在虚拟机内。我们将升级我们的虚拟机，并安装我们运行应用程序所需的所有必要应用程序：

    +   Java JDK（最新版）

    +   Apache Tomcat（8.5）

    +   一个用于登录 Docker 容器的用户账户

    +   开启 SSH 守护进程—`sshd`（以接受 SSH 连接）

    +   Curl

1.  现在，按照您在任何正常 Ubuntu 机器上的操作方式安装所有必需的应用程序。让我们首先创建一个`jenkins`用户：

    1.  执行以下命令并按照用户创建步骤进行操作：

```
adduser jenkins
```

输出如下：

```
Adding user `jenkins' ...
Adding new group `jenkins' (1001) ...
Adding new user `jenkins' (1001) with group `jenkins' ...
Creating home directory `/home/jenkins' ...
Copying files from `/etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for jenkins
Enter the new value, or press ENTER for the default
 Full Name []: Nikhil Pathania
 Room Number []:
 Work Phone []:
 Home Phone []:
 Other []:
Is the information correct? [Y/n] Y
```

1.  1.  使用切换用户命令检查新用户：

```
su jenkins
```

1.  通过键入`exit`切换回 root 用户。

1.  接下来，我们将安装 SSH 服务器。按顺序执行以下命令（如果`openssh-server`应用程序和`/var/run/sshd`目录路径已存在，则忽略）：

```
sudo apt-get update

sudo apt-get install openssh-server

sudo mkdir /var/run/sshd
```

1.  跟随以下步骤安装 Java：

    1.  更新软件包索引：

```
sudo apt-get update
```

1.  1.  接下来，安装 Java。以下命令将安装 JRE：

```
sudo apt-get install default-jre
```

1.  安装 Tomcat 8.5 的最佳方法是下载最新的二进制发行版，然后手动配置它：

    1.  切换到`/tmp`目录并使用以下命令下载 Apache Tomcat 8.5：

```
cd /tmp

wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.11/bin/apache-tomcat-8.5.11-deployer.tar.gz
```

1.  1.  我们将在`$HOME`目录下安装 Tomcat。为此，请在`$HOME`内创建一个`tomcat`目录：

```
mkdir $HOME/tomcat
```

1.  1.  然后，将存档文件解压缩到其中：

```
sudo tar xzvf apache-tomcat-8*tar.gz \
-C $HOME/tomcat --strip-components=1
```

1.  在终端中键入`exit`退出虚拟机。

# 在 Jenkins 内添加生产服务器凭据

为了使 Jenkins 与生产服务器通信，我们需要在 Jenkins 内添加账户凭据。

我们将使用 Jenkins 凭据插件来实现这一点。 如果您已经按照本章开头讨论的 Jenkins 设置向导进行操作，您将在 Jenkins 仪表板上找到凭据功能（请参阅左侧菜单）：

按照给定的步骤进行操作：

1.  从 Jenkins 仪表板，单击凭据 | 系统 | 全局凭据（无限制）。

1.  在全局凭据（无限制）页面上，从左侧菜单中，单击添加凭据链接。

1.  您将看到一堆字段供您配置。

1.  对于类型字段，选择用户名与密码。

1.  为范围字段选择全局（Jenkins、节点、项目、所有子项目等）。

1.  在用户名字段下添加一个用户名。

1.  在密码字段下添加一个密码。

1.  通过在 ID 字段下键入字符串为您的凭据分配一个唯一的 ID。

1.  在描述字段下添加一个有意义的描述。

1.  完成后单击保存按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/4d6e00da-6cea-423c-aecd-b71b2ab777b4.png)

在 Jenkins 内添加凭据

# 在生产服务器上安装 Jenkins 从节点

在本节中，我们将在生产服务器上安装一个 Jenkins 从节点。 这将允许我们在生产服务器上执行部署。 执行以下步骤：

1.  从 Jenkins 仪表板，单击管理 Jenkins | 管理节点。

1.  一旦在节点管理器页面上，从左侧菜单中单击新建节点。

1.  为您的新 Jenkins 从节点命名，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/00db7d51-f0f0-42fd-92bd-11ada1770bc6.png)

配置 Jenkins 从节点

# 创建 Jenkins 持续部署流水线

在下一节中，我们将扩展我们的持续交付流水线以执行部署。

# 重温 CD 流水线代码

以下是作为 CD 一部分的完整组合代码：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project
    -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
           "pattern": "target/hello-0.0.1.war",
           "target": "example-project/${BUILD_NUMBER}/",
           "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
  stash includes:
   'target/hello-0.0.1.war,src/pt/Hello_World_Test_Plan.jmx',
  name: 'binary'
}
node('docker_pt') {
  stage ('Start Tomcat'){
    sh '''cd /home/jenkins/tomcat/bin
    ./startup.sh''';
  }
  stage ('Deploy '){
    unstash 'binary'
    sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
  }
  stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l
    $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
  }
  stage ('Promote build in Artifactory'){
    withCredentials([usernameColonPassword(credentialsId:
     'artifactory-account', variable: 'credentials')]) {
      sh 'curl -u${credentials} -X PUT
      "http://192.168.56.102:8081/artifactory/api/storage/example-project/
      ${BUILD_NUMBER}/hello-0.0.1.war?properties=Performance-Tested=Yes"';
    }
  }
}
```

# 用于生产 Jenkins 从节点的流水线代码

首先，让我们为我们的 Jenkins 从节点 production-server 创建一个节点块：

```
node('production') {
}
```

其中`production`是 Jenkins 从节点 production-server 的标签。

我们希望将构建产物部署到生产服务器上的 Tomcat 上的`production`节点。

让我们为其编写流水线代码。

# 从 Artifactory 下载二进制文件的流水线代码

要从 Artifactory 下载构建产物，我们将使用文件规范。文件规范代码如下所示：

```
"files": [
    {
      "pattern": "[Mandatory]",
      "target": "[Mandatory]",
      "props": "[Optional]",
      "recursive": "[Optional, Default: 'true']",
      "flat" : "[Optional, Default: 'true']",
      "regexp": "[Optional, Default: 'false']"
    }
  ]
```

以下表描述了使用的各种参数：

| **参数** | **描述** |
| --- | --- |
| `pattern` | `[必填]`指定应上传到 Artifactory 的本地文件系统路径的工件。您可以使用通配符或由`regexp`属性指定的正则表达式指定多个工件。如果使用`regexp`，则需要使用反斜杠`\`转义表达式中使用的任何保留字符（例如`.`，`?`等）。从 Jenkins Artifactory 插件的版本 2.9.0 和 TeamCity Artifactory 插件的版本 2.3.1 开始，模式格式已经简化，并且对于所有操作系统（包括 Windows），都使用相同的文件分隔符`/`。 |
| `target` | `[必填]`指定 Artifactory 中目标路径的格式如下：`[repository_name]/[repository_path]`如果模式以斜杠结尾，例如，`repo-name/a/b/`，那么假定`b`是 Artifactory 中的一个文件夹，并且文件被上传到其中。在`repo-name/a/b`的情况下，上传的文件在 Artifactory 中被重命名为`b`。为了灵活指定上传路径，您可以在源路径中的对应令牌周围包含占位符形式的`{1}，{2}，{3}...`，这些占位符会被替换为相应的标记。有关更多详细信息，请参阅[使用占位符](https://www.jfrog.com/confluence/display/RTF/Using+File+Specs#UsingFileSpecs-UsingPlaceholders)文档。 |
| `props` | `[可选]`以分号(`;`)分隔的`key=value`对列表，将其附加为上传的属性。如果任何键可以具有多个值，则每个值由逗号(`,`)分隔。例如，`key1=value1;key2=value21,value22;key3=value3`。 |
| `flat` | `[默认值：true]`如果为`true`，则工件将上传到指定的确切目标路径，并且源文件系统中的层次结构将被忽略。如果为`false`，则工件将上传到目标路径，同时保持其文件系统层次结构。 |
| `recursive` | `[默认值：true]`如果为`true`，则还从源目录的子目录中收集工件进行上传。如果为`false`，则仅上传源目录中明确指定的工件。 |
| `regexp` | `[默认值：false]`如果为`true`，则命令将解释模式属性（描述要上传的工件的本地文件系统路径）为正则表达式。如果为`false`，则命令将解释模式属性为通配符表达式。 |

以下是我们将在管道中使用的 File Specs 代码：

```
def server = Artifactory.server 'Default Artifactory Server'
def downloadSpec = """{
  "files": [
    {
        "pattern": "example-project/$BUILD_NUMBER/*.zip",
        "target": "/home/jenkins/tomcat/webapps/"
        "props": "Performance-Tested=Yes;Integration-Tested=Yes",
    }
  ]
}""
server.download(downloadSpec)
```

将前面的步骤包装在名为`Deploy to Prod`的`stage`内：

```
stage ('Deploy to Prod'){
  def server = Artifactory.server 'Default Artifactory Server'
  def downloadSpec = """{
    "files": [
      {
        "pattern": "example-project/$BUILD_NUMBER/*.zip",
        "target": "/home/jenkins/tomcat/webapps/"
        "props": "Performance-Tested=Yes;Integration-Tested=Yes",
      }
    ]
  }""
server.download(downloadSpec)
}
```

将`Deploy to Prod`阶段包装在`production`节点块内：

```
node ('production') {
  stage ('Deploy to Prod'){    def server = Artifactory.server 'Default Artifactory Server'
    def downloadSpec = """{
      "files": [
        {
          "pattern": "example-project/$BUILD_NUMBER/*.zip",
          "target": "/home/jenkins/tomcat/webapps/"
          "props": "Performance-Tested=Yes;Integration-Tested=Yes",
        }
      ]
    }""
    server.download(downloadSpec)
  }
}
```

# 组合连续部署管道代码

以下是组合的连续部署管道代码：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project
    -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
          "pattern": "target/hello-0.0.1.war",
          "target": "example-project/${BUILD_NUMBER}/",
          "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
  stash includes:
   'target/hello-0.0.1.war,src/pt/Hello_World_Test_Plan.jmx',
  name: 'binary'
}
node('docker_pt') {
  stage ('Start Tomcat'){
    sh '''cd /home/jenkins/tomcat/bin
    ./startup.sh''';
  }
  stage ('Deploy '){
    unstash 'binary'
    sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
  }
  stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l
    $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
  }
  stage ('Promote build in Artifactory'){
    withCredentials([usernameColonPassword(credentialsId:
     'artifactory-account', variable: 'credentials')]) {
      sh 'curl -u${credentials} -X PUT
      "http://192.168.56.102:8081/artifactory/api/storage/example-project/
      ${BUILD_NUMBER}/hello-0.0.1.war?properties=Performance-Tested=Yes"';
    }
  }
}
node ('production') {  stage ('Deploy to Prod'){    def server = Artifactory.server 'Default Artifactory Server'
    def downloadSpec = """{
      "files": [
        {
          "pattern": "example-project/$BUILD_NUMBER/*.zip",
          "target": "/home/jenkins/tomcat/webapps/"
          "props": "Performance-Tested=Yes;Integration-Tested=Yes",
        }
      ]
    }""
    server.download(downloadSpec)
  }
}
```

# 更新 Jenkinsfile

Jenkins 多分支 CD Pipeline 利用 Jenkinsfile。在本节中，我们将更新现有的 Jenkinsfile。按照给定的步骤进行操作：

1.  登录到您的 GitHub 账户。

1.  转到分叉出来的仓库。

1.  在仓库页面上，点击`Jenkinsfile`。接下来，在结果页面上点击编辑按钮以编辑您的`Jenkinsfile`。

1.  用以下代码替换现有内容：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar
    -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project
    -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server
      'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
           "pattern": "target/hello-0.0.1.war",
           "target": "example-project/${BUILD_NUMBER}/",
           "props": "Integration-Tested=Yes;
             Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
  stash includes:
   'target/hello-0.0.1.war,src/pt/Hello_World_Test_Plan.jmx',
  name: 'binary'
}
node('docker_pt') {
  stage ('Start Tomcat'){
    sh '''cd /home/jenkins/tomcat/bin
    ./startup.sh''';
  }
  stage ('Deploy '){
    unstash 'binary'
    sh 'cp target/hello-0.0.1.war /home/jenkins/tomcat/webapps/';
  }
  stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx
    -l $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
  }
  stage ('Promote build in Artifactory'){
    withCredentials([usernameColonPassword(credentialsId:
     'artifactory-account', variable: 'credentials')]) {
      sh 'curl -u${credentials} -X PUT
      "http://192.168.56.102:8081/artifactory/api/storage/
       example-project/${BUILD_NUMBER}/hello-0.0.1.war?
       properties=Performance-Tested=Yes"';
    }
  }
}
node ('production') {  stage ('Deploy to Prod'){    def server = Artifactory.server 
     'Default Artifactory Server'
    def downloadSpec = """{
      "files": [
        {
          "pattern": "example-project/$BUILD_NUMBER/*.zip",
          "target": "/home/jenkins/tomcat/webapps/"
          "props": "Performance-Tested=Yes;
             Integration-Tested=Yes",
        }
      ]
    }""
    server.download(downloadSpec)
  }
}
```

1.  完成后，通过添加一个有意义的注释来提交新文件。

# 持续交付正在进行中

对您的 GitHub 代码进行一些更改，或者只需从 Jenkins 仪表盘触发 Jenkins 流水线。

登录到 Jenkins，从 Jenkins 仪表盘点击您的多分支流水线。您应该会看到类似以下截图的内容：

图片

Jenkins 中的持续部署流水线正在运行

# 摘要

这标志着持续部署的结束。在这一章中，我们学习了如何使用 Jenkins 实现持续部署。同时，我希望您已经清楚了持续交付与持续部署之间的区别。本章没有涉及到主要的设置或配置，因为在之前的章节中实现持续集成和持续交付时已经完成了所有必要的工作。

我真诚地希望这本书可以让您走出去，更多地尝试 Jenkins。

下次再见，加油！


# 第十章：支持工具和安装指南

本章将带您了解使您的 Jenkins 服务器可以通过互联网访问所需的步骤。我们还将介绍在 Windows 和 Linux 上安装 Git 所需的步骤。

# 将您的本地主机服务器暴露给互联网

您需要在 GitHub 上创建 Webhooks 以触发 Jenkins 中的管道。另外，对于 GitHub Webhooks 的工作，Jenkins 服务器可通过互联网访问非常重要。

在练习本书中描述的示例时，您可能会需要使您的 Jenkins 服务器可以通过互联网访问，该服务器安装在您的沙盒环境中。

在接下来的章节中，我们将使用一个名为 ngrok 的工具来实现这一目标。执行以下步骤使您的 Jenkins 服务器可以通过互联网访问：

1.  登录到 Jenkins 服务器机器（独立的 Windows/Linux 机器）。如果您正在使用 Docker 运行 Jenkins，请登录到您的 Docker 主机机器（很可能是 Linux）。

1.  从 [`ngrok.com/download`](https://ngrok.com/download) 下载 ngrok 应用程序。

1.  您下载的是一个 ZIP 包。使用`unzip`命令解压它（要在 Ubuntu 上安装 ZIP 实用程序，执行`sudo apt-get install zip`）。

1.  运行以下命令解压 ngrok ZIP 包：

```
unzip /path/to/ngrok.zip 
```

1.  要在 Linux 上运行 ngrok，请执行以下命令：

```
./ngrok http 8080
```

或者，运行以下命令：

```
nohup ./ngrok http 8080 & 
```

1.  要在 Windows 上运行 ngrok，请执行以下命令：

```
ngrok.exe http 8080 
```

1.  您应该会看到类似的输出，如下所示；突出显示的文本是`localhost:8080`的公共 URL：

```
ngrok by @inconshreveable (Ctrl+C to quit)
Session Status online
Version 2.2.8
Region United States (us)
Web Interface http://127.0.0.1:4040
Forwarding http://8bd4ecd3.ngrok.io -> localhost:8080
Forwarding https://8bd4ecd3.ngrok.io -> localhost:8080
Connections ttl opn rt1 rt5 p50 p90
0 0 0.00 0.00 0.00 0.00
```

1.  复制上述公共 URL。

1.  登录到您的 Jenkins 服务器。从 Jenkins 仪表板，导航到 Manage Jenkins | Configure System。

1.  在 Jenkins 配置页面上，向下滚动到 Jenkins 位置部分，并将使用 ngrok 生成的公共 URL 添加到 Jenkins URL 字段内。

1.  单击保存按钮以保存设置。

1.  现在，您将能够通过互联网访问您的 Jenkins 服务器使用公共 URL。

1.  在 GitHub 上创建 Webhooks 时，请使用使用 ngrok 生成的公共 URL。

# 在 Windows/Linux 上安装 Git

以下各节中提到的步骤是在 Windows 和 Linux 上安装 Git 所需的：

# 在 Windows 上安装 Git

要在 Windows 上安装 Git，请按照以下步骤操作：

1.  您可以从 [`git-scm.com/downloads`](https://git-scm.com/downloads) 下载 Git：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ce6a95c9-0f54-4ef8-8e00-42a521ea5d82.png)

1.  单击下载的可执行文件并按照安装步骤进行操作。

1.  接受许可协议并单击下一步。

1.  选择所有组件并单击下一步，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ff2bae15-4881-435e-a35a-d6145c36ec10.png)

1.  选择 Git 使用的默认编辑器，然后单击下一步。

1.  通过选择适当的环境来调整您的路径环境，并单击下一步，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c3f61f02-6489-495f-a39a-4d362c3f66d4.png)

1.  选择使用 OpenSSH 作为 SSH 可执行文件，然后单击下一步：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d53c922f-0c0e-4ccc-95e2-df874beca61e.png)

1.  选择将 OpenSSL 库用作 HTTPS 传输后端，然后点击下一步：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/0da5aa5c-2fda-4669-a6e9-ff3cee992fb8.png)

1.  选择适合你的行结束转换方式，然后点击下一步。

1.  选择终端模拟器，然后点击下一步。

1.  选择启用文件系统缓存和启用 Git 凭据管理器选项，如下截图所示，然后点击安装：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/52217b0f-36f5-497f-a50c-9b52762360ac.png)

1.  Git 安装应该现在开始。安装完成后，点击完成。

# 在 Linux 上安装 Git

在 Linux 上安装 Git，请执行以下步骤：

1.  在 Linux 上安装 Git 很简单。在本节中，我们将在 Ubuntu（16.04.x）上安装 Git。

1.  登录到你的 Ubuntu 机器。确保你拥有管理员权限。

1.  如果你使用的是 GUI，请打开终端。

1.  按顺序执行以下命令：

```
sudo apt-get update 
sudo apt-get install git
```

1.  执行以下命令检查 Git 是否安装成功：

```
git --version
```

1.  你应该得到以下结果：

```
git version 2.15.1.windows.2
```
