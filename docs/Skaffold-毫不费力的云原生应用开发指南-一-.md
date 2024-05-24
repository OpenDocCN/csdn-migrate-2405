# Skaffold：毫不费力的云原生应用开发指南（一）

> 原文：[`zh.annas-archive.org/md5/12FE92B278177BC9DBE7FCBCECC73A83`](https://zh.annas-archive.org/md5/12FE92B278177BC9DBE7FCBCECC73A83)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

多年来，围绕 Kubernetes 的工具已经发生了巨大变化，鉴于其所带来的热潮。越来越多的开发者正在寻找可以帮助他们快速开始使用 Kubernetes 的工具。这也给开发者带来了一些困惑：他们应该使用哪种工具来减少配置本地设置的时间，或者编写脚本来自动化他们的内部开发循环工作流程？此外，开发者在使用 Kubernetes 时需要更好的工具，因为焦点应该放在手头的任务上，即编码，而不是苦恼于如何以及在哪里部署应用程序。理想情况下，您会希望有一个提供可扩展性以支持各种用例的工具。

本书将向您展示如何通过使用 Skaffold 自动化构建、推送和部署样板来解决云原生应用中的内部开发循环复杂性。

# 本书的受众

本书适用于云原生应用开发人员、与 Kubernetes 合作的软件工程师以及寻找简化其内部开发循环并改进云原生应用的 CI/CD 流程的 DevOps 专业人员。在阅读本书之前，需要具备初级水平的 Java、Docker、Kubernetes 和容器生态系统知识。

# 本书涵盖内容

第一章《编码、构建、测试和重复——应用开发的内部循环》定义了应用开发的内部循环及其重要性。它还将内部循环与外部开发循环进行了比较，并涵盖了传统单体应用程序和容器原生微服务应用程序的典型开发工作流程。

第二章《使用 Kubernetes 开发云原生应用——开发者的噩梦》解释了开发者在使用 Kubernetes 开发云原生应用时所面临的问题。

第三章《Skaffold——简单易用的云原生 Kubernetes 应用开发》提供了 Skaffold 的高级概述。我们还将通过构建和部署一个 Spring Boot 应用程序来演示 Skaffold 的基本特性。

第四章《了解 Skaffold 的特性和架构》通过查看其架构、工作流程和配置文件`skaffold.yaml`来探讨 Skaffold 的特性和内部结构。

[*第五章*]，*安装 Skaffold 并揭秘其流水线阶段*，解释了 Skaffold 的安装以及在不同流水线阶段中使用的常见 CLI 命令。

[*第六章*]，*使用 Skaffold 容器镜像构建器和部署器*，介绍了用于使用 Skaffold 将容器镜像（Docker、Jib、kaniko、Buildpacks）构建和部署（Helm、kubectl、kustomize）到 Kubernetes 的各种工具。

[*第七章*]，*使用 Cloud Code 插件构建和部署 Spring Boot 应用*，向您介绍了由 Google 开发的 Cloud Code 插件。它解释了如何使用 Cloud Code 插件和诸如 IntelliJ 之类的 IDE 将 Spring Boot 应用构建和部署到 Kubernetes 集群。

[*第八章*]，*使用 Skaffold 将 Spring Boot 应用部署到 Google Kubernetes Engine*，解释了如何使用 Skaffold 将 Spring Boot 应用部署到 Google Kubernetes Engine，这是 Google Cloud Platform 提供的托管 Kubernetes 服务。

[*第九章*]，*使用 Skaffold 创建一个生产就绪的 CI/CD 流水线*，解释了如何使用 Skaffold 和 GitHub 操作创建一个 Spring Boot 应用的生产就绪的持续集成和部署流水线。

[*第十章*]，*探索 Skaffold 替代方案、最佳实践和陷阱*，介绍了 Skaffold 替代工具，如 Telepresence，并介绍了 Skaffold 的最佳实践和陷阱。

# 要充分利用本书

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Preface_table1.jpg)

如果您正在使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将有助于您避免与复制和粘贴代码相关的任何潜在错误。

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自我们丰富的图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：

[`static.packt-cdn.com/downloads/9781801077118_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781801077118_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“在内部，Skaffold 创建一个`tar`文件，其中包含与我们在`skaffold.yaml`文件中定义的同步规则匹配的更改文件。”

代码块设置如下：

```
profiles:
  - name: userDefinedPortForward
    portForward:
      - localPort: 9090
        port: 8080
        resourceName: reactive-web-app
        resourceType: deployment
```

任何命令行输入或输出都以以下方式编写：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64 && \sudo install skaffold /usr/local/bin/
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子：“现在我们有一个可用的项目，点击**Run/Debug Configurations**下拉菜单，然后选择**Edit Configurations**。”

提示或重要说明

会以这种方式出现。


# 第一部分：Kubernetes 的噩梦 – Skaffold 来拯救

在这一部分，我们将描述使用 Kubernetes 开发应用程序的痛苦和苦难。在本地开发 Kubernetes 应用程序时，存在多个手动触点，这降低了开发人员的生产力。焦点应该放在编写代码和为产品添加更多功能上，而不是担心在您的工作站上复制基础架构以调试问题或测试功能。谷歌的工程师们将这称为无尽的痛苦和苦难循环。我们将向您介绍 Skaffold 以及它如何帮助您自动化构建、推送和部署在 Kubernetes 上运行的应用程序的工作流程。

在这一部分，我们有以下章节：

+   *第一章*, *编码、构建、测试和重复 – 应用程序开发的内部循环*

+   *第二章*, *使用 Kubernetes 开发云原生应用程序 – 开发者的噩梦*

+   *第三章*, *Skaffold – 简单易用的云原生 Kubernetes 应用程序开发*


# 第一章：编码、构建、测试和重复 - 应用程序开发内部循环

构建和部署云原生应用程序可能会对本地和远程开发造成麻烦，如果您没有使用适当的工具。开发人员经历了很多痛苦来自动化构建、推送和部署步骤。在本书中，我们将向您介绍**Skaffold**，它可以帮助自动化这些开发工作流程步骤。您将学习如何使用 Skaffold CLI 来加速内部开发循环，以及如何创建有效的**持续集成**/**持续部署**（**CI/CD**）流水线，并执行构建和部署以管理 Kubernetes 实例，如**Google Kubernetes Engine**（**GKE**）、**Microsoft 的 Azure Kubernetes Service**（**AKS**）和 Amazon 的**Elastic Kubernetes Service**（**EKS**）。

本章将定义应用程序开发的内部循环及其重要性，比较内部与外部开发循环，并涵盖传统单体应用程序和容器本地微服务应用程序的典型开发工作流程。我们将深入讨论这两种方法之间的差异。

在本章中，我们将涵盖以下主要主题：

+   了解应用程序开发内部循环是什么

+   内部与外部开发循环

+   探索传统应用程序开发内部循环

+   检查容器本地应用程序开发内部循环

到本章结束时，您将了解传统和容器本地应用程序内部开发循环。

# 技术要求

要跟着本章的示例进行，您需要以下内容：

+   Eclipse ([`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)) or IntelliJ IDEA ([`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/))

+   Git ([`git-scm.com/downloads`](https://git-scm.com/downloads))

+   Spring Boot 2.5 ([`start.spring.io`](https://start.spring.io))

+   minikube ([`minikube.sigs.k8s.io/docs/`](https://minikube.sigs.k8s.io/docs/)) 或 Docker Desktop for macOS 和 Windows ([`www.docker.com/products/docker-desktop`](https://www.docker.com/products/docker-desktop))

+   OpenJDK 16 ([`jdk.java.net/16/`](https://jdk.java.net/16/))

您可以从 GitHub 存储库[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter01`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter01)下载本章的代码示例

# 理解应用程序开发的内部循环

**应用程序开发的内部循环**是一个迭代过程，在这个过程中，开发人员更改代码，开始构建，运行应用程序，然后测试它。如果出了问题，那么我们就重复整个循环。

因此，基本上，这是开发人员在本地完成更改之前与他人分享更改的阶段。无论您的技术堆栈、使用的工具和个人偏好如何，内部循环过程可能会有所不同，但理想情况下，可以总结为以下三个步骤：

1.  代码

1.  构建

1.  测试

以下是内部开发循环的快速可视化表示：

![图 1.1 - 内部循环](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.1_B17385.jpg)

图 1.1 - 内部循环

如果您仔细想想，编码是唯一增加价值的步骤，其余步骤都像是对您的工作进行验证，即确认您的代码是否正在编译和测试是否通过。由于开发人员大部分时间都花在内部循环上，他们不喜欢在任何步骤上花费太多时间。它应该迅速。此外，作为开发人员，我们渴望快速反馈。

到目前为止，我们定义的所有步骤都是在开发人员的机器上本地发生的，然后再将代码提交到源代码存储库。一旦开发人员提交并推送更改到源代码存储库，通常会启动他们的 CI/CD 管道，称为**外部开发循环**（拉取请求、CI、部署等）。无论您是开发传统的单体应用程序还是容器化的微服务应用程序，都不应忽视内部开发循环的重要性。以下是您应该关注内部开发循环的原因：

+   如果您的内部开发循环缓慢且缺乏自动化，那么开发人员的生产力将会下降。

+   最好始终致力于优化它，因为慢的内部循环会影响其他依赖团队，并且将需要更长的时间将新功能交付给用户。

现在我们已经快速概述了应用程序开发的内部循环，让我们比较一下内部和外部开发循环。

# 内部与外部开发循环

正如前面讨论的那样，只要开发人员在本地环境中测试，他们就处于内部循环中。一般来说，开发人员大部分时间都在内部循环中，因为它快速并且能够立即反馈。通常涉及以下步骤：

1.  开发人员开始处理新的功能请求。此时进行一些代码更改。

1.  一旦开发人员对更改感到自信，就会启动构建。

1.  如果构建成功，开发人员将运行单元测试。

1.  如果测试通过，开发人员将在本地启动应用程序的一个实例。

1.  他们将切换到浏览器验证更改。

1.  开发人员将跟踪日志或附加调试器。

1.  如果出现问题，开发人员将重复前面的步骤。

但是，一旦开发人员提交并将代码推送到源代码存储库，就会触发外部开发循环。外部开发循环与 CI/CD 流程密切相关。它涉及以下步骤：

1.  CI 检出源代码

1.  构建项目

1.  运行功能和集成测试套件

1.  创建运行时构件（JAR、WAR 等）

1.  部署到目标环境

1.  测试和重复

所有前面的步骤通常都是自动化的，开发人员几乎不需要参与。当 CI/CD 流水线因测试失败或编译问题而中断时，开发人员应该收到通知，然后开始在内部开发循环上再次工作以解决这个问题。以下是内循环与外循环的可视化：

![图 1.2 - 内循环与外循环](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.2_B17385.jpg)

图 1.2 - 内循环与外循环

很容易将 CI/CD 用作内部开发循环的替代品。让我们讨论一下这是否是一个好方法。

## 为什么不使用 CI/CD？

与我们刚讨论的内循环相反，一些开发人员可能会说他们不关心他们的内部开发循环，因为他们有一个 CI/CD 流程，这应该足够了。他们并不完全错误，因为这些流水线是为了使现代应用程序开发过程可重复和简单而构建的。但是，您的 CI/CD 流程只能解决一组独特的问题。

使用 CI/CD 替代你的内部开发循环将使整个过程变得更慢。想象一下，不得不等待整个 CI/CD 系统运行你的构建和测试套件，然后部署，只发现你犯了一个小错误；这将是相当恼人的。现在，你必须等待并重复整个过程，只是因为一些愚蠢的错误。如果我们可以避免不必要的迭代，那将会更容易。对于你的内部开发循环，你必须快速迭代并预览更改，就好像它们发生在一个实时集群上一样。

我们已经涵盖了关于应用程序开发内部循环的足够基础知识，现在我们将介绍 Java 开发人员的传统应用程序开发内部循环。

# 探索传统应用程序开发内部循环

在容器变得流行之前，我们被内部开发循环的选择所宠坏。你的集成开发环境可以在后台运行构建，然后你可以部署你的应用程序并在本地测试你的更改。典型的传统应用程序开发内部循环涉及以下步骤：

1.  开发人员在集成开发环境中进行代码更改

1.  构建和打包应用程序

1.  部署，然后在本地服务器上运行

1.  最后，测试更改并重复步骤

这是传统应用程序开发内部循环的可视化。

![图 1.3 - 传统应用程序开发内部循环](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.3_B17385.jpg)

图 1.3 - 传统应用程序开发内部循环

对于 Java 开发人员，有许多选项可用于自动化此过程。其中一些最受欢迎的选项如下：

+   Spring Boot 开发者工具

+   JRebel

让我们简要讨论这些选项。

## Spring Boot 开发者工具

Spring Boot 首次在 1.3 版中引入了开发者工具。Spring Boot 开发者工具提供快速反馈循环和自动重新启动应用程序以适应任何代码更改。它提供以下功能：

+   它提供了**热重载**功能。一旦在`classpath`上进行了任何文件更改，它将自动重新启动应用程序。自动重新启动可能会根据你的集成开发环境而有所不同。请查看官方文档（[`docs.spring.io/spring-boot/docs/1.5.16.RELEASE/reference/html/using-boot-devtools.html#using-boot-devtools-restart`](https://docs.spring.io/spring-boot/docs/1.5.16.RELEASE/reference/html/using-boot-devtools.html#using)）以获取更多关于此的详细信息。

+   它提供与**LiveReload**插件（[`livereload.com`](http://livereload.com)）的集成，以便在资源更改时自动刷新浏览器。在内部，Spring Boot 将启动一个嵌入式 LiveReload 服务器，每当资源更改时都会触发浏览器刷新。该插件适用于大多数流行的浏览器，如 Chrome、Firefox 和 Safari。

+   它不仅支持本地开发过程，还可以选择更新并重新启动远程在服务器或云上运行的应用程序。您也可以选择启用远程调试。但是，在生产中使用此功能存在安全风险。

以下是如何向 Maven 和 Gradle 项目添加相关依赖项以添加对 Spring Boot 开发工具的支持的简短片段。Maven/Gradle 应该首先有一个介绍部分：

Maven pom.xml

```
<dependencies>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
  </dependency>
</dependencies>
```

Gradle build.gradle

以下是 Gradle 的代码：

```
dependencies {
compileOnly("org.springframework.boot:spring-boot-devtools")
}
```

但这不是我们将如何添加依赖项来测试开发工具的自动重新加载功能。我们将使用**Spring Initializr**网站（[`start.spring.io/`](https://start.spring.io/)）根据您选择的选项生成项目存根。以下是我们将遵循的步骤：

1.  您可以选择默认选项，也可以自行选择。您可以选择构建工具（Maven 或 Gradle）、语言（Java、Kotlin 或 Groovy）和您选择的 Spring Boot 版本。

1.  之后，您可以通过点击“**ADD DEPENDENCIES…**”按钮并选择应用程序所需的依赖项来添加必要的依赖项。

1.  我选择了默认选项，并将`spring-boot-starter-web`、`spring-boot-dev-tools`和 Thymeleaf 作为我的演示 Hello World Spring Boot 应用程序的依赖项。

1.  现在，继续点击“**GENERATE**”按钮，以下载在您的计算机上生成的源代码。这是您应该看到的屏幕：![图 1.4 – Spring Initializr 首页](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.4_B17385.jpg)

图 1.4 – Spring Initializr 首页

1.  下载后，您可以将项目导入到您的 IDE 中。

下一个逻辑步骤是构建一个简单的 Hello World Spring Boot web 应用程序。让我们开始吧。

### Spring Boot web 应用程序的解剖

了解 Spring Boot 应用程序的工作部分的最佳方法是看一个例子。在这个例子中，我们将创建一个简单的**Spring Web MVC**应用程序，它将在`http://localhost:8080/hello`接受 HTTP GET 请求。我们将得到一个 HTML 网页，其中响应中的 HTML 主体中有"Hello, John!"。我们将允许用户通过在`http://localhost:8080/hello?name=Jack` URL 中输入查询字符串来自定义默认响应，以便我们可以更改默认消息。让我们开始：

1.  首先，让我们使用`@Controller`注解创建一个`HelloController` bean 来处理传入的 HTTP 请求。`@GetMapping`注解将 HTTP GET 请求绑定到`hello()`方法：

```
@Controller
public class HelloController {
   @GetMapping("/hello")
   public String hello(@RequestParam(defaultValue =     "John", name = "name", required = false) String name,     Model model) {
      model.addAttribute("name", name);
      return "index";
}
}
```

这个控制器返回视图的名称，在我们的例子中是`index`。我们在这里使用的视图技术是 Thymeleaf，它负责服务器端渲染 HTML 内容。

1.  在源代码模板中，`index.html`位于`src/main/resources/`的 templates 文件夹中。以下是文件的内容：

```
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head>
      <meta charset="UTF-8"/>
      <title>Welcome</title>
</head>
<body>
<p th:text="'Hello, ' + ${name} + '!'" />
</body>
</html>
```

1.  Spring Boot 为您的应用程序提供了一个默认的设置，其中包括一个`main`类：

```
@SpringBootApplication
public class Application {
   public static void main(String[] args) {
      SpringApplication.run(Application.class, args);
   }
}
```

1.  我们将使用`mvn` `spring-boot:run maven goal`来运行我们的应用程序，这是由`spring-boot-maven-plugin`提供的：![图 1.5 - 应用程序的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.5_B17385.jpg)

图 1.5 - Spring Boot 应用程序启动日志

注意

为了减少日志的冗长，我们已经将它们缩减到只显示与我们讨论相关的部分。

如果您仔细观察日志，我们已经启用了开发者工具支持，一个嵌入式的 Tomcat 服务器在端口`8080`上监听，并且一个运行在端口`35279`上的嵌入式 LiveReload 服务器。到目前为止，看起来很不错。一旦应用程序启动，您可以访问 http://localhost:8080/hello URL。

![图 1.6 - REST 端点响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.6_B17385.jpg)

图 1.6 - REST 端点响应

1.  现在我们将在 Java 文件中进行一个小的代码更改并保存，您可以从日志中看到嵌入式 Tomcat 服务器已经重新启动。在日志中，您还可以看到生成应用程序的线程不是主线程，而是一个`restartedMain`线程：

```
2021-02-12 16:28:54.500   INFO 53622 --- [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]          : Initializing Spring DispatcherServlet 'dispatcherServlet'
2021-02-12 16:28:54.500   INFO 53622 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet            : Initializing Servlet 'dispatcherServlet'
2021-02-12 16:28:54.501   INFO 53622 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet            : Completed initialization in 1 ms
2021-02-12 16:29:48.762   INFO 53622 --- [          Thread-5] o.s.s.concurrent.ThreadPoolTaskExecutor   : Shutting down ExecutorService 'applicationTaskExecutor'
2021-02-12 16:29:49.291   INFO 53622 --- [   restartedMain] c.e.helloworld.HelloWorldApplication       : Started HelloWorldApplication in 0.483 seconds (JVM running for 66.027)
2021-02-12 16:29:49.298   INFO 53622 --- [   restartedMain] .ConditionEvaluationDeltaLoggingListener : Condition evaluation unchanged
2021-02-12 16:29:49.318   INFO 53622 --- [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]          : Initializing Spring DispatcherServlet 'dispatcherServlet'
2021-02-12 16:29:49.319   INFO 53622 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet            : Initializing Servlet 'dispatcherServlet'
2021-02-12 16:29:49.320   INFO 53622 --- [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet            : Completed initialization in 1 ms
```

这完成了 Spring Boot 开发者工具自动重启功能的演示。出于简洁起见，我们没有涵盖 LiveReload 功能，因为在这里很难解释，因为这一切都是实时发生的。

## JRebel

**JRebel** ([`www.jrebel.com/products/jrebel`](https://www.jrebel.com/products/jrebel)) 是 Java 开发人员加速内部循环开发过程的另一个选择。它是一个 JVM 插件，有助于减少本地开发步骤的时间，如构建和部署。这是一个由名为*Perforce*的公司开发的付费工具。但是，如果您想尝试一下，有 10 天的免费试用期。它提供以下功能：

+   它允许开发人员跳过重建和重新部署，并通过刷新浏览器即可看到其更改的实时更新。

+   它将使开发人员在保持应用程序状态的同时更加高效。

+   它提供了即时反馈循环，允许您在开发过程中早期测试和修复问题。

+   它与流行的框架、应用服务器、构建工具和 IDE 有良好的集成。

有许多不同的方法可以使 JRebel 支持您的开发过程。我们将考虑使用它与 Eclipse 或 IntelliJ 这样的 IDE 的可能性。对于这两个 IDE，您可以安装插件，就这样。正如我之前所说，这是一个付费选项，您只能免费试用 10 天。

对于 IntelliJ IDEA，您可以从市场安装插件。

![图 1.7 – IntelliJ IDEA 安装 JRebel](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.7_B17385.jpg)

图 1.7 – IntelliJ IDEA 安装 JRebel

对于 Eclipse IDE，您可以从 Eclipse Marketplace 安装插件。

![图 1.8 – Eclipse IDE 安装 JRebel](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.8_B17385.jpg)

图 1.8 – Eclipse IDE 安装 JRebel

由于 JRebel 是一个付费选项，我们将不会在本书中探讨它，但您可以自行测试。

我们已经介绍了传统应用程序开发内部循环生命周期和工具，如 Spring Boot Developer Tools 和 JRebel，它们允许快速应用程序开发。现在让我们来看一下基于容器的应用程序开发内部循环生命周期。

# 检查基于容器的应用程序开发内部循环

Kubernetes 和容器为内部开发循环引入了一系列新的挑战和复杂性。现在在开发应用程序时，内部循环中添加了一组额外的步骤，这是耗时的。开发人员更愿意花时间解决业务问题，而不是等待构建过程完成。

它涉及以下步骤：

1.  在 IDE 中进行代码更改的开发人员

1.  构建和打包应用程序

1.  创建一个容器镜像

1.  将镜像推送到容器注册表

1.  Kubernetes 从注册表中拉取镜像

1.  Kubernetes 创建和部署 pod

1.  最后，测试和重复

谷歌的工程师称之为“无尽的痛苦和苦难”。这是一个容器本地应用开发内部循环的可视化：

![图 1.9 - 容器本地应用开发内部循环](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_1.9_B17385.jpg)

图 1.9 - 容器本地应用开发内部循环

正如你所看到的，我们现在在内部开发循环中增加了三个步骤，即创建应用程序的容器镜像，将其推送到容器注册表，最后，在部署到 Kubernetes 等容器编排工具时拉取镜像。

容器镜像可以是 Docker 或 OCI 格式的镜像，这取决于您用来构建镜像的工具。您可以选择 Docker Hub、AWS 容器注册表、谷歌容器注册表或 Azure 容器注册表作为容器注册表。然后，在部署时，对于容器编排，您可以使用 Kubernetes 等工具，它将首先从容器注册表中拉取镜像并部署您的应用程序。

这里涉及许多手动步骤。这也取决于您在本地开发工作流程中使用了什么工具。例如，您将使用以下命令：

```
docker build 
docker tag
docker push 
kubectl apply
```

以下是开发人员在开发容器本地应用程序时必须经历的详细步骤：

1.  使用 Dockerfile 定义如何配置容器的操作系统

1.  通过向 Dockerfile 添加指令来定义将应用程序打包成容器镜像

1.  使用 Docker 命令（如`docker build`和`docker tag`）创建一个容器镜像

1.  使用命令（如`docker push`）将容器镜像上传到容器注册表

1.  在 YAML 中编写一个或多个 Kubernetes 资源文件

1.  使用命令（如`kubectl apply -f myapp.yaml`）将应用程序部署到集群

1.  使用命令（如`kubectl apply -f mysvc.yaml`）将服务部署到集群

1.  编写配置，使应用程序可以通过命令（如`kubectl create configmap`）协同工作

1.  使用命令（如`kubectl apply -f myappconfigmap.yaml`）配置应用程序以正确地协同工作

哇哦！这是很多步骤和耗时的过程。您可以使用脚本或`docker compose`来在一定程度上自动化它，但很快您会意识到，如果没有 Skaffold 这样的工具，它是无法完全自动化的，Skaffold 可以抽象出许多与构建和部署相关的事情。

在*第三章*中，*Skaffold – 简单易用的云原生 Kubernetes 应用开发*，我们将介绍 Skaffold，它可以用单个命令简化我们在这里涵盖的过程。我在这里的唯一目的是让您了解涉及的步骤。我们将在下一章中通过一些实际示例来介绍这些步骤。

# 摘要

在本章中，我们涵盖了许多主题，比如典型的内部开发循环及其重要性。我们还讨论了内部和外部开发循环的不同之处，然后探讨了 CI/CD 过程是否可以替代内部开发循环。

然后，我们讨论了传统应用程序开发内部循环涉及的步骤，并介绍了诸如 Spring 开发者工具和 JRebel 之类的工具，这些工具使应用程序开发变得更加容易。为了进一步解释这一点，我们创建了一个简单的 Spring Boot web MVC 应用程序。最后，在最后一节中，我们涵盖了容器本地应用程序开发内部循环。我们还介绍了容器本地应用程序开发涉及的步骤。

在本章中，重点是向您介绍内部和外部开发等概念。您可以使用 Spring Boot 开发者工具和 JRebel 来加速/自动化传统应用程序开发生命周期。

在下一章中，我们将介绍开发人员在使用 Kubernetes 开发应用程序时面临的问题。

# 进一步阅读

+   了解有关 Spring Boot 开发者工具的更多信息，请访问[`docs.spring.io/spring-boot/docs/1.5.16.RELEASE/reference/html/using-boot-devtools.html`](https://docs.spring.io/spring-boot/docs/1.5.16.RELEASE/reference/html/using-boot-devtools.html)。

+   有关 JRebel 的更多信息，请访问[`www.jrebel.com/`](https://www.jrebel.com/)。

+   从 Packt 出版的*Docker for Developers*中了解更多有关 Docker 的信息([`www.packtpub.com/product/docker-for-developers/9781789536058`](https://www.packtpub.com/product/docker-for-developers/9781789536058))。

+   从 Packt 出版的《精通 Kubernetes》了解更多关于 Kubernetes 的信息（https://www.packtpub.com/product/mastering-kubernetes/9781786461001）.


# 第二章：使用 Kubernetes 开发云原生应用程序-开发者的噩梦

在上一章中，我们介绍了开发人员在开发容器原生应用程序时面临的困难。我们还介绍了开发生命周期中引入的新步骤。我们可能已经简化了解释概念，但在本章中我们将详细介绍每个步骤。

本章将涵盖开发人员在使用 Kubernetes 开发云原生应用程序时面临的问题。我们将介绍 Kubernetes 的整体开发体验为什么如此痛苦，以及为什么开发人员不是 Kubernetes 专家，他们在使用 Kubernetes 开发应用程序时寻求简化的工作流程。

在本章中，我们将涵盖以下主要主题：

+   开发者体验不佳

+   开发者希望简化 Kubernetes 的工作流程

+   开发者不是 Kubernetes 专家

通过本章的学习，您将了解开发人员在使用 Kubernetes 开发云原生应用程序时面临的常见挑战。随后，在下一章中，我们将学习如何通过使用 Skaffold 来克服这些挑战，以改善您的开发工作流程。

# 技术要求

要跟随本章中的示例，您需要以下内容：

+   Eclipse ([`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)) 或 IntelliJ IDE ([`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/))

+   Git ([`git-scm.com/downloads`](https://git-scm.com/downloads))

+   Spring Boot 2.5 ([`start.spring.io`](https://start.spring.io))

+   minikube ([`minikube.sigs.k8s.io/docs/`](https://minikube.sigs.k8s.io/docs/)) 或 Docker Desktop for macOS 和 Windows ([`www.docker.com/products/dockerdesktop`](https://www.docker.com/products/dockerdesktop))

+   OpenJDK 16 ([`jdk.java.net/16/`](https://jdk.java.net/16/))

您可以从 GitHub 存储库[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter02`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter02)下载本章的代码示例。

# 开发者体验不佳

现代开发人员正在寻找能够让他们在快节奏的今天世界中保持竞争力并交付符合客户期望的软件的工具和技术。进入 Kubernetes！Kubernetes 于 2014 年开源，自诞生以来，已成为全球众多企业选择的容器编排平台。Kubernetes 极大地简化了运维人员的工作，但对于构建和部署应用程序到 Kubernetes 的开发人员来说，情况并非如此。

我们在本章中详细介绍了这一点。根据最近的一项研究，大约 59%的企业组织正在使用 Kubernetes 运行其生产工作负载。对于一个只有 5 年历史的技术来说，这是非常出色的。企业采用 Kubernetes 的主要原因是为了增加敏捷性，加快软件交付，并支持数字化转型。

在讨论使用 Kubernetes 的痛点之前，让我们以一个真实的例子来了解 Kubernetes 如何帮助组织进行数字化转型。让我们以一个电子商务网站为例。大多数时候，网站都能正常运行。该网站利用微服务架构，并拥有多个服务协同工作，以提供更好的用户体验。然而，由于即将到来的假期，IT 团队预计网站的使用量会激增，团队担心这可能会导致停机，因为底层的微服务可能无法处理负载。但是有了 Kubernetes，很容易进行扩展而不会带来太多麻烦。例如，您可以利用 Kubernetes 的自动缩放功能以及其水平 Pod 自动缩放器（HPA）。HPA 根据观察到的 CPU 利用率自动调整 Pod 的数量。

此外，容器和 Kubernetes 确实改变了我们打包、部署和大规模运行云原生应用程序的方式。容器化后，您可以在任何地方运行应用程序，即在虚拟机、物理机或云上。并且借助 Kubernetes 等容器编排工具，您可以更有效地扩展、部署和管理云原生应用程序。它减少了生产中的停机时间，并使运维团队的工作更加轻松。然而，与传统应用程序相比，开发人员的体验和实践自 Kubernetes 问世以来并没有多大进步。让我们通过一个例子来了解云原生应用程序开发流程。

## 了解云原生应用程序开发工作流程

我们将使用在*第一章*中创建的相同的*Hello-World Spring Boot Web MVC*应用程序，*代码、构建、测试和重复 – 应用程序开发内部循环*；但是，这次我们将对其进行容器化并部署到 Kubernetes。我们的想法是经历开发人员在开发云原生 Spring Boot 应用程序时所经历的困难。以下是我们将要遵循的步骤：

1.  我们将使用**Docker Desktop**作为 macOS 和 Windows 的工具，因为它支持 Kubernetes，并且我们不必为此示例单独下载**minikube**。但是，如果您不使用 macOS，那么您也可以为其他操作系统安装 minikube ([`v1-18.docs.kubernetes.io/docs/tasks/tools/install-minikube/#installing-minikube`](https://v1-18.docs.kubernetes.io/docs/tasks/tools/install-minikube/#installing-minikube))。按照步骤在 macOS 和 Windows 上启用 Docker Desktop 的 Kubernetes 支持。

1.  在 Docker 菜单栏中导航到**首选项**。然后，在**Kubernetes**选项卡上，单击**启用 Kubernetes**复选框，以启动单节点功能性 Kubernetes 集群。启动集群需要一些时间。这不是强制性的，但您也可以将 Kubernetes 启用为`docker stack`命令的默认编排器。![图 2.1 – 启用 Kubernetes](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_2.1_B17385.jpg)

图 2.1 – 启用 Kubernetes

1.  启用后，您将在 Docker Desktop 菜单栏上看到以下屏幕。这证实了 Kubernetes 集群已经启动和运行：![图 2.2 – 验证设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_2.2_B17385.jpg)

图 2.2 – 验证设置

1.  接下来，请确保 Kubernetes 上下文设置为`docker-desktop`，如果您在本地运行多个集群或环境：![图 2.3 – 上下文设置为 docker-desktop](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_2.3_B17385.jpg)

图 2.3 – 上下文设置为 docker-desktop

1.  顺便说一句，Docker Desktop 带有**kubectl**支持；您不必单独下载它。kubectl 是 Kubernetes 的命令行工具，您可以使用它来针对您的集群运行命令。在 macOS 上，它通常位于路径`/usr/local/bin/kubectl`。对于 Windows，它位于`C:\>Program Files\Docker\Docker\Resources\bin\kubectl.exe`。您可能希望将其添加到您的`PATH`变量中。让我们使用以下命令验证设置：

```
kubectl get nodes
NAME             STATUS   ROLES    AGE   VERSION
docker-desktop   Ready    master   59d   v1.19.3
```

1.  以下是我们用于此示例的 Dockerfile：

```
FROM openjdk:16
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
```

我们这里有一个非常基本的 Dockerfile。让我简要解释一下指令：

a. `FROM`指令指定了我们的 Spring Boot 应用程序的基础镜像，即 OpenJDK 16。

b. `COPY`用于将文件或目录从主机系统移动到容器内部的文件系统。在这里，我们将`.jar`文件从目标目录复制到容器内部的根路径。

c. `ENTRYPOINT`作为容器的运行时可执行文件，将启动我们的应用程序。

1.  现在我们有了 Dockerfile，接下来我们需要创建一个可执行的`.jar`文件。我们将使用`mvn clean install`命令为我们的应用程序创建一个可执行的`.jar`文件。让我们运行`docker build`命令来创建一个容器镜像。在这里，我们将我们的镜像命名为`helloworld`。`docker build`命令的输出将如下所示：

```
docker build -t hiashish/helloworld:latest .
[+] Building 4.9s (8/8) FINISHED
 => [internal] load build definition from Dockerfile
0.1s
 => => transferring dockerfile: 36B
0.0s
 => [internal] load .dockerignore
0.0s
 => => transferring context: 2B
0.0s
 => [internal] load metadata for docker.io/library/openjdk:16
4.3s
 => [auth] library/openjdk:pull token for registry-1.docker.io
0.0s
 => [internal] load build context
0.1s
 => => transferring context: 86B
0.0s
 => [1/2] FROM docker.io/library/openjdk:11@sha256:3805f5303af58ebfee1d2f5cd5a897e97409e48398144afc223 3f7b778337017
0.0s
 => CACHED [2/2] COPY target/*.jar app.jar
0.0s
 => exporting to image
0.0s
 => => exporting layers
0.0s
 => => writing image sha256:65b544ec877ec10a4dce9883b3 766fe0d6682fb8f67f0952a41200b49c8b0c50
0.0s
 => => naming to docker.io/hiashish/helloworld:latest
```

1.  我们已经为应用程序创建了一个镜像。现在我们准备使用`docker push`命令将镜像推送到 DockerHub 容器注册表，如下所示：

```
docker push hiashish/helloworld
Using default tag: latest
The push refers to repository [docker.io/hiashish/helloworld]
7f517448b554: Pushed 
ebab439b6c1b: Pushed 
c44cd007351c: Pushed 
02f0a7f763a3: Pushed 
da654bc8bc80: Pushed 
4ef81dc52d99: Pushed 
909e93c71745: Pushed 
7f03bfe4d6dc: Pushed 
latest: digest: sha256:16d3d9db1ecdbf21c69bc838d4a a7860ddd5e212a289b726ac043df708801473 size: 2006
```

1.  这个练习的最后一部分是创建 Kubernetes 资源（部署和服务），以便在 Kubernetes 上启动和运行我们的应用程序。服务和部署的声明性 YAML 文件位于源代码的`K8s`目录中。让我们首先创建部署资源，它负责动态创建和运行一组 Pod：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: helloworld
  name: helloworld
spec:
  replicas: 1
  selector:
    matchLabels:
      app: helloworld
  template:
    metadata:
      labels:
        app: helloworld
    spec:
      containers:
        - image: docker.io/hiashish/helloworld
          name: helloworld
```

让我澄清一下我们用来创建 Kubernetes 部署对象的 YAML 文件的一些事情：

a. `metadata.name`指定要创建的部署对象的名称。

b. `spec.replicas`字段表示 Kubernetes 部署对象将创建一个副本。

c. `template.spec`字段表示 Pod 将运行一个名为`helloworld`的单个容器，该容器运行我们应用程序的 DockerHub 镜像。

这是创建 Deployment 对象的`kubectl`命令：

```
kubectl create -f mydeployment.yaml
deployment.apps/helloworld created
```

1.  服务为一组 Pod 提供单一的 DNS 名称，并在它们之间进行负载平衡。让我们创建 Service 资源，以便可以从集群外部访问应用程序：

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app: helloworld
  name: helloworld
spec:
  ports:
    - port: 8080
      protocol: TCP
      targetPort: 8080
  selector:
    app: helloworld
  type: NodePort
```

让我们谈谈我们用来创建 Kubernetes Service 对象的 YAML 文件：

a. `metadata.name`指定要创建的 Service 对象的名称。

b. `spec.selectors`允许 Kubernetes 将名为`helloworld`的 Pod 分组，并将请求转发给它们。

c. `type: Nodeport`为每个节点创建一个静态 IP，以便我们可以从外部访问 Service。

d. `targetPort`是容器端口。

e. `port`是在集群内部暴露的端口。

以下是创建 Service 对象的`kubectl`命令：

```
kubectl create -f myservice.yaml   
service/helloworld created
```

1.  现在让我们验证一下我们是否有一个正在运行的 Pod：![图 2.4 - Pod 运行](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_2.4_B17385.jpg)

图 2.4 - Pod 运行

1.  正如您所看到的，我们现在已经在 Kubernetes 上运行我们的应用程序。让我们来验证一下：

![图 2.5 - REST 端点响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_2.5_B17385.jpg)

图 2.5 - REST 端点响应

这是很多步骤，即使您的更改很小，也需要太多的按键，而且您甚至不知道它是否有效。现在想象一下，每次您推送更改时都需要这样做！如果您有多个微服务相互通信，这个工作流程可能会更加复杂。您可以选择不在本地开发时部署到 Kubernetes，而是依赖于 CI/CD 流程。或者您可能正在使用类似于`docker-compose`或者使用 Docker 进行隔离测试。想象一下，您需要以这种方式运行多个微服务。

要真实地测试一切，您需要使开发环境与部署环境相匹配，以测试您的微服务依赖关系。这是容器本地开发的缺点，因为开发人员花费更少的时间编码，而更多的时间担心配置、设置环境和等待部署完成。在本书的后面章节中，我们将介绍如何使用 Skaffold 构建和部署多个微服务。

由于 Kubernetes 带来的固有复杂性，开发人员正在寻找简单的工作流程。让我们在下一节讨论这个问题。

# 开发人员希望简化 Kubernetes 的工作流程。

在上一章中，我们讨论了开发人员在内部开发循环中开发传统的 Spring Boot 应用程序时经历的步骤。我们还讨论了如何使用*spring-dev-tools*等工具轻松自动化整个流程。一旦开发人员对更改感到满意，他们可以保存更改，更改将自动部署。

开发云原生应用程序的开发人员正在寻找类似的工作流程，他们可以保存更改。在后台进行一些魔术操作后，应用程序应该部署到他们选择的本地或远程集群。此外，之前曾在传统单片应用程序上工作过的开发人员在转向开发云原生应用程序时会期望类似的工作流程。从开发人员的角度来看，期望是云原生应用程序开发的额外步骤应该可以通过单个命令或点击来抑制。

开发人员期望在 Kubernetes 中有简化的工作流程，如下图所示：

![图 2.6 - 使用 Kubernetes 的 Ctrl + S 工作流程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_2.6_B17385.jpg)

图 2.6 - 使用 Kubernetes 的 Ctrl + S 工作流程

为解决这些问题，企业需要为开发人员提供可以抽象一般 Kubernetes 复杂性的工具。具体而言，开发人员正在寻找可以满足以下要求的平台或工具：

+   开发人员应该能够在不经过支持经理批准的官僚主义的情况下连接到 Kubernetes。

+   开发人员不应该浪费时间和精力来配置环境。

+   开发人员在使用 Kubernetes 时应该能够快速开始工作。

+   开发人员可以通过单个命令快速部署更改到 Kubernetes 集群。

+   开发人员应该在开发过程中调试云原生应用程序，就像他们习惯于调试传统应用程序一样。

开发人员不应该被绑定在一个用于构建和部署图像的工具上。好消息是，许多企业已经意识到开发人员在 Kubernetes 上的体验有多痛苦，并正在提出他们自己的解决方案来改进它。在本书的后面，我们将介绍一个名为 Skaffold 的工具，它简化了开发人员在处理云原生应用程序时的内部开发循环。Skaffold 实现了*Ctrl* + *Save*的工作流，并自动化了构建和部署过程。Skaffold 还赋予了开发人员选择构建工具（Docker/Jib/Buildpacks）和部署工具（kubectl/Helm/kustomize）的自由。

拥有这样的技能集会很不错，但我们真的希望开发人员成为 Kubernetes 专家吗？让我们在下一节讨论这个问题。

# 开发人员不是 Kubernetes 专家

Kubernetes 最初是为运维人员开发的，而不是为开发人员开发的。有许多原因，开发人员可能对了解 Kubernetes 并不感兴趣。一个合理的理由是，开发人员更感兴趣的是解决业务问题，为他们正在开发的产品添加功能，而不关心目标环境，也就是他们将部署应用的地方。而且，说实话，Kubernetes 很复杂，这不仅对初学者而言很难，对经验丰富的人也很难。我在哪里看到过这个笑话，可能是在 Twitter 上，关于理解 Kubernetes 有多难：“*有一次我试图向某人解释 Kubernetes。然后我们俩都没搞懂*。”

这需要一种与开发人员日常任务不同的技能水平。由于其复杂性，通常需要很长时间才能让普通开发人员掌握 Kubernetes。

在企业环境中工作的开发人员往往会处理以下任务：

+   参与设计讨论

+   为产品添加新功能

+   编写单元测试用例

+   提高代码质量

+   致力于改进应用程序的性能

+   修复错误

+   重构代码

开发人员只想编码，而不想担心他们的应用程序将如何部署在哪里。

关键是，我们需要不断告诉自己，Kubernetes 对开发人员来说并不是一个容易的工具。此外，开发人员更感兴趣的是创建应用程序，使用可以处理构建并为其部署样板的工具。

# 总结

本章涵盖了开发人员在使用 Kubernetes 开发云原生应用程序时必须经历的困难。我们首先描述了部署到 Kubernetes 的应用程序的云原生应用程序开发工作流程。我们通过一些编码示例介绍了开发人员在开发云原生应用程序时必须经历的额外步骤。然后我们解释了开发人员正在寻找一个简化的工作流程，以便在 Kubernetes 上轻松开发。随后在本章中，我们展示了开发人员并不是 Kubernetes 专家，他们应该配备诸如 Skaffold 之类的工具，以改善他们在 Kubernetes 上的开发体验。

在本章中，主要目标是为您介绍开发人员在开发容器本地应用程序时遇到的问题。阅读完本章后，您应该能够理解这些问题，同时我也给出了 Skaffold 如何帮助解决这些问题的提示。

在下一章中，我们将快速介绍 Skaffold，并通过一些编码示例来更好地理解这些提示。

# 进一步阅读。

+   了解有关 Docker 和 Kubernetes 的更多信息，请访问[`www.packtpub.com/product/kubernetes-and-docker-an-enterprise-guide/9781839213403`](https://www.packtpub.com/product/kubernetes-and-docker-an-enterprise-guide/9781839213403)。

+   有关使用 Kubernetes 进行云原生开发的更多信息，请访问[`www.packtpub.com/product/cloud-native-with-kubernetes/9781838823078`](https://www.packtpub.com/product/cloud-native-with-kubernetes/9781838823078)。


# 第三章：Skaffold ——轻松开发云原生 Kubernetes 应用程序

在上一章中，我们了解到使用 Kubernetes 开发应用是繁琐的，并提供了一些编码示例。本章将概述 Skaffold 的高级概述。您还将学习和了解 Skaffold 基本命令行界面（CLI）命令以及这些命令如何简化开发人员在 Skaffold 中开发云原生微服务的痛点。我们将通过构建和部署一个 Spring Boot 应用程序来演示 Skaffold 的基本功能。

在本章中，我们将涵盖以下主要主题：

+   什么是 Skaffold？

+   使用 Skaffold 构建和部署 Spring Boot 应用程序

通过本章结束时，您将对 Skaffold 有基本的了解，并能够利用 Skaffold 加速内部开发循环，同时开发云原生应用程序。

# 技术要求

为了跟着本章的例子，你需要以下内容：

+   Eclipse ([`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)) 或 IntelliJ IDEA [`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/)

+   Git

+   Skaffold CLI ([`skaffold.dev/docs/install/`](https://skaffold.dev/docs/install/))

+   Spring Boot 2.5 ([`start.spring.io`](https://start.spring.io))

+   OpenJDK 16 ([`jdk.java.net/16/`](https://jdk.java.net/16/))

+   minikube ([`minikube.sigs.k8s.io/docs/`](https://minikube.sigs.k8s.io/docs/)) 或 Docker Desktop for macOS and Windows ([`www.docker.com/products/dockerdesktop`](https://www.docker.com/products/dockerdesktop))

您可以从 GitHub 存储库[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter03`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold/tree/main/Chapter03)下载本章的代码示例。

# 什么是 Skaffold？

像大多数开发人员一样，Google 工程师 Matt Rickard 在构建和部署 Kubernetes 应用程序时也遇到了同样的痛点。Matt 决定自己动手，创建了 Skaffold。

**Skaffold**是一个 CLI 工具，它可以自动化构建、推送和部署本地或远程 Kubernetes 集群上运行的云原生应用程序的步骤。Skaffold 并不是 Docker 或 Kubernetes 的替代品。它与它们一起工作，并为您处理构建、推送和部署的样板部分。

Skaffold 是由 Google 开发的开源工具。它于 2019 年 11 月 7 日正式发布，并在 Apache 2.0 许可下发布。Skaffold 是用 Go 编程语言编写的。您可以访问 Skaffold 主页[`skaffold.dev/`](https://skaffold.dev/)。Skaffold 文档可在[`skaffold.dev/docs/`](https://skaffold.dev/docs/)找到。

如果您使用的是 macOS，那么您可以使用`homebrew`软件包管理器通过`brew install skaffold`命令安装 Skaffold。然而，在*第五章*，*安装 Skaffold 并揭秘其流水线阶段*中，我们将介绍安装 Skaffold 的各种方法。

Skaffold 在开发者社区中广受欢迎，因为它提供了合理的默认设置，易于使用，并具有可插拔的架构。这是官方 Skaffold 账号最近的一条推文，证实了这一点：

![图 3.1 – Skaffold Twitter 账号在 GitHub 上通过 11k 星标推文](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_03_01.jpg)

图 3.1 – Skaffold Twitter 账号在 GitHub 上通过 11k 星标推文

如推文中所述，Skaffold GitHub 仓库的星标和分支数量本身就说明了它的受欢迎程度，如下所示：

![图 3.2 – Skaffold GitHub 仓库](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_03_02.jpg)

图 3.2 – Skaffold GitHub 仓库

Skaffold GitHub 页面可在[`github.com/GoogleContainerTools/skaffold`](https://github.com/GoogleContainerTools/skaffold)找到。

让我们尝试通过构建和部署一个 Spring Boot 应用程序来理解 Skaffold 的工作原理。

# 使用 Skaffold 构建和部署 Spring Boot 应用程序

为了更好地理解 Skaffold 命令和概念，在本节中，我们将使用 Skaffold 构建和部署一个 Spring Boot Java 应用程序到本地单节点 Kubernetes 集群。

注意

每当我们在本书中谈论*用于本地开发的 Kubernetes 集群*时，我们指的是*具有 Docker 桌面版的 Kubernetes 集群*，除非另有说明。然而，Docker 桌面版或 minikube 并不是今天用于运行本地 Kubernetes 集群的唯一工具。Skaffold 还支持 Kind [`github.com/kubernetes-sigs/kind`](https://github.com/kubernetes-sigs/kind)和 k3d [`github.com/rancher/k3d`](https://github.com/rancher/k3d)作为本地开发的目标 Kubernetes 集群。

由于这将是 Skaffold 的预览，我们不会详细介绍 Skaffold 的所有内容，因为我们将在接下来的章节中介绍这一点。但是，我会尝试解释所使用的命令，以便您可以理解确切的流程。在我们深入研究 Skaffold 之前，让我们先谈谈我们将使用 Skaffold 构建和部署的 Spring Boot 应用程序。

## 创建一个 Spring Boot 应用程序

我们将要创建的这个 Spring Boot 应用程序将暴露两个**表述状态转移**（**REST**）端点。`/states` REST 端点将返回所有印度各邦及其首府，而`/state?name=statename` REST 端点将返回特定的印度邦及其首府。该应用程序使用内存中的`H2`数据库，在应用程序启动时插入行。与之前的章节类似，我们将使用[`start.spring.io`](https://start.spring.io)生成项目的存根。以下屏幕截图显示了我们将用于构建此应用程序的依赖项：

![图 3.3 – Spring Boot 应用程序所需的依赖项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_03_03.jpg)

图 3.3 – Spring Boot 应用程序所需的依赖项

将以下依赖项添加到 Maven 的`pom.xml`文件中：

```
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-data-jdbc</artifactId>
</dependency>
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-web</artifactId>
</dependency> 
<dependency>
   <groupId>com.h2database</groupId>
   <artifactId>h2</artifactId>
   <scope>runtime</scope>
</dependency>
<plugin>
   <groupId>com.google.cloud.tools</groupId>
   <artifactId>jib-maven-plugin</artifactId>
   <version>2.8.0</version>
   <configuration>
      <from>
         <image>openjdk:16-jdk-alpine</image>
      </from>
      <to>
         <image>docker.io/hiashish/skaffold-introduction            </image>
      </to>
   </configuration>
</plugin>
```

除了我们已经讨论过的依赖项之外，我还在`pom.xml`中添加了`jib-maven-plugin`插件，它将 Spring Boot 应用程序容器化为一个容器镜像。Jib 将您的源代码作为输入，并输出一个准备就绪的应用程序容器镜像。顺便说一句，Gradle 也有一个等效的插件。对于 Gradle，请使用以下代码：

```
plugins {  
  id 'com.google.cloud.tools.jib' version '2.8.0'
} 
```

提示

**Jib**可以在没有 Docker 守护程序的情况下创建镜像。这意味着您不必安装和配置 Docker，也不必创建或维护 Dockerfile。

我们将在*第六章*中更多地介绍 Jib，*使用 Skaffold 容器镜像构建器和部署器*。

让我们开始吧：

1.  这是源代码目录的布局:![图 3.4 - 项目布局](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_03_04.jpg)

图 3.4 - 项目布局

1.  以下是用`@RestController`注解的 REST 控制器类，用于处理传入的**超文本传输协议**（**HTTP**）请求。`getAllStates()`方法上的`@GetMapping`注解在访问`/states` REST 端点时绑定所有 HTTP `GET`请求。同样，`getSpecificState()`方法处理了传入 REST **统一资源定位符**（**URL**）的`/state`的 HTTP `GET`请求，当州名作为查询参数传递时。如果没有传递参数，则它将采用`Maharashtra`州的默认值:

```
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
@RestController
public class StateController {
    private final StateService stateService;
    private static final Logger LOGGER =    LoggerFactory.getLogger(Controller.class);
    public StateController(StateService stateService) {
        this.stateService = stateService;
    }
    @GetMapping("/states")
    private List<State> getAllStates() {
        LOGGER.info("Getting all state");
        return stateService.findAll();
    }
    @GetMapping(value = "/state")
    private String getSpecificState(@      RequestParam(required = false, name = "name",         defaultValue = "Maharashtra") String name) {
        return stateService.findByName(name);
    }
}
```

1.  在撰写本书时，Java 16 已经普遍可用。我还有幸向您介绍了一些其新功能。现在让我们谈谈记录。我们有以下数据载体`record`类:

```
public record State(String name, String capital) {}
```

类类型是`record`，它是 Java 16 中作为特性添加的特殊类型。根据*Java Enhancement Proposal 395* ([`openjdk.java.net/jeps/395`](https://openjdk.java.net/jeps/395))，记录是 Java 语言中的一种新类型的类。它们作为不可变数据的透明载体，比普通类的仪式少。记录可以被视为名义元组。`record`类声明包括名称、可选类型参数、头部和主体。关于`record`类的另一个值得一提的有趣特性是编译器会为我们隐式生成`hashcode()`、`equals()`、`toString()`和一个规范构造函数。

1.  以下是由`StateService`类实现的`StateRepository`接口:

```
import java.util.List;
public interface StateRepository {
    List<State> findAll();
    String findByName(String name);
}
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import java.util.List;
@Service
public class StateService implements StateRepository{
    private final JdbcTemplate;
    public StateService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
    private final RowMapper<State>  rowMapper = (rs,    rowNum) -> new State(rs.getString("name"),
    rs.getString("capital"));
    @Override
    public List<State> findAll() {
        String findAllStates = """
                select * from States
                """;
        return jdbcTemplate.query(findAllStates,
          rowMapper);
    }
    @Override
    public String findByName(String name) {
        String findByName = """
                select capital from States where name
                  = ?;
                """;
        return jdbcTemplate.queryForObject(findByName,          String.class, name);
    }
}
```

在`StateService`类中，我们使用 Spring 的`JdbcTemplate`来访问`H2`数据库。`findAll()`方法返回所有州和它们的首府。在与`findAll()`方法相同的类中，我使用了`RowMapper`函数接口。`JdbcTemplate`使用它来映射`ResultSet`对象的行，并为当前行返回一个`Row`对象。

我相信您可能也注意到我另外使用了`new`关键字来初始化`record`类，这意味着我可以像在 Java 中初始化普通类一样初始化`record`类。`findByName()`方法返回一个`String`，这是在`query`参数请求中传入的州的首府。

在声明**结构化查询语言**（**SQL**）查询时，我还使用了*Java 15 文本块*（[`openjdk.java.net/jeps/378`](https://openjdk.java.net/jeps/378)）功能，这有助于提高 SQL 查询和**JavaScript 对象表示**（**JSON**）字符串值的可读性。

1.  正如我之前解释的，我们使用内存中的`H2`数据库来保存数据，该数据在应用程序运行时插入。它使用以下 SQL 语句在应用程序启动时插入：

```
INSERT INTO States VALUES ('Andra Pradesh','Hyderabad');
INSERT INTO States VALUES ('Arunachal Pradesh','Itangar');
INSERT INTO States VALUES ('Assam','Dispur');
INSERT INTO States VALUES ('Bihar','Patna');
INSERT INTO States VALUES ('Chhattisgarh','Raipur');
INSERT INTO States VALUES ('Goa','Panaji');
INSERT INTO States VALUES ('Gujarat','Gandhinagar');
INSERT INTO States VALUES ('Haryana','Chandigarh');
INSERT INTO States VALUES ('Himachal Pradesh','Shimla');
INSERT INTO States VALUES ('Jharkhand','Ranchi');
INSERT INTO States VALUES ('Karnataka','Bengaluru');
INSERT INTO States VALUES ('Kerala','Thiruvananthapuram');
INSERT INTO States VALUES ('Madhya Pradesh','Bhopal');
INSERT INTO States VALUES ('Maharashtra','Mumbai');
INSERT INTO States VALUES ('Manipur','Imphal');
INSERT INTO States VALUES ('Meghalaya','Shillong');
INSERT INTO States VALUES ('Mizoram','Aizawl');
INSERT INTO States VALUES ('Nagaland','Kohima');
INSERT INTO States VALUES ('Orissa','Bhubaneshwar');
INSERT INTO States VALUES ('Rajasthan','Jaipur');
INSERT INTO States VALUES ('Sikkim','Gangtok');
INSERT INTO States VALUES ('Tamil Nadu','Chennai');
INSERT INTO States VALUES ('Telangana','Hyderabad');
INSERT INTO States VALUES ('Tripura','Agartala');
INSERT INTO States VALUES ('Uttarakhand','Dehradun');
INSERT INTO States VALUES ('Uttar Pradesh','Lucknow');
INSERT INTO States VALUES ('West Bengal','Kolkata');
INSERT INTO States VALUES ('Punjab','Chandigarh');
```

1.  数据使用以下模式定义：

```
DROP TABLE States IF EXISTS;
CREATE TABLE States(name VARCHAR(255), capital VARCHAR(255));
```

1.  Kubernetes 清单，即部署和服务，可在源代码的`k8s`目录下找到，如下面的代码片段所示：

`mydeployment.yaml`

```
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: skaffold-introduction
  name: skaffold-introduction
spec:
  replicas: 1
  selector:
    matchLabels:
      app: skaffold-introduction
  template:
    metadata:
      labels:
        app: skaffold-introduction
    spec:
      containers:
        - image: docker.io/hiashish/skaffold-introduction
          name: skaffold-introduction
```

`myservice.yaml`

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app: skaffold-introduction
  name: skaffold-introduction
spec:
  ports:
    - port: 8080
      protocol: TCP
      targetPort: 8080
  selector:
    app: skaffold-introduction
  type: LoadBalancer
```

到目前为止，我们已经涵盖了 Skaffold 的所有必需构建块。现在，让我们谈谈 Skaffold 配置。

## 了解 Skaffold 配置

让我们谈谈`skaffold.yaml` Skaffold 配置文件，在其中我们描述了工作流的构建和部署部分。该文件是使用`skaffold init`命令生成的。我们将在*第五章*中探讨这个以及许多其他 Skaffold CLI 命令，*安装 Skaffold 和揭秘其流水线阶段*。Skaffold 通常期望`skaffold.yaml`配置文件在当前目录中，但您可以通过传递`--filename`标志来覆盖它。

这是配置文件的内容：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: indian-states
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: {}
deploy:
  kubectl:
    manifests:
      - k8s/mydeployment.yaml
      - k8s/myservice.yaml
```

让我解释一下这个文件中的关键组件，如下所示：

+   `apiVersion`：这指定了**应用程序编程接口**（**API**）模式版本。

+   `build`：这指定了如何使用 Skaffold 构建图像。

+   `artifacts`：这里有要构建的图像。

+   `image`：这是要构建的图像的名称。

+   `jib`：这指定了使用 Jib Maven 插件构建图像。

+   `deploy`：这指定了图像将如何部署到本地或远程 Kubernetes 集群。

+   `kubectl`：这指定了要使用`kubectl` CLI 来创建和更新 Kubernetes 清单。

+   `manifests`：这指定了 Kubernetes 清单文件路径，即部署和服务。

现在您已经了解了 Skaffold 配置，下一个逻辑步骤是使用 Skaffold 构建和部署我们的 Spring Boot 应用程序。

## 构建和部署 Spring Boot 应用程序

在继续构建和部署我们的 Spring Boot 应用程序之前，请确保在运行`skaffold`命令之前 Docker 已经启动并运行。否则，您将收到以下错误：

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

现在唯一剩下的就是运行`skaffold dev`命令并启动**持续开发**（**CD**）工作流。如果您在没有启用 Docker Desktop 的情况下运行此命令，它将失败，并显示以下错误。因此，请注意这些先决条件：

```
Deploy Failed. Could not connect to cluster docker-desktop due to "https://kubernetes.docker.internal:6443/version?timeout=32s": dial tcp 127.0.0.1:6443: connect: connection refused. Check your connection for the cluster.
```

如果满足了所有的先决条件，那么当您输入该命令时，Skaffold 将会使用其**文件监视器**机制来监视源代码目录中的更改。它将构建一个图像，将其推送到本地 Docker 注册表，部署您的应用程序，并从运行中的 pod 中流式传输日志。

这多酷啊！！您应该看到以下输出：

```
$ skaffold dev
Listing files to watch...
- docker.io/hiashish/skaffold-introduction
Generating tags...
- docker.io/hiashish/skaffold-introduction -> docker.io/hiashish/skaffold-introduction:22f18cc-dirty
Checking cache...
- docker.io/hiashish/skaffold-introduction: Not found. Building
Starting build...
Found [docker-desktop] context, using local docker daemon.
Building [docker.io/hiashish/skaffold-introduction]...
[INFO] --- jib-maven-plugin:2.8.0:dockerBuild (default-cli) @ skaffold-introduction ---
[INFO] Containerizing application to Docker daemon as hiashish/skaffold-introduction:22f18cc-dirty...
[WARNING] Base image 'openjdk:16-jdk-alpine' does not use a specific image digest - build may not be reproducible
[INFO] Building dependencies layer...
[INFO] Building resources layer...
[INFO] Building classes layer...
[INFO] The base image requires auth. Trying again for openjdk:16-jdk-alpine...
[INFO] Using credentials from Docker config (/Users/ashish/.docker/config.json) for openjdk:16-jdk-alpine
[INFO] Using base image with digest: sha256:49d822f4fa4deb 5f9d0201ffeec9f4d113bcb4e7e49bd6bc063d3ba93aacbcae
[INFO] Container entrypoint set to [java, -cp, /app/resources:/app/classes:/app/libs/*, com.example.indianstates.IndianStatesApplication]
[INFO] Loading to Docker daemon...
[INFO] Built image to Docker daemon as hiashish/skaffold-introduction:22f18cc-dirty
[INFO] BUILD SUCCESS
```

注意

为了减少日志的冗长，我们已经将它们裁剪，只显示与我们讨论相关的部分。

由于生成了大量日志，并且一次性解释它们将会很困难，我故意将它们分成几部分，以帮助您通过这些日志更好地理解 Skaffold 的工作。到目前为止，我们可以从日志中得出以下结论：

+   Skaffold 首先尝试根据`skaffold.yaml`文件中定义的构建器来确定它需要监视的源代码依赖关系。

+   然后，它会为图像生成一个标签，如`skaffold.yaml`文件中的`build`部分所述。您可能想知道为什么在构建图像之前会生成图像标签。我们将在*第五章*中专门介绍 Skaffold 的标记机制，*安装 Skaffold 并揭秘其流水线阶段*。

+   然后，它尝试在本地缓存中找到图像。图像被本地缓存以提高执行时间，如果不需要编译的话。由于图像在本地不可用，Skaffold 开始构建。

在进行实际构建之前，Skaffold 确定了 Kubernetes 上下文设置为`docker-desktop`。它将使用本地 Docker 守护程序来创建图像。您是否看到它所采取的巧妙猜测以加快内部开发循环？您可以使用以下命令验证当前的`kube-context`状态：

```
   $kubectl config current-context
   docker-desktop
```

由于我们使用了`jib-maven-plugin`插件，并且 Kubernetes 上下文设置为`docker-desktop`，Skaffold 将在内部使用`jib:dockerBuild`命令来创建映像。我们使用了`openjdk:16-jdk-alpine`作为基础映像，因为它很轻量级。

首先，Jib 将尝试使用位于`/Users/ashish/.docker/config.json`路径下的`config.json`文件中的凭据进行身份验证，并从 Docker Hub 容器注册表下载基础映像；然后，它将创建映像层，并最终将其上传到本地 Docker 守护程序，如下例所示：

```
Starting test...
Tags used in deployment:
- docker.io/hiashish/skaffold-introduction -> docker.io/hiashish/skaffold-introduction:adb6df1b0757245bd08f790e93ed5f8cc621a8f7e500e3c5ad18505a8b677139
Starting deploy...
- deployment.apps/skaffold-introduction created
- service/skaffold-introduction created
Waiting for deployments to stabilize...
- deployment/skaffold-introduction is ready.
Deployments stabilized in 3.771 seconds
Press Ctrl+C to exit
Watching for changes...
[skaffold-introduction]  :: Spring Boot ::                (v2.4.4)
[skaffold-introduction] 2021-03-25 21:17:49.048  INFO 1 --- [           main] c.e.i.IndianStatesApplication            : Starting IndianStatesApplication using Java 16-ea on skaffold-introduction-85bbfddbc9-bfxnx with PID 1 (/app/classes started by root in /)
[skaffold-introduction] 2021-03-25 21:17:55.895  INFO 1 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
[skaffold-introduction] 2021-03-25 21:17:55.936  INFO 1 --- [           main] c.e.i.IndianStatesApplication            : Started IndianStatesApplication in 8.315 seconds (JVM running for 9.579)
```

我们可以从日志中得出以下结论：

+   在第一行的`Starting test...`日志中，Skaffold 运行 container-structure 测试来验证构建的容器映像在部署到我们的集群之前。

+   在那之后，Skaffold 将创建 Kubernetes 清单 - 即，在`k8s`目录下可用的部署和服务。

+   一旦清单创建完成，意味着 Pod 在一段时间后已经启动并运行。然后，它还将在您的控制台上开始从 Pod 中流式传输日志。

现在，我们将进行一些验证，以确保 Pod 实际上正在运行。我们将运行以下`kubectl`命令进行验证：

![图 3.5 - 创建的 Kubernetes 资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_03_05.jpg)

图 3.5 - 创建的 Kubernetes 资源

正如您所看到的，我们有一个名为`skaffold-introduction-667786cc47-khx4q`的 Pod，状态为`RUNNING`。让我们访问`/states` REST 端点，看看我们是否得到了期望的输出，如下所示：

```
$ curl localhost:30368/states
[{"name":"Andra Pradesh","capital":"Hyderabad"},{"name":"Arunachal Pradesh","capital":"Itangar"},{"name":"Assam","capital":"Dispur"},{"name":"Bihar","capital":"Patna"},{"name":"Chhattisgarh","capital":"Raipur"},{"name":"Goa","capital":"Panaji"},{"name":"Gujarat","capital":"Gandhinagar"},{"name":"Haryana","capital":"Chandigarh"},{"name":"Himachal Pradesh","capital":"Shimla"},{"name":"Jharkhand","capital":"Ranchi"},{"name":"Karnataka","capital":"Bengaluru"},{"name":"Kerala","capital":"Thiruvananthapuram"},{"name":"Madhya Pradesh","capital":"Bhopal"},{"name":"Maharashtra","capital":"Mumbai"},{"name":"Manipur","capital":"Imphal"},{"name":"Meghalaya","capital":"Shillong"},{"name":"Mizoram","capital":"Aizawl"},{"name":"Nagaland","capital":"Kohima"},{"name":"Orissa","capital":"Bhubaneshwar"},{"name":"Rajasthan","capital":"Jaipur"},{"name":"Sikkim","capital":"Gangtok"},{"name":"Tamil Nadu","capital":"Chennai"},{"name":"Telangana","capital":"Hyderabad"},{"name":"Tripura","capital":"Agartala"},{"name":"Uttarakhand","capital":"Dehradun"},{"name":"Uttar Pradesh","capital":"Lucknow"},{"name":"West Bengal","capital":"Kolkata"},{"name":"Punjab","capital":"Chandigarh"}]
```

确实，我们得到了预期的输出。让我们也访问另一个`/state?name=statename` REST 端点，看看我们是否得到了期望的输出，如下所示：

```
$ curl -X GET "localhost:30368/state?name=Karnataka"
Bengaluru
```

是的 - 我们确实得到了期望的输出！

当您运行`skaffold dev`命令时，它将创建一个 CD 流水线。例如，在此模式下进行任何代码更改时，Skaffold 将自动重新构建和重新部署映像。

在`Skaffold dev`模式下，由于我们使用的是本地 Kubernetes 集群，并且 Kubernetes 上下文设置为`docker-desktop`，Skaffold 将不会将映像推送到远程容器注册表，而是将其加载到本地 Docker 注册表中。这将进一步帮助加快内部开发循环。

最后，为了清理我们迄今为止所做的一切，我们只需按下*Ctrl* + *C*，Skaffold 将处理其余的事情。

因此，我们到达了这个演示的结束，我们已成功地构建并部署了一个 Spring Boot 应用程序到一个带有 Docker Desktop 的单节点 Kubernetes 集群，使用 Skaffold。

# 总结

在本章中，我们向您介绍了 Skaffold 及其一些命令和概念。在示例中，我们只向您介绍了一个 Skaffold 命令，即`skaffold dev`。然而，还有许多类似的命令，例如`skaffold run`和`skaffold render`，我们将在接下来的章节中介绍。您还学会了如何使用诸如`skaffold dev`这样的命令来构建和部署应用程序到本地 Kubernetes 集群。

在下一章中，我们将学习 Skaffold 的特性和架构。

# 进一步阅读

+   从 Packt Publishing 出版的*Developing Java Applications with Spring and Spring Boot*中了解更多关于使用 Spring Boot 开发 Java 应用程序的信息（[`www.packtpub.com/product/developing-java-applications-with-spring-and-spring-boot/9781789534757`](https://www.packtpub.com/product/developing-java-applications-with-spring-and-spring-boot/9781789534757)）。

+   Java 16 最新版本的发布说明可在[`jdk.java.net/16/`](https://jdk.java.net/16/)上找到。


# 第二部分：开始使用 Skaffold

在这一部分，我们将介绍 Skaffold 的特性和内部架构。我们将尝试理解一些图表，展示 Skaffold 的工作原理。我们还将学习如何使用 Skaffold 启动我们的项目，涵盖 Skaffold 配置文件的一些基础知识。我们将了解 Skaffold 的安装以及在不同流水线阶段（即`init`、`build`和`deploy`）中可以使用的各种命令。最后，在这一部分中，我们将解释使用 Skaffold 构建和部署容器镜像的不同方法。

在这一部分，我们有以下章节：

+   *第四章*, *理解 Skaffold 的特性和架构*

+   *第五章*, *安装 Skaffold 并揭秘其流水线阶段*

+   *第六章*, *使用 Skaffold 容器镜像构建器和部署器工作*


# 第四章：理解 Skaffold 的功能和架构

在上一章中，我们通过一些编码示例对 Skaffold 有了基本的了解。本章将介绍 Skaffold 提供的功能。此外，我们将通过查看其架构、工作流程和`skaffold.yaml`配置文件来探索 Skaffold 的内部。

在本章中，我们将涵盖以下主要主题：

+   理解 Skaffold 的功能

+   揭秘 Skaffold 的架构

+   理解 Skaffold 的工作流程

+   使用`skaffold.yaml`解密 Skaffold 的配置

通过本章结束时，您将对 Skaffold 提供的功能有扎实的了解，并通过查看其工作流程和架构来了解它是如何完成所有魔术的。

# 技术要求

要跟随本章的示例，您需要安装以下软件：

+   Eclipse ([`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)) 或 IntelliJ IDE ([`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/))

+   Git ([`git-scm.com/downloads`](https://git-scm.com/downloads))

+   Skaffold ([`skaffold.dev/docs/install/`](https://skaffold.dev/docs/install/))

+   Docker Desktop for macOS 和 Windows ([`www.docker.com/products/docker-desktop`](https://www.docker.com/products/docker-desktop))

您可以从 GitHub 存储库[`github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold`](https://github.com/PacktPublishing/Effortless-Cloud-Native-App-Development-Using-Skaffold)下载本章的代码示例。

# 理解 Skaffold 的功能

在[*第三章*]，*Skaffold – Easy-Peasy Cloud-Native Kubernetes Application Development*中，我们介绍了 Skaffold。我们通过构建和部署 Spring Boot 应用程序到本地 Kubernetes 集群来揭示了一些功能。然而，Skaffold 能做的远不止这些，让我们来看看它的一些功能。

Skaffold 具有以下功能：

+   **易于共享**：在同一团队或不同团队之间共享项目非常简单，只要他们已经安装了 Skaffold，就可以运行以下命令继续开发活动：

```
git clone repository URL
skaffold dev
```

+   **与 IDE 集成**：许多 IDE，如 IntelliJ 和 VS Code，支持由 Google 开发的**Cloud Code**插件，该插件内部使用 Skaffold 及其 API，在开发 Kubernetes 应用程序时提供更好的开发者体验。使用 IntelliJ 或 VS code 的**Google Cloud Code Extension**插件可以更轻松地使用其代码补全功能创建、编辑和更新`skaffold.yaml`文件。例如，为了让您对此有更多的上下文，插件可以通过查看`skaffold.yaml`配置文件来检测项目是否正在使用 Skaffold 进行构建和部署：

![图 4.1 – IntelliJ Cloud code 插件检测到 Skaffold 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.1_B17385.jpg)

图 4.1 – IntelliJ Cloud code 插件检测到 Skaffold 配置

您还可以使用代码补全功能查找 Skaffold 支持的构建器和部署器。我们将在*第七章*中专门介绍 Cloud Code 插件，*使用 Cloud Code 插件构建和部署 Spring Boot 应用程序*。

+   **文件同步**：Skaffold 具有出色的文件同步功能。它可以直接将更改的文件复制到已经运行的容器中，以避免重新构建、重新部署和重新启动容器。

我们将在*第五章*中了解更多信息，*安装 Skaffold 并揭秘其流水线阶段*。

+   **超快速本地开发**：在上一章中，您了解到使用 Skaffold 构建和部署应用程序非常快速，因为它可以确定您的 Kubernetes 上下文是否设置为本地 Kubernetes 集群，并且将避免将镜像推送到远程容器注册表。因此，您可以避免昂贵的网络跳跃，同时也可以延长笔记本电脑的电池寿命。

不仅如此，Skaffold 实时检测您的代码更改，并自动化构建、推送和部署工作流程。因此，您可以在内部开发循环中继续工作，专注于编码，而无需离开该循环，直到您完全确定所做的更改。这不仅加快了您的内部开发循环，还使您更加高效。

+   **轻松的远程开发**：到目前为止，在阅读本书时，你可能会认为 Skaffold 只能加速内部开发循环。哦，天哪！你会惊喜地发现 Skaffold 也可以处理外部开发循环工作流。例如，你可以使用 Skaffold 创建成熟的生产就绪的 CI/CD 流水线。我们将在*第九章*中具体介绍这一点，*使用 Skaffold 创建生产就绪的 CI/CD 流水线*。不仅如此，你还可以使用命令如`kubectl config use-context context-name`在本地开发环境中切换 Kubernetes 上下文，并将部署到你选择的远程集群。

由于我们正在讨论远程开发，我想强调另一点——如果你正在使用`jib-maven`插件进行远程构建（即，如果你要推送到远程容器注册表），你就不需要运行 Docker 守护进程。你也可以使用像**Google Cloud Build**这样的工具进行远程构建。Cloud Build 是**Google Cloud Platform**提供的一项服务，你可以使用它在云中执行构建，并为云原生应用程序创建无服务器 CI/CD 流水线。如果你从本地系统运行它可能会比较慢，但值得探索。

+   **内置镜像标签管理**：在上一章中，在声明 Kubernetes 部署清单时，我们只提到了镜像名称，而没有在构建和部署 Spring Boot 应用程序时提到镜像标签。例如，在上一章的以下片段中，在`image:`字段中，我们只提到了镜像名称：

```
 spec:
      containers:
        - image: docker.io/hiashish/skaffold-introduction
          name: skaffold-introduction
```

通常，我们必须在推送之前给镜像打标签，然后在拉取时使用相同的镜像标签。例如，你还必须以以下格式指定镜像标签：

```
- image: imagename:imagetag
```

这是因为 Skaffold 会在每次重新构建镜像时自动生成镜像标签，这样你就不必手动编辑 Kubernetes 清单文件。Skaffold 的默认标记策略是`gitCommit`。

我们将在*第五章*中更详细地介绍这一点，*安装 Skaffold 并揭秘其流水线阶段*。

+   **轻量级**：Skaffold 完全是一个 CLI 工具。在使用 Skaffold 时不需要寻找服务器端组件。这使得它非常轻量、易于使用，而且没有维护负担。Skaffold 二进制文件的大小约为 63MB。

+   **可插拔架构**：Skaffold 具有可插拔架构。这最终意味着您可以选择构建和部署工具。自带您自己的工具，Skaffold 将相应地调整自己。

+   **专为 CI/CD 流水线而设计**：Skaffold 可以帮助您创建有效的 CI/CD 流水线。例如，您可以使用`skaffold run`命令执行端到端的流水线，或者使用诸如`skaffold build`或`skaffold deploy`之类的单独命令。

此外，通过诸如`skaffold render`和`skaffold apply`之类的命令，您可以为应用程序创建**GitOps**风格的持续交付工作流程。GitOps 允许您将应用程序的期望状态存储在 Git 存储库中，以 Kubernetes 清单的形式。它还允许其他人将您的基础架构视为代码。

+   **轻松的环境管理**：Skaffold 允许您为不同的环境定义、构建、测试和部署配置。您可以为开发或分段保留一组配置，为生产保留另一组配置。此外，您可以根据每个环境保持完全不同的配置。您可以通过使用 Skaffold 配置文件来实现这一点。这与为 Spring Boot 应用程序提供的`profiles`功能相对类似。

请参考以下截图：

![图 4.2 – Skaffold 配置文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.2_B17385.jpg)

图 4.2 – Skaffold 配置文件

典型的 Skaffold 配置文件包括以下部分：

+   `构建`

+   `测试`

+   `激活`

+   `部署`

+   `名称`

+   `补丁`

其中一些部分是相当明显的，因为它们解释了配置文件的唯一名称、构建步骤、部署步骤以及如何测试图像。让我们继续讨论补丁和激活。

首先，让我们了解补丁。

### Skaffold 配置文件补丁

顾名思义，补丁是一种更详细的方式，用于覆盖`skaffold.yaml`文件中的单个值。例如，在以下代码片段中，`dev`配置文件定义了第一个构件的不同`Dockerfile`，而不是覆盖整个构建部分：

```
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-example
      docker:
        dockerfile: Dockerfile
    - image: docker.io/hiashish/skaffold2
    - image: docker.io/hiashish/skaffold3
deploy:
  kubectl:
    manifests:
      - k8s-pod
profiles:
  - name: dev
    patches:
      - op: replace 
        path: /build/artifacts/0/docker/dockerfile
        value: Dockerfile_dev
```

在这里，`patches`部分下面的`op`字符串指定了此补丁要执行的操作。`path`字符串指定了`.yaml`文件中您在`op`字符串中定义的操作发生的位置，`value`对象指定了应替换的值。

支持以下操作：

+   添加

+   删除

+   替换

+   移动

+   复制

+   测试

总之，在这里，我们指示 Skaffold 使用名为`Dockerfile_dev`的不同`Dockerfile`替换用于构建第一个`docker.io/hiashish/skaffold-example`镜像的`Dockerfile`。

现在，让我们讨论配置文件中的激活对象。

### Skaffold 配置文件激活

您可以通过以下两种方式之一在 Skaffold 中激活配置文件：

+   使用 CLI

+   使用`skaffold.yaml`激活

首先，让我们讨论如何使用 CLI 激活配置文件。例如，在下面的`skaffold.yaml`文件中，在`profiles`部分下面，我们声明了一个名为`gcb`的配置文件名称：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: skaffold-introduction
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: { }
deploy:
  kubectl:
    manifests:
      - k8s/mydeployment.yaml
      - k8s/myservice.yaml
profiles:
  - name: gcb
    build:
      googleCloudBuild:
        projectId: gke_projectid
```

当运行`skaffold run`或`skaffold dev`命令时，可以通过传递`--profile`或`-p`CLI 标志来激活此配置文件。如果运行以下命令，则 Skaffold 将使用**Google Cloud Build**来构建这些构件：

```
skaffold run -p gcb
```

请注意，我们在`gcb`配置文件下面没有指定`deploy`部分。这意味着 Skaffold 将继续使用`kubectl`进行部署。如果您的用例需要多个配置文件，您可以多次使用`-p`标志或传递逗号分隔的配置文件，如下面的命令所示：

```
skaffold dev -p profile1,profile2
```

让我们尝试使用另一个例子来理解这个。在这个例子中，我们将使用我们在*第三章*中构建的 Spring Boot 应用程序，*Skaffold – Easy-Peasy Cloud-Native Kubernetes Application Development*。在那种情况下，我们使用 Jib 来将应用程序容器化；然而，在这个例子中，我们将使用多阶段 Docker 构建来创建我们应用程序的精简 Docker 镜像。以下是我们 Spring Boot 应用程序的`Dockerfile`：

```
FROM maven:3-adoptopenjdk-16 as build
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN mvn clean package
FROM adoptopenjdk:16-jre
RUN mkdir /project
COPY --from=build /app/target/*.jar /project/app.jar
WORKDIR /project
ENTRYPOINT ["java","-jar","app.jar"]
```

我们可以解释多阶段`Dockerfile`构建如下：

+   在构建的第一阶段中，我们使用`maven:3-adoptopenjdk-16`镜像使用`mvn clean package` Maven 命令构建和创建了我们的应用程序的`jar`。

+   在第二阶段，我们复制了在上一个构建阶段中制作的`jar`并基于一个明显更小的*Java 16 JRE 基础镜像*创建了一个新的最终镜像。

+   最终的 Docker 镜像不包括 JDK 或 Maven 镜像，只包括 JRE 镜像。这种方法的唯一缺点是构建时间更长，因为在构建的第一阶段需要下载所有必需的依赖项。

提示

您可以使用 Docker 多阶段构建来创建更小的应用程序 Docker 镜像。典型的 JDK 镜像大小约为 650 MB，通过使用 JRE 作为多阶段构建的最后阶段的基础镜像，我们可以将其大小减半。

此外，您还可以使用 Java 工具如`jdeps`和`jlink`（在 Java 9 中引入）进一步减小镜像的大小。`jdeps`帮助您识别所需的 JVM 模块，`jlink`允许您创建定制的 JRE。通过这些工具的组合，您可以创建一个定制的 JRE，从而使您的应用程序的 Docker 镜像更加精简。

为了演示配置文件的使用，我们将对`skaffold.yaml`文件进行以下更改。以下是我们在`skaffold.yaml`文件中添加了一个名为`docker`的新配置文件：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: skaffold-introduction
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: { }
deploy:
  kubectl:
    manifests:
      - k8s/mydeployment.yaml
      - k8s/myservice.yaml
profiles:
  - name: docker
    build:
      artifacts:
        - image: docker.io/hiashish/skaffold-introduction
          docker:
            dockerfile: Dockerfile
```

我们将使用`skaffold run --profile docker`命令来构建和部署我们的 Spring Boot 应用程序。以下是输出：

```
Generating tags...
- docker.io/hiashish/skaffold-introduction -> docker.io/hiashish/skaffold-introduction:fcda757-dirty
Checking cache...
- docker.io/hiashish/skaffold-introduction: Not found. Building
Starting build...
Found [minikube] context, using local docker daemon.
Building [docker.io/hiashish/skaffold-introduction]...
Sending build context to Docker daemon  128.5kB
Step 1/10 : FROM maven:3-adoptopenjdk-16 as build
3-adoptopenjdk-16: Pulling from library/maven
........
ecf4fc483ced: Pull complete
Status: Downloaded newer image for maven:3-adoptopenjdk-16
---> 8bb5929b61c3
Step 2/10 : RUN mkdir /app
---> Running in ff5bf71356dc
---> 83040b88c925
Step 3/10 : COPY . /app
---> 5715636b31d8
Step 4/10 : WORKDIR /app
---> Running in 6de38bef1b56
---> ca82b0631625
Step 5/10 : RUN mvn clean package -DskipTests
---> Running in 91df70ce44fa
[INFO] Scanning for projects...
Downloading from repository.spring.milestone: https://repo.spring.io/milestone/org/springframework/boot/spring-boot-starter-parent/2.5.0-M1/spring-boot-starter-parent-2.5.0-M1.pom
........
[INFO] BUILD SUCCESS
```

在前面的日志中，您可以看到，首先，Skaffold 开始使用 Docker 构建我们的镜像。此外，我们使用了多阶段构建，然后在步骤 1 到 6 中，我们进入了构建的第一阶段，在其中我们在容器内创建了我们应用程序的`jar`：

```
Step 6/10 : FROM adoptopenjdk:16-jre
16-jre: Pulling from library/adoptopenjdk
c549ccf8d472: Already exists
........
23bb7f46497d: Pull complete
Digest: sha256:f2d0e6433fa7d172e312bad9d7b46ff227888926f2fe526 c731dd4de295ef887
Status: Downloaded newer image for adoptopenjdk:16-jre
---> 954409133efc
Step 7/10 : RUN mkdir /project
---> Running in abfd14b21ac6
---> 2ab11f2093a3
Step 8/10 : COPY --from=build /app/target/*.jar /project/app.jar
---> 52b596edfac9
Step 9/10 : WORKDIR /project
---> Running in 473cbb6d878d
---> b06856859039
Step 10/10 : ENTRYPOINT ["java","-jar","app.jar"]
---> Running in 6b22aee242d2
---> f62822733ebd
Successfully built f62822733ebd
Successfully tagged hiashish/skaffold-introduction:fcda757-dirty
```

在*步骤 6 到 10*中，我们处于构建的第二阶段，我们使用`adoptopenjdk:16-jre`作为基础镜像，因为我们只需要 JRE 来运行我们的应用程序。通常，JRE 镜像比 JDK 镜像要小。

这个最终的输出是我们的容器化应用程序，应该如下所示：

```
Starting test...
Tags used in deployment:
- docker.io/hiashish/skaffold-introduction -> docker.io/hiashish/skaffold-introduction:f62822733ebd832cab
 058e5b0282af6bb504f60be892eb074f980132e3630d88
Starting deploy...
- deployment.apps/skaffold-introduction created
- service/skaffold-introduction created
Waiting for deployments to stabilize...
- deployment/skaffold-introduction is ready.
Deployments stabilized in 4.378 seconds
```

最后，Skaffold 将我们的容器化应用部署到本地 Kubernetes 集群。

激活配置文件的另一种方法是在`skaffold.yaml`中使用激活对象数组自动激活配置文件，具体取决于以下内容：

+   `kubeContext`

+   一个环境变量：`env`

+   一个 Skaffold 命令

请参考以下截图：

![图 4.3 - 使用 skaffold.yaml 文件激活 Skaffold 配置文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.3_B17385.jpg)

图 4.3 - 使用 skaffold.yaml 文件激活 Skaffold 配置文件

让我们尝试使用一个例子来理解这个激活选项。

在下面的代码示例中，我们有两个配置文件——`profile-staging`和`profile-production`。正如它们的名称所暗示的，`profile-staging`将用于分段环境，而`profile-production`将用于生产环境：

```
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: { }
deploy:
  kubectl:
    manifests:
      - k8s/mydeployment.yaml
      - k8s/myservice.yaml
profiles:
  - name: profile-staging
    activation:
      - env: ENV=staging
  - name: profile-production
    build:
      googleCloudBuild:
        projectId: gke_projectid
    activation:
      - env: ENV=production
      - kubeContext: gke_cluster
        command: run
```

在这里，如果`ENV`环境变量键匹配值分段，`profile-staging`将自动激活。我们没有为此特定配置文件指定构建、测试和部署步骤，因此它将继续使用我们在`skaffold.yaml`文件的主要部分中提供的选项。除此之外，只有在满足以下条件时，`profile-production`才会自动激活。请注意，只有在满足所有这些条件时，它才会运行配置文件生产阶段：

+   `ENV`环境变量键匹配值生产。

+   Kubernetes 上下文设置为**GKE**（即**Google Kubernetes Engine**的缩写）。

+   使用的 Skaffold 命令是`scaffold run`。

请注意，`profile-production`将使用 Google 的 Cloud Build 进行构建，并默认使用`kubectl`进行部署（因为没有明确指定）。

这种分离还允许您在不同的环境中使用各种工具进行构建和部署。例如，您可能会在本地开发中使用 Docker 创建映像，而在生产中使用`Jib`。在部署的情况下，您可能会在开发中使用`kubectl`，而在生产中使用 Helm。

在上一章中，我解释了 Skaffold 默认情况下会从位于`${HOME}/.kube/config`路径的`kube config`文件中查找当前的 Kubernetes 上下文。如果您希望更改它，可以在运行`skaffold dev`命令时进行更改：

```
skaffold dev --kube-context <myrepo>
```

您还可以在`skaffold.yaml`文件中提到`kubeContext`，如下所示：

```
deploy:
  kubeContext: docker-desktop
```

通过 CLI 传递的标志优先于`skaffold.yaml`文件。

接下来，让我们讨论 Skaffold 如何配置或调整自己以适应不同的本地 Kubernetes 集群。

### 本地 Kubernetes 集群

到目前为止，您应该已经意识到 Skaffold 提供了明智的、智能的默认值，使开发过程更加轻松，而无需告诉它要做什么。如果您的 Kubernetes 上下文设置为本地 Kubernetes 集群，那么就没有必要将映像推送到远程 Kubernetes 集群。相反，Skaffold 将映像移动到本地 Docker 守护程序，以加快开发周期。

到目前为止，我们只讨论了与 Docker Desktop 一起提供的 Kubernetes 集群，但这并不是您唯一的选择。有多种方式可以设置和运行本地 Kubernetes 集群。例如，在创建本地 Kubernetes 集群时，您有以下选择：

+   Docker Desktop ([`docs.docker.com/desktop/kubernetes/#enable-kubernetes`](https://docs.docker.com/desktop/kubernetes/#enable-kubernetes))

+   Minikube ([`minikube.sigs.k8s.io/docs/`](https://minikube.sigs.k8s.io/docs/))

+   Kind ([`kind.sigs.k8s.io/`](https://kind.sigs.k8s.io/))

+   k3d ([`k3d.io/`](https://k3d.io/))

如果这些支持的 Kubernetes 安装可用于本地开发，则 Skaffold 期望 Kubernetes 的上下文如下表所示。否则，它将假定我们正在部署到远程 Kubernetes 集群。

根据以下表格中描述的 Kubernetes 上下文名称，Skaffold 会检测本地集群：

![表 4.1 - Skaffold 支持的 Kubernetes 上下文](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Table_4.1_B17385.jpg)

表 4.1 - Skaffold 支持的 Kubernetes 上下文

然而，对于其他非标准的本地集群设置，比如使用自定义配置运行`minikube`（例如，`minikube` `start -p my-profile`），您可以使用以下命令告诉 Skaffold 您正在使用本地 Kubernetes 集群：

1.  首先，使用以下命令为 Skaffold 设置 Docker 环境：

```
source <(minikube docker-env -p my-profile)
```

1.  然后，使用以下命令指示 Skaffold 将`my-profile`视为本地集群：

```
$ skaffold config set --kube-context my-profile local-cluster true
```

在本节中，我们深入探讨了 Skaffold 提供的功能。现在，让我们讨论 Skaffold 的架构。

# 解密 Skaffold 的架构

如前所述，Skaffold 的设计考虑了可插拔性。以下是 Skaffold 架构的可视化：

![图 4.4 - Skaffold 架构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.4_B17385.jpg)

图 4.4 - Skaffold 架构

从这个架构图中，您可以得出结论，Skaffold 具有模块化设计。但是，什么是模块化设计？

嗯，模块化设计，或者说设计中的模块化，是一种将系统细分为称为模块的较小部分的设计原则，这些模块可以独立创建、修改、替换或与其他模块或不同系统之间交换。

有了这个定义，我们可以为 Skaffold 定义以下模块：

+   容器镜像构建器

+   容器测试工具/策略

+   容器映像标签器

+   容器部署工具

现在，让我们更详细地讨论每个这些工具/模块。目前，Skaffold 支持以下容器映像构建器：

+   **Dockerfile**

+   **Jib（Maven 和 Gradle）**

+   **Bazel**

+   **Cloud-Native Buildpacks**

+   **自定义脚本**

对于部署到 Kubernetes，Skaffold 支持以下工具：

+   **Helm**

+   **kubectl**

+   **kustomize**

我们将在*第六章*中更详细地讨论这些选项，*使用 Skaffold 容器映像构建器和部署器*。

Skaffold 支持管道阶段之间的以下类型测试：

+   自定义测试

+   容器结构测试

我们将在*第五章*中进一步探讨这些选项，*安装 Skaffold 并揭秘其流水线阶段*。

如前所述，在 Skaffold 的**功能**部分下，Skaffold 提供了内置的映像标签管理。目前，Skaffold 支持多个标签器和标签策略来对映像进行标记：

+   `gitCommit`标签器

+   `inputDigest`标签器

+   `envTemplate`标签器

+   `datetime`标签器

+   `customTemplate`标签器

+   `sha256`标签器

通过 IntelliJ Cloud Code 插件的代码完成功能，很容易知道支持哪种映像标签策略。假设您没有在`skaffold.yaml`文件中指定映像标签策略；在这种情况下，默认策略是`gitCommit`标签器：

看一下以下截图：

![图 4.5 – Skaffold 支持的映像标签策略](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.5_B17385.jpg)

图 4.5 – Skaffold 支持的映像标签策略

现在，考虑到 Skaffold 的可插拔架构，您可以使用**本地 Docker 守护程序**来构建映像，使用`kubectl`部署到`minikube`，或者任何其他支持的本地 Kubernetes 集群。在这种情况下，Skaffold 将不会将映像推送到远程注册表，您甚至可以通过使用`-skipTests`标志跳过容器结构测试。

以下图表显示了在这种情况下用于本地开发的工具：

![图 4.6 – Skaffold 在开发中](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.6_B17385.jpg)

图 4.6 – Skaffold 在开发中

而在生产场景中，您可能会使用 Jib Maven 或 Gradle 插件来构建映像，测试构件，将其推送到远程注册表，最后使用 Helm 将其部署到远程 Kubernetes 集群。

以下图表显示了生产场景中使用的工具：

![图 4.7–生产中的 Skaffold](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.7_B17385.jpg)

图 4.7–生产中的 Skaffold

这完成了我们对 Skaffold 架构的深入分析。现在，让我们讨论 Skaffold 的工作流程。

# 理解 Skaffold 的工作流程

通常，Skaffold 以两种模式工作，即*连续开发*或*端到端管道*，通过命令如`skaffold dev`和`skaffold run`。例如，当您运行`skaffold dev`命令时，Skaffold 将执行以下步骤：

1.  接收并监视您的源代码更改。

1.  如果用户将更改的文件标记为可复制，则直接将其复制到`build`中。

1.  从源代码构建您的构件。

1.  使用`container-structure-tests`或自定义脚本测试您构建的构件。

1.  为您的构件打标签。

1.  推送您的构件（仅当 Kubernetes 上下文设置为远程集群时）。

1.  使用正确的标签更新 Kubernetes 清单。

1.  部署您的构件。

1.  使用内置的健康检查监视部署的构件。

1.  从正在运行的 pod 中流式传输日志。

1.  通过按下*Ctrl + C*清除退出时部署的任何构件。

在`skaffold run`命令的情况下，工作流程相对类似。唯一的区别是以下内容：

+   Skaffold 不会持续监视代码更改。

+   默认情况下，Skaffold 不会从正在运行的 pod 中流式传输日志。

+   在端到端管道模式结束后，Skaffold 将在*步骤 9*之后退出。

以下图表说明了我们在前面步骤中解释的连续开发和端到端管道：

![图 4.8–Skaffold 工作流程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Figure_4.8_B17385.jpg)

图 4.8–Skaffold 工作流程

现在，您应该了解了 Skaffold 在连续开发和端到端管道模式下的工作方式。让我们看一下`skaffold.yaml`文件中可用的组件。

# 使用 skaffold.yaml 解析 Skaffold 的配置

Skaffold 需要执行的任何操作都应在`skaffold.yaml`配置文件中明确定义。在此配置文件中，您必须指定 Skaffold 必须使用哪个工具来构建图像，然后将其部署到 Kubernetes 集群。Skaffold 通常期望在当前目录中找到配置文件`skaffold.yaml`；但是，我们可以使用`--filename`标志覆盖位置。

提示

我们建议您将 Skaffold 配置文件保存在项目的根目录中。

配置文件包括以下主要组件：

![表 4.2 - skaffold.yaml 文件组件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Table_4.2_B17385.jpg)

表 4.2 - skaffold.yaml 文件组件

Skaffold 还支持一个全局配置文件，位于`~/.skaffold/config`路径下。以下是它支持的选项，可以在全局级别定义：

![表 4.3 - Skaffold 全局配置选项](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/Table_4.3_B17385.jpg)

表 4.3 - Skaffold 全局配置选项

您可以使用以下命令轻松在命令行中列出、设置和取消这些选项：

```
$ skaffold config
Interact with the Skaffold configuration
Available Commands:
  list        List all values set in the global Skaffold config
  set         Set a value in the global Skaffold config
  unset       Unset a value in the global Skaffold config
```

例如，您可以将本地集群选项设置为 false。这将允许您在构建图像后将图像推送到远程注册表。请参考以下命令：

```
$ skaffold config set --global local-cluster false
set global value local-cluster to false
$ cat ~/.skaffold/config
global:
  local-cluster: false
  survey:
    last-prompted: "2021-03-20T13:42:49+05:30"
  collect-metrics: true
```

同样，您可以使用以下命令取消配置：

```
$ skaffold config unset --global local-cluster
unset global value local-cluster
$ cat ~/.skaffold/config
global:
  survey:
    last-prompted: "2021-03-20T13:42:49+05:30"
  collect-metrics: true
kubeContexts: []
```

在本节中，我们介绍了`skaffold.yaml`配置文件的组件。我们还看了一些可以通过 Skaffold CLI 命令设置的全局配置设置。

# 总结

本章向您介绍了 Skaffold 的一些特点，例如超快速的本地开发、轻松的远程开发、内置标签管理、轻量级能力和文件同步能力等。这些是令人信服的功能，将帮助您改善开发人员体验。此外，我们还看了 Skaffold 的架构，并发现 Skaffold 具有可插拔的架构。这意味着您可以随时携带自己的工具来构建和部署应用程序。接下来，我们介绍了 Skaffold 开发工作流程中通常发生的步骤。最后，在本章末尾，我们研究了 Skaffold 的主要组件和一些通过 Skaffold 配置支持的全局配置。

在本章中，主要目标是通过查看其架构和典型的开发工作流程，让您深入了解 Skaffold 的特性和内部工作原理。您已经对 Skaffold 有了深入的了解，现在您将更容易地连接前后章节之间的关系。

在下一章中，我们将介绍安装 Skaffold 的不同方法。此外，我们将探索 Skaffold CLI 命令。

# 参考

+   官方 Skaffold 文档([`skaffold.dev/docs/`](https://skaffold.dev/docs/))


# 第五章：安装 Skaffold 并揭秘其流水线阶段

在上一章中，我们深入了解了 Skaffold 的架构和工作流程。我们还看了 Skaffold 的配置。本章将介绍如何在不同操作系统上安装 Skaffold，如 Linux、Windows 和 macOS。我们还将探讨常见的 CLI 命令以及如何在 Skaffold 的不同流水线阶段中使用这些命令。

在本章中，我们将讨论以下主要主题：

+   安装 Skaffold

+   理解常见的 CLI 命令

+   理解 Skaffold 的流水线阶段

+   使用 Skaffold 进行调试

在本章结束时，您将了解如何在不同平台上安装 Skaffold。您还将对 Skaffold 最常用的 CLI 命令有扎实的理解。

# 技术要求

要跟着本章的示例进行操作，您需要以下内容：

+   Skaffold CLI ([`skaffold.dev/docs/install/`](https://skaffold.dev/docs/install/))

+   minikube ([`minikube.sigs.k8s.io/docs/`](https://minikube.sigs.k8s.io/docs/)) 或者 macOS 和 Windows 上的 Docker Desktop ([`www.docker.com/products/dockerdesktop`](https://www.docker.com/products/dockerdesktop))

# 安装 Skaffold

Skaffold 作为一个 CLI 工具，需要首先在您喜欢的操作系统上下载和安装。以下是支持的平台，您可以在这些平台上下载和安装 Skaffold：

+   Linux

+   macOS

+   Windows

+   Docker

+   Google Cloud SDK

让我们详细讨论这些选项。

## 在 Linux 上安装 Skaffold

对于 Linux，您可以使用以下 URL 来下载最新的稳定版本 Skaffold：

+   [`storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64`](https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64)

+   [`storage.googleapis.com/skaffold/releases/latest/skaffold-linux-arm64`](https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-arm64)

下载二进制文件后，您可以将其添加到`PATH`变量中。或者，您可以使用以下命令。

对于 AMD64 上的 Linux，请使用以下命令：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64 && \sudo install skaffold /usr/local/bin/
```

对于 ARM64 上的 Linux，请使用以下命令：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-arm64 && \sudo install skaffold /usr/local/bin/
```

还有一个最新版本的 Skaffold，它是使用最新提交构建的。它可能不是一个稳定的版本，所以在使用时要小心。您可以使用以下 URL 来下载最新版本的 Skaffold。

对于 AMD64 上的 Linux，请执行以下操作：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/builds/latest/skaffold-linux-amd64 && \sudo install skaffold /usr/local/bin/
```

对于 ARM64 架构的 Linux，请执行以下操作：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/builds/latest/skaffold-linux-arm64 && \sudo install skaffold /usr/local/bin/
```

在本节中，我们查看了在 Linux 操作系统（OS）上安装 Skaffold 的命令。

## 在 macOS 上安装 Skaffold

对于 macOS，您可以使用以下 URL 下载 Skaffold 的最新稳定版本：

+   [`storage.googleapis.com/skaffold/releases/latest/skaffold-darwin-amd64`](https://storage.googleapis.com/skaffold/releases/latest/skaffold-darwin-amd64)

+   [`storage.googleapis.com/skaffold/releases/latest/skaffold-darwin-arm64`](https://storage.googleapis.com/skaffold/releases/latest/skaffold-darwin-arm64)

下载二进制文件后，您可以将其添加到`PATH`变量中。或者，您可以使用以下命令。

对于 AMD64 架构的 macOS，请使用以下命令：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-darwin-amd64 && \sudo install skaffold /usr/local/bin/
```

对于 ARM64 架构的 macOS，请使用以下命令：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-darwin-amd64 && \sudo install skaffold /usr/local/bin/
```

要下载具有最新提交的构建，可以使用以下命令。

对于 AMD64 架构的 macOS，请使用以下命令：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/builds/latest/skaffold-darwin-amd64 && \sudo install skaffold /usr/local/bin/
```

对于 ARM64 架构的 macOS，请使用以下命令：

```
curl -Lo skaffold https://storage.googleapis.com/skaffold/builds/latest/skaffold-darwin-amd64 && \sudo install skaffold /usr/local/bin/
```

特别是对于 macOS，您可以使用以下软件包管理器下载 Skaffold。

对于 Homebrew，请使用以下命令：

```
brew install skaffold
```

对于 MacPorts，请使用以下命令：

```
sudo port install skaffold
```

在本节中，我们探讨了在 macOS 上安装 Skaffold 的各种命令。

## 在 Windows 上安装 Skaffold

对于 Windows，您可以使用以下 URL 下载 Skaffold 的最新稳定版本：

[`storage.googleapis.com/skaffold/releases/latest/skaffold-windows-amd64.exe`](https://storage.googleapis.com/skaffold/releases/latest/skaffold-windows-amd64.exe)

下载 EXE 文件后，您可以将其添加到`PATH`变量中。

要下载具有最新提交的构建，可以使用以下 URL：

[`storage.googleapis.com/skaffold/builds/latest/skaffold-windows-amd64.exe`](https://storage.googleapis.com/skaffold/builds/latest/skaffold-windows-amd64.exe)

特别是对于 Windows，您可以使用以下 Chocolatey 软件包管理器命令下载 Skaffold：

```
choco install -y skaffold
```

以下是输出：

![图 5.1 - 在 Windows 上安装 Skaffold](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.1.jpg)

图 5.1 - 在 Windows 上安装 Skaffold

注意

`skaffold dev`命令存在已知问题（https://github.com/chocolatey/shimgen/issues/32），在 Windows 上使用 Chocolatey 软件包管理器安装时，按下*Ctrl* + *C*时 Skaffold 不会清理部署。问题与 Skaffold 无关，而是与 Chocolatey 在安装过程中如何干扰*Ctrl* + *C*处理有关。

本节介绍了如何在 Windows 上安装 Skaffold。

## 使用 Docker 安装 Skaffold

您还可以下载并在 Docker 容器中运行 Skaffold。要做到这一点，您可以使用以下`docker run`命令：

```
docker run gcr.io/k8s-skaffold/skaffold:latest skaffold <command>
```

要使用最新提交的边缘构建，您可以使用以下命令：

```
docker run gcr.io/k8s-skaffold/skaffold:edge skaffold <command>
```

我想强调一个关于使用 Docker 图像的 Skaffold 的要点。 Docker 图像的大小约为~3.83 GB，这对于 Skaffold 来说似乎过大，因为在*第三章*中，*Skaffold – Easy-Peasy Cloud-Native Kubernetes Application Development*，我们了解到 Skaffold 的二进制大小约为~63 MB。这可以在以下截图中看到：

![图 5.2 – Skaffold Docker 图像大小](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.2.jpg)

图 5.2 – Skaffold Docker 图像大小

那么，为什么图像大小如此之大？这是因为图像还包含其他工具，如 gcloud SDK，kind，minikube，k3d，kompose 和 bazel 等。

您可以使用 Dive CLI 验证容器图像中的内容。

提示

Dive 允许您检查图像层的内容，并建议不同的方法来缩小图像的大小，如果您浪费了任何空间。

您可以按照[`github.com/wagoodman/dive#installation`](https://github.com/wagoodman/dive#installation)上的说明下载 Dive。运行以下命令以查看容器图像的内部视图：

```
$ dive image tag/id/digest
```

以下是 Skaffold docker 图像的输出，其中包含一个图像层：

![图 5.3 – Skaffold Docker 图像层](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.3.jpg)

图 5.3 – Skaffold Docker 图像层

从图像内部的层可以看出，我们有许多可用的工具，而不仅仅是 Skaffold。使用此 Docker 图像的另一个优势是，您不必单独安装这些工具，而且可以使用相同的图像来玩耍或尝试这些工具。

本节介绍了如何使用 Docker 图像安装 Skaffold。

## 使用 gcloud 安装 Skaffold

Google 开发了 Skaffold，因此它很好地适应了 Google 产品生态系统。如果您的机器上安装了**Google 的 Cloud SDK**，您可以使用`gcloud components install skaffold`命令来安装 Skaffold。

我们将在*第八章*中介绍如何安装 gcloud SDK，*使用 Skaffold 将 Spring Boot 应用部署到 Google Kubernetes Engine*。目前，我们可以假设 Cloud SDK 已经安装。您可以使用`gcloud list`命令查看已安装和未安装的组件。以下是输出：

![图 5.4 – gcloud list 命令输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.4.jpg)

图 5.4 – gcloud list 命令输出

从前面的输出可以清楚地看出，Skaffold 未安装。虽然这不是强制性的，但在我们继续安装之前，请确保已安装`gcloud`并且其组件是最新的。我们可以运行以下命令来执行此操作：

```
gcloud components update
```

最后，我们可以使用以下`gcloud`命令安装 Skaffold：

```
gcloud components install skaffold
```

以下是输出：

![图 5.5 – 通过 gcloud 安装 Skaffold](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.5.jpg)

图 5.5 – 通过 gcloud 安装 Skaffold

在本节中，我们讨论了安装 Skaffold 的不同方法。现在，让我们讨论 Skaffold CLI 命令。

# 理解常见的 CLI 命令

到目前为止，我们已经向您介绍了诸如`skaffold dev`和`skaffold run`之类的命令，但是还有许多类似的命令，您可以在 CI/CD 流水线中使用这些命令来创建端到端的流水线或单独使用。我们将把这些命令分类如下。您还可以通过启用`skaffold completion bash/zsh`命令并在输入命令后按*Tab*键来发现这些命令的支持选项：

+   **端到端流水线的命令**：

+   `skaffold run`：此命令允许您构建和部署一次。

+   `skaffold dev`：此命令允许您触发用于构建和部署的持续开发循环。此工作流将在退出时清理。

+   `skaffold debug`：此命令允许您以*调试模式*触发用于构建和部署流水线的持续开发循环。此工作流也将在退出时清理。

+   **CI/CD 流水线的命令**：

+   `skaffold build`：此命令允许您只构建、标记和推送您的镜像。

+   `skaffold test`：此命令允许您针对构建的应用程序镜像运行测试。

+   `skaffold deploy`：此命令允许您部署给定的镜像。

+   `skaffold delete`：此命令允许您清理已部署的构件。

+   `skaffold render`：此命令允许您构建应用程序映像，然后将经过填充（使用新构建的映像标签）的 Kubernetes 清单导出到文件或终端。

+   `skaffold apply`：此命令以模板化的 Kubernetes 清单作为输入，在目标集群上创建资源。

+   **入门命令**：

+   `skaffod init`：此命令允许您引导 Skaffold 配置。

+   `skaffold fix`：此命令允许您升级模式版本。

+   **其他命令**：

+   `skaffold help`：此命令允许您打印帮助信息。使用`skaffold options`获取全局命令行选项的列表（适用于所有命令）。

+   `skaffold version`：此命令允许您获取 Skaffold 的版本。

+   `skaffold completion`：此命令允许您为 CLI 设置选项卡完成。它支持与`skaffold version`相同的选项。

+   `skaffold config`：此命令允许您管理特定上下文的参数。它支持与`skaffold version`相同的选项。

+   `skaffold credits`：此命令允许您将第三方通知导出到指定路径（默认为`./skaffold-credits`）。它支持与`skaffold version`相同的选项。

+   `skaffold diagnose`：此命令允许您运行对 Skaffold 在您的项目中的诊断。

+   `skaffold schema`：此命令允许您列出并打印用于验证`skaffold.yaml`配置的 JSON 模式。它支持与`skaffold version`相同的选项。

在本节中，我们讨论了 Skaffold 命令及其用法。在下一节中，我们将尝试了解 Skaffold 的不同流水线阶段。

# 了解 Skaffold 流水线阶段

到目前为止，我们已经对 Skaffold 的工作原理有了基本的了解。从前面的章节中，我们知道它会选择项目中的源代码更改，并使用您选择的工具创建容器映像；一旦成功构建，这些映像将根据您的要求进行标记，并推送到您指定的存储库。Skaffold 还可以帮助您在工作流程结束时将这些构件部署到您的 Kubernetes 集群中，再次使用您喜欢的工具。

Skaffold 允许您跳过阶段。例如，如果您在本地使用 Minikube 或 Docker 桌面运行 Kubernetes，Skaffold 足够智能，会为您做出选择，并不会将构件推送到远程存储库。

让我们详细了解 Skaffold 的流水线阶段，以了解每个流水线阶段中我们还有哪些选择。Skaffold 流水线阶段可以大致分为以下几个领域：

+   初始化

+   构建

+   标签

+   测试

+   部署

+   文件

+   日志尾随

+   端口转发

+   清理

让我们详细讨论每个。

## 初始化阶段

在这个阶段，我们通常会生成一个基本的 Skaffold 配置文件，以便在几秒钟内启动和运行您的项目。Skaffold 会查看您的项目目录中是否有任何构建配置文件，比如`Dockerfile`、`build.gradle`和`pom.xml`，然后自动生成构建和部署配置。

Skaffold 目前支持以下构建工具的构建检测：

+   Docker

+   Jib

+   Buildpacks

如果 Skaffold 检测到多个构建配置文件，它将提示您将构建配置文件与在部署配置中检测到的任何镜像配对。

提示

从 Skaffold v1.27.0 开始，您不再需要在`skaffold init`命令中提供`XXenableJibInit`或`XXenableBuildpacksInit`标志，因为它们的默认值已设置为`true`。这也意味着`init`命令将检测您是否应该根据项目使用 Jib 或 Buildpacks，无需指定这些标志。

例如，在运行`skaffold init`命令后，您可能会被要求从以下选项中选择。在这个例子中，我们在根目录中有一个`Dockerfile`，所以 Skaffold 要求您选择此项目的构建配置：

![图 5.6 – skaffold init 提示](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.6.jpg)

图 5.6 – skaffold init 提示

同样，对于部署，Skaffold 将查看您的项目目录，如果检测到一些 Kubernetes 清单 – 即`deployment.yaml`或`sevice.yaml` – 已经存在，那么它将自动将它们添加到`skaffold.yaml`文件的`deploy`部分：

![图 5.7 – 生成 Skaffold 配置文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.7.jpg)

图 5.7 – 生成 Skaffold 配置文件

如果您没有准备好清单，但希望 Skaffold 处理清单生成部分，那么不用担心 – 您可以在`skaffold init`命令中传递`--generate-manifests`标志。

## 构建阶段

Skaffold 支持各种工具进行镜像构建。

从下表中，您可以了解到镜像构建可以在本地、集群中或远程使用 Google Cloud Build 进行：

![表 5.1– Skaffold 支持的容器镜像构建工具](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.8.jpg)

表 5.1– Skaffold 支持的容器镜像构建器

我们将在*第六章*中了解更多关于这些选项的内容，*使用 Skaffold 容器镜像构建器和部署器*。在集群中，构建由 kaniko 或使用自定义脚本支持。远程构建仅支持使用 Cloud Build 的 Dockerfile、Jib 和 Buildpacks。对于本地构建，您几乎可以使用任何受支持的图像构建方法。

您可以通过`skaffold.yaml`文件的`build`部分设置构建配置。以下是一个示例：

```
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: {}
```

既然我们已经讨论了构建阶段，接下来，我们将看一下标记阶段。

## 标记阶段

Skaffold 支持以下图像标记策略：

+   标记可通过`gitCommit 标记器`进行，它利用 Git 提交来标记图像。

+   标记可通过`sha256 标记器`进行，该标记器使用最新标记来标记图像。

+   标记可通过`envTemplate 标记器`进行，它使用**环境变量**来标记图像。

+   标记可通过`dateTime 标记器`进行，它接受当前的**日期和时间**以及可配置的模式。

+   标记可通过`customTemplate 标记器`进行，它使用现有标记器作为模板的组件组合。

可以使用`skaffold.yaml`的`build`部分中的`tagPolicy`字段来配置图像标记策略。如果未指定`tagPolicy`，则默认为`gitCommit`策略。请参考以下代码片段：

```
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: {}
  tagPolicy: 
    sha256: {}
```

既然我们已经了解了 Skaffold 的不同图像标记策略，我们将进入测试阶段。

## 测试阶段

Skaffold 在构建和部署之间有一个集成测试阶段。它支持容器结构测试和集成测试的自定义测试。让我们详细讨论一下。

### 容器结构测试

Skaffold 支持在使用 Skaffold 构建的容器镜像上运行容器结构测试（https://github.com/GoogleContainerTools/container-structure-test）。容器结构测试框架主要旨在验证容器的内容和结构。例如，我们可能想在容器内运行一些命令，以测试它是否成功执行。我们可以在 Skaffold 配置中为每个图像定义测试。构建完毕后，Skaffold 将在该图像上运行相关的结构测试。如果测试失败，Skaffold 将不会继续部署。

自定义测试

使用 Skaffold 自定义测试，开发人员可以在其开发循环的一部分运行自定义命令。自定义测试将在将镜像部署到 Kubernetes 集群之前运行。该命令将在执行 Skaffold 的本地机器上执行，并与所有支持的 Skaffold 平台一起工作。您可以使用`--skip-tests`标志选择不运行自定义测试。您可以使用`skaffold test`命令单独运行测试。

以下是自定义测试的一些用例：

+   运行单元测试

+   使用 GCP Container Analysis 或 Anchore Grype 在图像上运行验证和安全扫描

+   我们还可以使用**kubeval**（[`github.com/instrumenta/kubeval`](https://github.com/instrumenta/kubeval)）或**kubeconform**（[`github.com/yannh/kubeconform`](https://github.com/yannh/kubeconform)）等工具，在部署前验证 Kubernetes 清单。

+   在 Helm 图表的情况下，我们可以在部署前使用**helm lint**命令。

在以下示例中，我们有一个名为`test`的配置文件，并且我们正在使用`mvn test`命令运行各种测试。我们将在此处使用`skaffold dev --profile=test`命令，该命令在构建后和部署前运行测试：

```
profiles:
  - name: test
    test:
      - image: docker.io/hiashish/skaffold-introduction
        custom:
          - command: mvn test -Dmaven.test.skip=false
```

在日志中，您将看到以下内容，其中说明测试已经开始，并且没有失败：

```
Starting test...
Testing images...
Running custom test command: "mvn test -Dmaven.test.skip
=false"
[INFO] Results:
[INFO] 
[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
```

有了这些，我们已经学会了如何使用 Skaffold 执行自定义测试。在部署阶段，我们将学习如何使用 Skaffold 部署应用程序。

## 部署阶段

Skaffold 部署阶段通常通过将 Kubernetes 清单中的未标记的镜像名称替换为最终标记的镜像名称来呈现 Kubernetes 清单。它还可能通过扩展 helm 的模板或计算 kustomize 的叠加来进行额外的中间步骤。然后，Skaffold 将最终的 Kubernetes 清单部署到集群中。为了确保部署发生，理想情况下，它将通过健康检查等待部署的资源稳定。

健康检查默认启用，并且是 CI/CD 流水线用例的一个重要功能，以确保部署的资源健康，并且可以在流水线中进一步进行。Skaffold 内部使用`kubectl rollout status`命令来测试部署的状态。

例如，在以下日志中，您可以看到 Skaffold 等待部署稳定：

```
Starting test...
Tags used in deployment:
 - docker.io/hiashish/skaffold-introduction -> docker.io/hiashish/skaffold-introduction:fcda757-dirty@sha256:f07c1dc192 cf5f391a1c5af8dd994b51f7b6e353a087cbcc49e754367c8825cc
Starting deploy...
 - deployment.apps/skaffold-introduction created
 - service/skaffold-introduction created
Waiting for deployments to stabilize...
 - deployment/skaffold-introduction: 0/4 nodes are available: 2 Insufficient memory, 4 Insufficient cpu.
    - pod/skaffold-introduction-59b479ddcb-f8ljj: 0/4 nodes are available: 2 Insufficient memory, 4 Insufficient cpu.
 - deployment/skaffold-introduction is ready.
Deployments stabilized in 56.784 seconds
Press Ctrl+C to exit
Watching for changes...
```

Skaffold 目前支持以下工具，用于将应用程序部署到本地或远程 Kubernetes 集群：

+   `kubectl`

+   `helm`

+   `kustomize`

您可以通过`skaffold.yaml`文件的`deploy`部分设置部署配置，如下所示：

```
deploy:
  kubectl:
    manifests:
      - k8s/mydeployment.yaml
      - k8s/myservice.yaml
```

通过这样，我们学会了如何使用 Skaffold 将镜像部署到 Kubernetes。接下来，我们将探讨如何使用文件同步直接将更改同步到 pod，而无需重新构建和重新部署镜像。

## 文件同步

Skaffold 具有一个很棒的功能，可以将更改的文件复制到部署的容器中，而无需重新构建、重新部署和重新启动相应的 pod。我们可以通过在`skaffold.yaml`文件的构件中添加带有同步规则的`sync`部分来启用此文件复制功能。在内部，Skaffold 创建一个包含与我们在`skaffold.yaml`文件中定义的同步规则匹配的更改文件的`.tar`文件。然后，这个`.tar`文件被传输到相应的容器中并在其中解压。

Skaffold 支持以下类型的同步：

+   `manual`：在此模式下，我们需要指定本地源文件路径和运行容器的目标路径。

+   `infer`：在此模式下，Skaffold 将通过查看您的 Dockerfile 来推断目标路径。在同步规则下，您可以指定哪些文件适合同步。

+   `auto`：在此模式下，Skaffold 将自动生成已知文件类型的同步规则。

为了理解**文件同步**功能，我们将使用我们在*第三章*中构建的 Spring Boot 应用程序，*Skaffold – Easy-Peasy Cloud-Native Kubernetes Application Development*。Spring Boot 应用程序公开了一个`/states` REST 端点，将返回所有印度各邦及其首府。我们在`skaffold.yaml`文件中添加了一个名为 sync 的新配置文件。

在下面的`skaffold.yaml`文件中，我们使用`jib`作为镜像构建器。Jib 与 Skaffold 集成允许您在更改后自动同步类文件、资源文件和 Jib 的额外目录文件到远程容器。但是，它只能与 Jib 一起在默认构建模式（exploded）下用于非 WAR 应用程序，因为存在一些限制。您还需要在项目中添加 Spring Boot 开发工具依赖项才能使其工作。它还可以与任何能够重新加载或重启的嵌入式服务器一起工作：

```
apiVersion: skaffold/v2beta20
kind: Config
metadata:
  name: skaffold-introduction
build:
  artifacts:
    - image: docker.io/hiashish/skaffold-introduction
      jib: { }
deploy:
  kubectl:
    manifests:
      - k8s/mydeployment.yaml
      - k8s/myservice.yaml
profiles:
  - name: sync
    build:
      artifacts:
        - image: docker.io/hiashish/skaffold-introduction
          jib: {}
          sync: 
            auto: true
```

在 Spring Boot 应用程序中，我们故意将班加罗尔的名称更改为班加罗尔。在运行`skaffold dev --profile=sync`命令后，您将在输出中看到以下内容：

![图 5.8 - 同步前的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.9.jpg)

图 5.8 - 同步前的输出

现在，由于我们将 Jib 的自动同步设置为`true`，对`schema.sql`文件所做的任何更改都将直接与在 Kubernetes 集群内运行的 pod 同步。我们对`schema.sql`文件进行了更改，它们通过重新启动应用程序直接与运行中的 pod 同步。在这里，我们不必重新构建镜像、推送镜像、重新部署镜像或重新启动 pod。在进行此更改后，您将在控制台的流式日志中看到以下输出：

```
: Completed initialization in 3 ms
[skaffold-introduction] 2021-07-18 21:07:03.279  INFO 1 --- [nio-8080-exec-1] c.p.c.indianstates.StateController       : Getting all states.
Syncing 1 files for docker.io/hiashish/skaffold-introduction:fcda757-dirty@sha256:f07c1dc192cf5f391a1c5af8d
d994b51f7b6e353a087cbcc49e754367c8825cc
Watching for changes...
```

再次访问 URL 后，您将看到更改后的输出：

![图 5.9 - 同步后的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.10.jpg)

图 5.9 - 同步后的输出

`schema.sql`在我们的资源下，所以让我们看看当我们对 Java 类文件进行更改时，是否也会被同步。让我们试一试。

为了测试这一点，我将调整我们在`StateController`类中的日志记录语句。我们有以下日志记录语句：

```
LOGGER.info("Getting all states.");
```

我们将其更改为以下内容：

```
LOGGER.info("Getting all Indian states and their capitals.");
```

在进行这些更改后，您应该在控制台的流式日志中看到以下内容。您可能会想知道为什么有五个文件被同步，因为我们只改变了一个文件。嗯，原因是 Jib 传输了整个层，其中包含您的类文件：

```
: Completed initialization in 3 ms
[skaffold-introduction] 2021-07-18 21:19:52.941  INFO 1 --- [nio-8080-exec-2] c.p.c.indianstates.StateController       : Getting all states.
Syncing 5 files for docker.io/hiashish/skaffold-introduction:fcda757-dirty@sha256:f07c1dc192cf5f391a1c5af
8dd994b51f7b6e353a087cbcc49e754367c8825cc
Watching for changes...
```

同样，在流式日志中，我们将看到更改后的日志记录语句。

```
[skaffold-introduction] 2021-07-18 21:40:46.868  INFO 1 --- [nio-8080-exec-1] c.p.c.indianstates.StateController       : Getting all Indian states and their capitals.
```

通过这样，我们已经了解了 Skaffold 的直接文件同步功能。现在，让我们了解如何使用各种 Skaffold 命令尾随日志。

## 日志尾随

Skaffold 可以为其构建和部署的容器尾随日志。有了这个功能，当您执行`skaffold dev`、`skaffold debug`或`skaffold run`时，您可以从集群尾随日志到本地机器。

默认情况下，skaffold `dev`和`skaffold debug`模式启用了日志尾随。对于 skaffold `run`，您可以使用`--tail`标志显式启用日志尾随。

对于典型的 Spring Boot 应用程序，您将在使用`skaffold dev`构建和部署后，在尾随日志中看到以下内容。

在下面的日志中，您可以看到成功构建并部署到集群后，应用程序日志被流式传输到控制台：

```
Starting test...
Tags used in deployment:
 - docker.io/hiashish/skaffold-introduction -> docker.io/hiashish/skaffold-introduction:fcda757-dirty@sha256:f07c1dc1 92cf5f391a1c5af8dd994b51f7b6e353a087cbcc49e754367c8825cc
Starting deploy...
 - deployment.apps/skaffold-introduction created
 - service/skaffold-introduction created
Waiting for deployments to stabilize...
 - deployment/skaffold-introduction: 0/4 nodes are available: 2 Insufficient memory, 4 Insufficient cpu.
    - pod/skaffold-introduction-59b479ddcb-f8ljj: 0/4 nodes are available: 2 Insufficient memory, 4 Insufficient cpu.
 - deployment/skaffold-introduction is ready.
Deployments stabilized in 56.784 seconds
Press Ctrl+C to exit
Watching for changes...
[skaffold-introduction]  
[skaffold-introduction] 2021-07-18 21:06:44.072  INFO 1 --- [  restartedMain] c.p.c.i.IndianStatesApplication          : Starting IndianStatesApplication using Java 16-ea on skaffold-introduction-59b479ddcb-f8ljj with PID 1 (/app/classes started by root in /)
```

此时，我们知道了如何使用 Skaffold 从运行的容器中尾随日志。接下来，让我们讨论 Skaffold 的端口转发。

## 端口转发

Skaffold 支持在开发、调试、部署或运行模式下自动转发服务和用户定义的端口转发。您不必暴露端点来访问您的应用程序。端口转发对于本地开发非常有帮助。Skaffold 在内部使用`kubectl port-forward`来实现端口转发。您可以在`skaffold.yaml`中明确定义自定义端口转发，或者在运行`skaffold dev`、`debug`、`run`或`deploy`时传递`--port-forward`标志。

以下是用户定义的端口转发的示例。在这个例子中，Skaffold 将尝试将端口`8080`转发到`localhost:9000`。如果由于某种原因端口`9000`不可用，那么 Skaffold 将转发到一个随机开放的端口：

```
profiles:
  - name: userDefinedPortForward
    portForward:
      - localPort: 9090
        port: 8080
        resourceName: reactive-web-app
        resourceType: deployment
```

在完成工作后，清理我们使用 Skaffold 创建的资源是一个好习惯。现在，让我们学习如何使用 Skaffold 清理和删除 Kubernetes 资源。

## 清理

通过`skaffold run`和`skaffold dev`命令，我们可以在 Kubernetes 集群中创建资源，在本地 Docker 守护程序上创建图像，并有时将图像推送到远程注册表。做所有这些工作可能会对您的本地和部署环境产生副作用，您可能会在本地环境中占用大量磁盘空间。

Skaffold 提供了清理功能来中和其中一些副作用：

+   您可以通过运行`skaffold delete`来清理 Kubernetes 资源，或者通过使用*Ctrl* + *C*来执行自动清理`skaffold dev`和`skaffold debug`。

+   可以通过传递`--no-prune=false`标志来为本地 Docker 守护程序镜像启用图像修剪。由于默认情况下启用了工件缓存，您需要禁用该功能才能进行清除。您需要运行的实际命令是`skaffold dev --no-prune=false --cache-artifacts=false`。通过按下`skaffold dev`和`skaffold debug`的*Ctrl* + *C*，Skaffold 将自动清理存储在本地 Docker 守护程序上的图像。

+   对于已推送到远程容器注册表的图像，用户必须负责清理工作。

例如，为了测试图像修剪，我们可以使用以下`docker`配置文件来使用我们的本地 Docker 守护程序构建图像：

```
  - name: docker
    build:
      artifacts:
        - image: docker.io/hiashish/skaffold-introduction
          docker:
            dockerfile: Dockerfile
```

然后，我们可以运行`skaffold dev --no-prune=false --cache-artifacts=false`命令。构建和部署后，我们可以按下*Ctrl* + *C*，这应该清除图像并删除任何 Kubernetes 资源。在以下日志中，您可以看到按下*Ctrl* + *C*后，Skaffold 开始删除 Kubernetes 资源并清除图像：

```
Cleaning up...
 - deployment.apps "skaffold-introduction" deleted
 - service "skaffold-introduction" deleted
Pruning images...
```

在本节中，我们深入探讨了 Skaffold 流水线阶段，如 init、build 和 deploy 等。在下一节中，我们将讨论使用 Skaffold 部署到 Kubernetes 集群的应用程序的调试。

# 使用 Skaffold 进行调试

Skaffold 支持在 Kubernetes 上运行的容器化应用程序进行调试，使用`skaffold debug`命令。Skaffold 为不同容器的运行时技术提供调试支持。一旦启用了调试，相关的调试端口将被暴露和标记为要转发到本地机器。IntelliJ IDE 的插件，比如 Cloud Code，内部使用 Skaffold 为您的语言添加和附加正确的调试器。

然而，在调试模式下，`skaffold debug`将禁用图像重建和同步，因为这可能会导致调试会话在保存文件更改时意外终止。您可以使用`--auto-build`、`--auto-deploy`和`--auto-sync`标志允许图像重建和同步。

`skaffold debug`命令支持以下语言和运行时：

+   Go 1.13+（运行时 ID：go）并使用 Delve

+   Node.js（运行时 ID：nodejs）并使用 Node.js Inspector Chrome DevTools

+   Java 和 JVM 语言（运行时 ID：jvm）并使用 JDWP

+   Python 3.5+（运行时 ID：python）并使用`debugpy`（调试适配器协议）或`pydevd`

+   .NET Core（运行时 ID：netcore）使用`vsdbg`

在 IDE 中，比如 IntelliJ，一旦启动应用程序，您需要将远程 Java 应用程序配置添加到您的运行/调试配置中。您还必须选择在启动应用程序时定义的端口/地址。然后，您就可以开始调试了：

```
[skaffold-introduction] Picked up JAVA_TOOL_OPTIONS: -agentlib:jdwp=transport=dt_socket,server=y,address=5005,suspend=n,quiet=y
Port forwarding pod/skaffold-introduction-766df7f799-dmq4t in namespace default, remote port 5005 -> 127.0.0.1:5005
```

在 IntelliJ 中，设置断点后，您应该看到以下内容。在断点处，一旦调试会话已激活，您应该看到对号：

![图 5.10 – 已启用断点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.11.jpg)

图 5.10 – 已启用断点

在**调试**控制台日志中，一旦调试会话开始，您应该看到以下内容。现在，您已经准备好调试您的应用程序了：

![图 5.11 – 调试器已连接](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/effls-cld-ntv-app-dev-skfd/img/B17385_Figure_5.12.jpg)

图 5.11 – 调试器已连接

在本节中，我们深入探讨了 Skaffold 的调试能力。我们还学习了如何使用`skaffold debug`命令调试我们应用程序的容器化版本。您还可以使用 Cloud Code IntelliJ 插件进行调试，我们将在第七章中介绍，即使用 Cloud Code 插件构建和部署 Spring Boot 应用程序。

# 总结

在本章中，我们首先发现了在不同操作系统上安装 Skaffold 的各种方法。我们涵盖了流行操作系统（如 macOS、Windows 和 Linux）的安装。然后，我们看了一些 Skaffold 支持的帮助构建和部署 Kubernetes 应用程序的各种命令。我们还涵盖了一些杂项和日常命令。然后，我们发现了不同的 Skaffold 流水线阶段，比如 init、build 和 deploy 等。最后，我们讨论了如何使用`skaffold dev`等命令调试应用程序。

在下一章中，我们将讨论 Skaffold 容器镜像构建器（Dockerfile、kaniko、Buildpacks、Jib）和部署器（Helm、kubectl、kustomize）。

# 进一步阅读

如果您想了解更多关于 Skaffold 的信息，请查看其文档 https://skaffold.dev/docs/。
