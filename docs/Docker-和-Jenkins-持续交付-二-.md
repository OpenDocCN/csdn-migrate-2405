# Docker 和 Jenkins 持续交付（二）

> 原文：[`zh.annas-archive.org/md5/7C44824F34694A0D5BA0600DC67F15A8`](https://zh.annas-archive.org/md5/7C44824F34694A0D5BA0600DC67F15A8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：持续集成管道

我们已经知道如何配置 Jenkins。在本章中，您将看到如何有效地使用它，重点放在 Jenkins 核心的功能上，即管道。通过从头开始构建完整的持续集成过程，我们将描述现代团队导向的代码开发的所有方面。

本章涵盖以下要点：

+   解释管道的概念

+   介绍 Jenkins 管道语法

+   创建持续集成管道

+   解释 Jenkinsfile 的概念

+   创建代码质量检查

+   添加管道触发器和通知

+   解释开发工作流程和分支策略

+   介绍 Jenkins 多分支

# 介绍管道

管道是一系列自动化操作，通常代表软件交付和质量保证过程的一部分。它可以简单地被看作是一系列脚本，提供以下额外的好处：

+   **操作分组**：操作被分组到阶段中（也称为**门**或**质量门**），引入了结构到过程中，并清晰地定义了规则：如果一个阶段失败，就不会执行更多的阶段

+   **可见性**：过程的所有方面都被可视化，这有助于快速分析失败，并促进团队协作

+   **反馈**：团队成员一旦发现问题，就可以迅速做出反应

管道的概念对于大多数持续集成工具来说是相似的，但命名可能有所不同。在本书中，我们遵循 Jenkins 的术语。

# 管道结构

Jenkins 管道由两种元素组成：阶段和步骤。以下图显示了它们的使用方式：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/f0485dcf-1ed8-4ab0-bb5a-7cea1f89a09f.png)

以下是基本的管道元素：

+   **步骤**：单个操作（告诉 Jenkins 要做什么，例如，从存储库检出代码，执行脚本）

+   **阶段**：步骤的逻辑分离（概念上区分不同的步骤序列，例如**构建，测试**和**部署**），用于可视化 Jenkins 管道的进展

从技术上讲，可以创建并行步骤；然而，最好将其视为真正需要优化目的时的例外。

# 多阶段 Hello World

例如，让我们扩展`Hello World`管道，包含两个阶段：

```
pipeline {
     agent any
     stages {
          stage('First Stage') {
               steps {
                    echo 'Step 1\. Hello World'
               }
          }
          stage('Second Stage') {
               steps {
                    echo 'Step 2\. Second time Hello'
                    echo 'Step 3\. Third time Hello'
               }
          }
     }
}
```

管道在环境方面没有特殊要求（任何从属代理），并在两个阶段内执行三个步骤。当我们点击“立即构建”时，我们应该看到可视化表示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/e654212a-9407-4e1a-9543-e54ee2b15bdf.png)

管道成功了，我们可以通过单击控制台查看步骤执行详细信息。如果任何步骤失败，处理将停止，不会运行更多的步骤。实际上，管道的整个目的是阻止所有进一步的步骤执行并可视化失败点。

# 管道语法

我们已经讨论了管道元素，并已经使用了一些管道步骤，例如`echo`。在管道定义内部，我们还可以使用哪些其他操作？

在本书中，我们使用了为所有新项目推荐的声明性语法。不同的选项是基于 Groovy 的 DSL 和（在 Jenkins 2 之前）XML（通过 Web 界面创建）。

声明性语法旨在使人们尽可能简单地理解管道，即使是那些不经常编写代码的人。这就是为什么语法仅限于最重要的关键字。

让我们准备一个实验，在我们描述所有细节之前，阅读以下管道定义并尝试猜测它的作用：

```
pipeline {
     agent any
     triggers { cron('* * * * *') }
     options { timeout(time: 5) }
     parameters { 
          booleanParam(name: 'DEBUG_BUILD', defaultValue: true, 
          description: 'Is it the debug build?') 
     }
     stages {
          stage('Example') {
               environment { NAME = 'Rafal' }
               when { expression { return params.DEBUG_BUILD } } 
               steps {
                    echo "Hello from $NAME"
                    script {
                         def browsers = ['chrome', 'firefox']
                         for (int i = 0; i < browsers.size(); ++i) {
                              echo "Testing the ${browsers[i]} browser."
                         }
                    }
               }
          }
     }
     post { always { echo 'I will always say Hello again!' } }
}
```

希望管道没有吓到你。它相当复杂。实际上，它是如此复杂，以至于它包含了所有可能的 Jenkins 指令。为了回答实验谜题，让我们逐条看看管道的执行指令：

1.  使用任何可用的代理。

1.  每分钟自动执行。

1.  如果执行时间超过 5 分钟，请停止。

1.  在开始之前要求布尔输入参数。

1.  将`Rafal`设置为环境变量 NAME。

1.  仅在`true`输入参数的情况下：

+   打印`来自 Rafal 的问候`

+   打印`测试 chrome 浏览器`

+   打印`测试 firefox 浏览器`

1.  无论执行过程中是否出现任何错误，都打印`我总是会说再见！`

让我们描述最重要的 Jenkins 关键字。声明性管道总是在`pipeline`块内指定，并包含部分、指令和步骤。我们将逐个讨论它们。

完整的管道语法描述可以在官方 Jenkins 页面上找到[`jenkins.io/doc/book/pipeline/syntax/`](https://jenkins.io/doc/book/pipeline/syntax/)。

# 部分

部分定义了流水线的结构，通常包含一个或多个指令或步骤。它们使用以下关键字进行定义：

+   **阶段**：这定义了一系列一个或多个阶段指令

+   **步骤**：这定义了一系列一个或多个步骤指令

+   **后置**：这定义了在流水线构建结束时运行的一个或多个步骤指令序列；标有条件（例如 always，success 或 failure），通常用于在流水线构建后发送通知（我们将在*触发器和通知*部分详细介绍）。

# 指令

指令表达了流水线或其部分的配置：

+   **代理**：这指定执行的位置，并可以定义`label`以匹配同样标记的代理，或者使用`docker`来指定动态提供环境以执行流水线的容器

+   触发器：这定义了触发流水线的自动方式，可以使用`cron`来设置基于时间的调度，或者使用`pollScm`来检查仓库的更改（我们将在*触发器和通知*部分详细介绍）

+   **选项**：这指定了特定于流水线的选项，例如`timeout`（流水线运行的最长时间）或`retry`（流水线在失败后应重新运行的次数）

+   **环境**：这定义了在构建过程中用作环境变量的一组键值

+   **参数**：这定义了用户输入参数的列表

+   **阶段**：这允许对步骤进行逻辑分组

+   **当**：这确定阶段是否应根据给定条件执行

# 步骤

步骤是流水线最基本的部分。它们定义了要执行的操作，因此它们实际上告诉 Jenkins**要做什么**。

+   **sh**：这执行 shell 命令；实际上，几乎可以使用`sh`来定义任何操作

+   **自定义**：Jenkins 提供了许多可用作步骤的操作（例如`echo`）；其中许多只是用于方便的`sh`命令的包装器；插件也可以定义自己的操作

+   **脚本**：这执行基于 Groovy 的代码块，可用于一些需要流程控制的非常规情况

可用步骤的完整规范可以在以下网址找到：[`jenkins.io/doc/pipeline/steps/`](https://jenkins.io/doc/pipeline/steps/)。

请注意，流水线语法非常通用，从技术上讲，几乎可以用于任何自动化流程。这就是为什么应该将流水线视为一种结构化和可视化的方法。然而，最常见的用例是实现我们将在下一节中看到的持续集成服务器。

# 提交流水线

最基本的持续集成流程称为提交流水线。这个经典阶段，顾名思义，从主存储库提交（或在 Git 中推送）开始，并导致构建成功或失败的报告。由于它在代码每次更改后运行，构建时间不应超过 5 分钟，并且应消耗合理数量的资源。提交阶段始终是持续交付流程的起点，并且在开发过程中提供了最重要的反馈循环，不断提供代码是否处于健康状态的信息。

提交阶段的工作如下。开发人员将代码提交到存储库，持续集成服务器检测到更改，构建开始。最基本的提交流水线包含三个阶段：

+   **检出**：此阶段从存储库下载源代码

+   **编译**：此阶段编译源代码

+   **单元测试**：此阶段运行一套单元测试

让我们创建一个示例项目，看看如何实现提交流水线。

这是一个使用 Git、Java、Gradle 和 Spring Boot 等技术的项目的流水线示例。然而，相同的原则适用于任何其他技术。

# 检出

从存储库检出代码始终是任何流水线中的第一个操作。为了看到这一点，我们需要有一个存储库。然后，我们将能够创建一个流水线。

# 创建 GitHub 存储库

在 GitHub 服务器上创建存储库只需几个步骤：

1.  转到[`github.com/`](https://github.com/)页面。

1.  如果还没有帐户，请创建一个。

1.  点击“新存储库”。

1.  给它一个名字，`calculator`。

1.  选中“使用 README 初始化此存储库”。

1.  点击“创建存储库”。

现在，您应该看到存储库的地址，例如`https://github.com/leszko/calculator.git`。

# 创建一个检出阶段

我们可以创建一个名为`calculator`的新流水线，并将代码放在一个名为 Checkout 的阶段的**流水线脚本**中：

```
pipeline {
     agent any
     stages {
          stage("Checkout") {
               steps {
                    git url: 'https://github.com/leszko/calculator.git'
               }
          }
     }
}
```

流水线可以在任何代理上执行，它的唯一步骤只是从存储库下载代码。我们可以点击“立即构建”并查看是否成功执行。

请注意，Git 工具包需要安装在执行构建的节点上。

当我们完成检出时，我们准备进行第二阶段。

# 编译

为了编译一个项目，我们需要：

1.  创建一个带有源代码的项目。

1.  将其推送到存储库。

1.  将编译阶段添加到流水线。

# 创建一个 Java Spring Boot 项目

让我们使用 Gradle 构建的 Spring Boot 框架创建一个非常简单的 Java 项目。

Spring Boot 是一个简化构建企业应用程序的 Java 框架。Gradle 是一个基于 Apache Maven 概念的构建自动化系统。

创建 Spring Boot 项目的最简单方法是执行以下步骤：

1.  转到[`start.spring.io/`](http://start.spring.io/)页面。

1.  选择 Gradle 项目而不是 Maven 项目（如果您更喜欢 Maven，也可以保留 Maven）。

1.  填写组和 Artifact（例如，`com.leszko`和`calculator`）。

1.  将 Web 添加到依赖项。

1.  单击生成项目。

1.  应下载生成的骨架项目（`calculator.zip`文件）。

以下屏幕截图显示了[`start.spring.io/`](http://start.spring.io/)页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/f7679438-1eed-48ca-be76-8fc68853701d.png)

# 将代码推送到 GitHub

我们将使用 Git 工具执行`commit`和`push`操作：

为了运行`git`命令，您需要安装 Git 工具包（可以从[`git-scm.com/downloads`](https://git-scm.com/downloads)下载）。

让我们首先将存储库克隆到文件系统：

```
$ git clone https://github.com/leszko/calculator.git
```

将从[`start.spring.io/`](http://start.spring.io/)下载的项目解压到 Git 创建的目录中。

如果您愿意，您可以将项目导入到 IntelliJ、Eclipse 或您喜欢的 IDE 工具中。

结果，`calculator`目录应该有以下文件：

```
$ ls -a
. .. build.gradle .git .gitignore gradle gradlew gradlew.bat README.md src
```

为了在本地执行 Gradle 操作，您需要安装 Java JDK（在 Ubuntu 中，您可以通过执行`sudo apt-get install -y default-jdk`来完成）。

我们可以使用以下代码在本地编译项目：

```
$ ./gradlew compileJava
```

在 Maven 的情况下，您可以运行`./mvnw compile`。Gradle 和 Maven 都编译`src`目录中的 Java 类。

您可以在[`docs.gradle.org/current/userguide/java_plugin.html`](https://docs.gradle.org/current/userguide/java_plugin.html)找到所有可能的 Gradle 指令（用于 Java 项目）。

现在，我们可以将其`commit`和`push`到 GitHub 存储库中：

```
$ git add .
$ git commit -m "Add Spring Boot skeleton"
$ git push -u origin master
```

运行`git push`命令后，您将被提示输入 GitHub 凭据（用户名和密码）。

代码已经在 GitHub 存储库中。如果您想检查它，可以转到 GitHub 页面并查看文件。

# 创建一个编译阶段

我们可以使用以下代码在管道中添加一个`编译`阶段：

```
stage("Compile") {
     steps {
          sh "./gradlew compileJava"
     }
}
```

请注意，我们在本地和 Jenkins 管道中使用了完全相同的命令，这是一个非常好的迹象，因为本地开发过程与持续集成环境保持一致。运行构建后，您应该看到两个绿色的框。您还可以在控制台日志中检查项目是否已正确编译。

# 单元测试

是时候添加最后一个阶段了，即单元测试，检查我们的代码是否符合预期。我们必须：

+   添加计算器逻辑的源代码

+   为代码编写单元测试

+   添加一个阶段来执行单元测试

# 创建业务逻辑

计算器的第一个版本将能够添加两个数字。让我们将业务逻辑作为一个类添加到`src/main/java/com/leszko/calculator/Calculator.java`文件中：

```
package com.leszko.calculator;
import org.springframework.stereotype.Service;

@Service
public class Calculator {
     int sum(int a, int b) {
          return a + b;
     }
}
```

为了执行业务逻辑，我们还需要在单独的文件`src/main/java/com/leszko/calculator/CalculatorController.java`中添加网络服务控制器：

```
package com.leszko.calculator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CalculatorController {
     @Autowired
     private Calculator calculator;

     @RequestMapping("/sum")
     String sum(@RequestParam("a") Integer a, 
                @RequestParam("b") Integer b) {
          return String.valueOf(calculator.sum(a, b));
     }
}
```

这个类将业务逻辑公开为一个网络服务。我们可以运行应用程序并查看它的工作方式：

```
$ ./gradlew bootRun
```

它应该启动我们的网络服务，我们可以通过浏览器导航到页面`http://localhost:8080/sum?a=1&b=2`来检查它是否工作。这应该对两个数字（`1`和`2`）求和，并在浏览器中显示`3`。

# 编写单元测试

我们已经有了可工作的应用程序。我们如何确保逻辑按预期工作？我们已经尝试过一次，但为了不断了解，我们需要进行单元测试。在我们的情况下，这可能是微不足道的，甚至是不必要的；然而，在实际项目中，单元测试可以避免错误和系统故障。

让我们在文件`src/test/java/com/leszko/calculator/CalculatorTest.java`中创建一个单元测试：

```
package com.leszko.calculator;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class CalculatorTest {
     private Calculator calculator = new Calculator();

     @Test
     public void testSum() {
          assertEquals(5, calculator.sum(2, 3));
     }
}
```

我们可以使用`./gradlew test`命令在本地运行测试。然后，让我们`commit`代码并将其`push`到存储库中：

```
$ git add .
$ git commit -m "Add sum logic, controller and unit test"
$ git push
```

# 创建一个单元测试阶段

现在，我们可以在管道中添加一个`单元测试`阶段：

```
stage("Unit test") {
     steps {
          sh "./gradlew test"
     }
}
```

在 Maven 的情况下，我们需要使用`./mvnw test`。

当我们再次构建流水线时，我们应该看到三个框，这意味着我们已经完成了持续集成流水线：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/ee925c80-529f-4732-8a8e-57c41190cf79.png)

# Jenkinsfile

到目前为止，我们一直直接在 Jenkins 中创建流水线代码。然而，这并不是唯一的选择。我们还可以将流水线定义放在一个名为`Jenkinsfile`的文件中，并将其与源代码一起`commit`到存储库中。这种方法更加一致，因为流水线的外观与项目本身密切相关。

例如，如果您不需要代码编译，因为您的编程语言是解释性的（而不是编译的），那么您将不会有`Compile`阶段。您使用的工具也取决于环境。我们使用 Gradle/Maven，因为我们构建了 Java 项目；然而，对于用 Python 编写的项目，您可以使用 PyBuilder。这导致了一个想法，即流水线应该由编写代码的同一人员，即开发人员创建。此外，流水线定义应与代码一起放在存储库中。

这种方法带来了即时的好处，如下所示：

+   在 Jenkins 失败的情况下，流水线定义不会丢失（因为它存储在代码存储库中，而不是在 Jenkins 中）

+   流水线更改的历史记录被存储

+   流水线更改经过标准的代码开发过程（例如，它们要经过代码审查）

+   对流水线更改的访问受到与对源代码访问完全相同的限制

# 创建 Jenkinsfile

我们可以创建`Jenkinsfile`并将其推送到我们的 GitHub 存储库。它的内容几乎与我们编写的提交流水线相同。唯一的区别是，检出阶段变得多余，因为 Jenkins 必须首先检出代码（与`Jenkinsfile`一起），然后读取流水线结构（从`Jenkinsfile`）。这就是为什么 Jenkins 在读取`Jenkinsfile`之前需要知道存储库地址。

让我们在项目的根目录中创建一个名为`Jenkinsfile`的文件：

```
pipeline {
     agent any
     stages {
          stage("Compile") {
               steps {
                    sh "./gradlew compileJava"
               }
          }
          stage("Unit test") {
               steps {
                    sh "./gradlew test"
               }
          }
     }
}
```

我们现在可以`commit`添加的文件并`push`到 GitHub 存储库：

```
$ git add .
$ git commit -m "Add sum Jenkinsfile"
$ git push
```

# 从 Jenkinsfile 运行流水线

当`Jenkinsfile`在存储库中时，我们所要做的就是打开流水线配置，在`Pipeline`部分：

+   将定义从`Pipeline script`更改为`Pipeline script from SCM`

+   在 SCM 中选择 Git

+   将`https://github.com/leszko/calculator.git`放入存储库 URL

！[](assets/2abce73b-7789-4457-9252-7eff8f912dbf.png)

保存后，构建将始终从 Jenkinsfile 的当前版本运行到存储库中。

我们已成功创建了第一个完整的提交流水线。它可以被视为最小可行产品，并且实际上，在许多情况下，它作为持续集成流程是足够的。在接下来的章节中，我们将看到如何改进提交流水线以使其更好。

# 代码质量阶段

我们可以通过额外的步骤扩展经典的持续集成三个步骤。最常用的是代码覆盖和静态分析。让我们分别看看它们。

# 代码覆盖

考虑以下情景：您有一个良好配置的持续集成流程；然而，项目中没有人编写单元测试。它通过了所有构建，但这并不意味着代码按预期工作。那么该怎么办？如何确保代码已经测试过了？

解决方案是添加代码覆盖工具，运行所有测试并验证代码的哪些部分已执行。然后，它创建一个报告显示未经测试的部分。此外，当未经测试的代码太多时，我们可以使构建失败。

有很多工具可用于执行测试覆盖分析；对于 Java 来说，最流行的是 JaCoCo、Clover 和 Cobertura。

让我们使用 JaCoCo 并展示覆盖检查在实践中是如何工作的。为了做到这一点，我们需要执行以下步骤：

1.  将 JaCoCo 添加到 Gradle 配置中。

1.  将代码覆盖阶段添加到流水线中。

1.  可选地，在 Jenkins 中发布 JaCoCo 报告。

# 将 JaCoCo 添加到 Gradle

为了从 Gradle 运行 JaCoCo，我们需要通过在插件部分添加以下行将`jacoco`插件添加到`build.gradle`文件中：

```
apply plugin: "jacoco"
```

接下来，如果我们希望在代码覆盖率过低的情况下使 Gradle 失败，我们还可以将以下配置添加到`build.gradle`文件中：

```
jacocoTestCoverageVerification {
     violationRules {
          rule {
               limit {
                    minimum = 0.2
               }
          }
     }
}
```

此配置将最小代码覆盖率设置为 20%。我们可以使用以下命令运行它：

```
$ ./gradlew test jacocoTestCoverageVerification
```

该命令检查代码覆盖率是否至少为 20%。您可以尝试不同的最小值来查看构建失败的级别。我们还可以使用以下命令生成测试覆盖报告：

```
$ ./gradlew test jacocoTestReport
```

您还可以在`build/reports/jacoco/test/html/index.html`文件中查看完整的覆盖报告：

！[](assets/f40840a3-e0e7-47f2-810c-53cd492ae0f6.png)

# 添加代码覆盖阶段

将代码覆盖率阶段添加到流水线中与之前的阶段一样简单：

```
stage("Code coverage") {
     steps {
          sh "./gradlew jacocoTestReport"
          sh "./gradlew jacocoTestCoverageVerification"
     }
}
```

添加了这个阶段后，如果有人提交了未经充分测试的代码，构建将失败。

# 发布代码覆盖率报告

当覆盖率低且流水线失败时，查看代码覆盖率报告并找出尚未通过测试的部分将非常有用。我们可以在本地运行 Gradle 并生成覆盖率报告；然而，如果 Jenkins 为我们显示报告会更方便。

为了在 Jenkins 中发布代码覆盖率报告，我们需要以下阶段定义：

```
stage("Code coverage") {
     steps {
          sh "./gradlew jacocoTestReport"
          publishHTML (target: [
               reportDir: 'build/reports/jacoco/test/html',
               reportFiles: 'index.html',
               reportName: "JaCoCo Report"
          ])
          sh "./gradlew jacocoTestCoverageVerification"
     }
}
```

此阶段将生成的 JaCoCo 报告复制到 Jenkins 输出。当我们再次运行构建时，我们应该会看到代码覆盖率报告的链接（在左侧菜单下方的“立即构建”下）。

要执行`publishHTML`步骤，您需要在 Jenkins 中安装**HTML Publisher**插件。您可以在[`jenkins.io/doc/pipeline/steps/htmlpublisher/#publishhtml-publish-html-reports`](https://jenkins.io/doc/pipeline/steps/htmlpublisher/#publishhtml-publish-html-reports)了解有关该插件的更多信息。

我们已经创建了代码覆盖率阶段，显示了未经测试且因此容易出现错误的代码。让我们看看还可以做些什么来提高代码质量。

如果您需要更严格的代码覆盖率，可以检查变异测试的概念，并将 PIT 框架阶段添加到流水线中。在[`pitest.org/`](http://pitest.org/)了解更多信息。

# 静态代码分析

您的代码可能运行得很好，但是代码本身的质量如何呢？我们如何确保它是可维护的并且以良好的风格编写的？

静态代码分析是一种自动检查代码而不实际执行的过程。在大多数情况下，它意味着对源代码检查一系列规则。这些规则可能适用于各种方面；例如，所有公共类都需要有 Javadoc 注释；一行的最大长度是 120 个字符，或者如果一个类定义了`equals()`方法，它也必须定义`hashCode()`方法。

对 Java 代码进行静态分析的最流行工具是 Checkstyle、FindBugs 和 PMD。让我们看一个例子，并使用 Checkstyle 添加静态代码分析阶段。我们将分三步完成这个过程：

1.  添加 Checkstyle 配置。

1.  添加 Checkstyle 阶段。

1.  可选地，在 Jenkins 中发布 Checkstyle 报告。

# 添加 Checkstyle 配置

为了添加 Checkstyle 配置，我们需要定义代码检查的规则。我们可以通过指定`config/checkstyle/checkstyle.xml`文件来做到这一点：

```
<?xml version="1.0"?>
<!DOCTYPE module PUBLIC
     "-//Puppy Crawl//DTD Check Configuration 1.2//EN"
     "http://www.puppycrawl.com/dtds/configuration_1_2.dtd">

<module name="Checker">
     <module name="TreeWalker">
          <module name="JavadocType">
               <property name="scope" value="public"/>
          </module>
     </module>
</module>
```

配置只包含一个规则：检查公共类、接口和枚举是否用 Javadoc 记录。如果没有，构建将失败。

完整的 Checkstyle 描述可以在[`checkstyle.sourceforge.net/config.html`](http://checkstyle.sourceforge.net/config.html)找到。

我们还需要将`checkstyle`插件添加到`build.gradle`文件中：

```
apply plugin: 'checkstyle'
```

然后，我们可以运行以下代码来运行`checkstyle`：

```
$ ./gradlew checkstyleMain
```

在我们的项目中，这应该会导致失败，因为我们的公共类（`Calculator.java`，`CalculatorApplication.java`，`CalculatorTest.java`，`CalculatorApplicationTests.java`）都没有 Javadoc 注释。我们需要通过添加文档来修复它，例如，在`src/main/java/com/leszko/calculator/CalculatorApplication.java`文件中：

```
/
 * Main Spring Application.
 */
@SpringBootApplication
public class CalculatorApplication {
     public static void main(String[] args) {
          SpringApplication.run(CalculatorApplication.class, args);
     }
}
```

现在，构建应该成功。

# 添加静态代码分析阶段

我们可以在流水线中添加一个“静态代码分析”阶段：

```
stage("Static code analysis") {
     steps {
          sh "./gradlew checkstyleMain"
     }
}
```

现在，如果有人提交了一个没有 Javadoc 的公共类文件，构建将失败。

# 发布静态代码分析报告

与 JaCoCo 非常相似，我们可以将 Checkstyle 报告添加到 Jenkins 中：

```
publishHTML (target: [
     reportDir: 'build/reports/checkstyle/',
     reportFiles: 'main.html',
     reportName: "Checkstyle Report"
])
```

它会生成一个指向 Checkstyle 报告的链接。

我们已经添加了静态代码分析阶段，可以帮助找到错误并在团队或组织内标准化代码风格。

# SonarQube

SonarQube 是最广泛使用的源代码质量管理工具。它支持多种编程语言，并且可以作为我们查看的代码覆盖率和静态代码分析步骤的替代品。实际上，它是一个单独的服务器，汇总了不同的代码分析框架，如 Checkstyle、FindBugs 和 JaCoCo。它有自己的仪表板，并且与 Jenkins 集成良好。

与将代码质量步骤添加到流水线不同，我们可以安装 SonarQube，在那里添加插件，并在流水线中添加一个“sonar”阶段。这种解决方案的优势在于，SonarQube 提供了一个用户友好的 Web 界面来配置规则并显示代码漏洞。

您可以在其官方页面[`www.sonarqube.org/`](https://www.sonarqube.org/)上阅读有关 SonarQube 的更多信息。

# 触发器和通知

到目前为止，我们一直通过点击“立即构建”按钮手动构建流水线。这样做虽然有效，但不太方便。所有团队成员都需要记住，在提交到存储库后，他们需要打开 Jenkins 并开始构建。流水线监控也是一样；到目前为止，我们手动打开 Jenkins 并检查构建状态。在本节中，我们将看到如何改进流程，使得流水线可以自动启动，并在完成后通知团队成员其状态。

# 触发器

自动启动构建的操作称为流水线触发器。在 Jenkins 中，有许多选择，但它们都归结为三种类型：

+   外部

+   轮询 SCM（源代码管理）

+   定时构建

让我们来看看每一个。

# 外部

外部触发器很容易理解。它意味着 Jenkins 在被通知者调用后开始构建，通知者可以是其他流水线构建、SCM 系统（例如 GitHub）或任何远程脚本。

下图展示了通信：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/51bf1a24-ebcd-48de-b743-4bea791ba412.png)

GitHub 在推送到存储库后触发 Jenkins 并开始构建。

要以这种方式配置系统，我们需要以下设置步骤：

1.  在 Jenkins 中安装 GitHub 插件。

1.  为 Jenkins 生成一个秘钥。

1.  设置 GitHub Web 钩子并指定 Jenkins 地址和秘钥。

对于最流行的 SCM 提供商，通常都会提供专门的 Jenkins 插件。

还有一种更通用的方式可以通过对端点`<jenkins_url>/job/<job_name>/build?token=<token>`进行 REST 调用来触发 Jenkins。出于安全原因，它需要在 Jenkins 中设置`token`，然后在远程脚本中使用。

Jenkins 必须可以从 SCM 服务器访问。换句话说，如果我们使用公共 GitHub 来触发 Jenkins，那么我们的 Jenkins 服务器也必须是公共的。这也适用于通用解决方案；`<jenkins_url>`地址必须是可访问的。

# 轮询 SCM

轮询 SCM 触发器有点不太直观。下图展示了通信：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/ea1d08c6-7d01-477e-9d0f-3639f4aabc12.png)

Jenkins 定期调用 GitHub 并检查存储库是否有任何推送。然后，它开始构建。这可能听起来有些反直觉，但是至少有两种情况可以使用这种方法：

+   Jenkins 位于防火墙网络内（GitHub 无法访问）

+   提交频繁，构建时间长，因此在每次提交后执行构建会导致过载

**轮询 SCM**的配置也更简单，因为从 Jenkins 到 GitHub 的连接方式已经设置好了（Jenkins 从 GitHub 检出代码，因此需要访问权限）。对于我们的计算器项目，我们可以通过在流水线中添加`triggers`声明（在`agent`之后）来设置自动触发：

```
triggers {
     pollSCM('* * * * *')
}
```

第一次手动运行流水线后，自动触发被设置。然后，它每分钟检查 GitHub，对于新的提交，它会开始构建。为了测试它是否按预期工作，您可以提交并推送任何内容到 GitHub 存储库，然后查看构建是否开始。

我们使用神秘的`* * * * *`作为`pollSCM`的参数。它指定 Jenkins 应该多久检查新的源更改，并以 cron 样式字符串格式表示。

cron 字符串格式在[`en.wikipedia.org/wiki/Cron`](https://en.wikipedia.org/wiki/Cron)中描述（与 cron 工具一起）。

# 计划构建

计划触发意味着 Jenkins 定期运行构建，无论存储库是否有任何提交。

如下图所示，不需要与任何系统进行通信：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/a7ecf582-38bd-4402-98f3-b28700ff392a.png)

计划构建的实现与轮询 SCM 完全相同。唯一的区别是使用`cron`关键字而不是`pollSCM`。这种触发方法很少用于提交流水线，但适用于夜间构建（例如，在夜间执行的复杂集成测试）。

# 通知

Jenkins 提供了很多宣布其构建状态的方式。而且，与 Jenkins 中的所有内容一样，可以使用插件添加新的通知类型。

让我们逐一介绍最流行的类型，以便您选择适合您需求的类型。

# 电子邮件

通知 Jenkins 构建状态的最经典方式是发送电子邮件。这种解决方案的优势是每个人都有邮箱；每个人都知道如何使用邮箱；每个人都习惯通过邮箱接收信息。缺点是通常有太多的电子邮件，而来自 Jenkins 的电子邮件很快就会被过滤掉，从未被阅读。

电子邮件通知的配置非常简单；只需：

+   已配置 SMTP 服务器

+   在 Jenkins 中设置其详细信息（在管理 Jenkins | 配置系统中）

+   在流水线中使用`mail to`指令

流水线配置可以如下：

```
post {
     always {
          mail to: 'team@company.com',
          subject: "Completed Pipeline: ${currentBuild.fullDisplayName}",
          body: "Your build completed, please check: ${env.BUILD_URL}"
     }
}
```

请注意，所有通知通常在流水线的`post`部分中调用，该部分在所有步骤之后执行，无论构建是否成功或失败。我们使用了`always`关键字；然而，还有不同的选项：

+   **始终：**无论完成状态如何都执行

+   **更改：**仅在流水线更改其状态时执行

+   **失败：**仅在流水线处于**失败**状态时执行

+   **成功：**仅在流水线处于**成功**状态时执行

+   **不稳定：**仅在流水线处于**不稳定**状态时执行（通常是由测试失败或代码违规引起的）

# 群聊

如果群聊（例如 Slack 或 HipChat）是团队中的第一种沟通方式，那么考虑在那里添加自动构建通知是值得的。无论使用哪种工具，配置的过程始终是相同的：

1.  查找并安装群聊工具的插件（例如**Slack 通知**插件）。

1.  配置插件（服务器 URL、频道、授权令牌等）。

1.  将发送指令添加到流水线中。

让我们看一个 Slack 的样本流水线配置，在构建失败后发送通知：

```
post {
     failure {
          slackSend channel: '#dragons-team',
          color: 'danger',
          message: "The pipeline ${currentBuild.fullDisplayName} failed."
     }
}
```

# 团队空间

随着敏捷文化的出现，人们认为最好让所有事情都发生在团队空间里。与其写电子邮件，不如一起见面；与其在线聊天，不如当面交谈；与其使用任务跟踪工具，不如使用白板。这个想法也适用于持续交付和 Jenkins。目前，在团队空间安装大屏幕（也称为**构建辐射器**）非常普遍。因此，当你来到办公室时，你看到的第一件事就是流水线的当前状态。构建辐射器被认为是最有效的通知策略之一。它们确保每个人都知道构建失败，并且作为副作用，它们提升了团队精神并促进了面对面的沟通。

由于开发人员是有创造力的存在，他们发明了许多其他与“辐射器”起着相同作用的想法。一些团队挂大型扬声器，当管道失败时会发出哔哔声。其他一些团队有玩具，在构建完成时会闪烁。我最喜欢的之一是 Pipeline State UFO，它是 GitHub 上的开源项目。在其页面上，您可以找到如何打印和配置挂在天花板下并信号管道状态的 UFO 的描述。您可以在[`github.com/Dynatrace/ufo`](https://github.com/Dynatrace/ufo)找到更多信息。

由于 Jenkins 可以通过插件进行扩展，其社区编写了许多不同的方式来通知构建状态。其中，您可以找到 RSS 订阅、短信通知、移动应用程序、桌面通知器等。

# 团队开发策略

我们已经描述了持续集成管道应该是什么样子的一切。但是，它应该在什么时候运行？当然，它是在提交到存储库后触发的，但是提交到哪个分支？只提交到主干还是每个分支都提交？或者它应该在提交之前而不是之后运行，以便存储库始终保持健康？或者，怎么样采用没有分支的疯狂想法？

对于这些问题并没有单一的最佳答案。实际上，您使用持续集成过程的方式取决于团队的开发工作流程。因此，在我们继续之前，让我们描述一下可能的工作流程是什么。

# 开发工作流程

开发工作流程是您的团队将代码放入存储库的方式。当然，这取决于许多因素，如源代码控制管理工具、项目特定性或团队规模。

因此，每个团队以稍微不同的方式开发代码。但是，我们可以将它们分类为三种类型：基于主干的工作流程、分支工作流程和分叉工作流程。

所有工作流程都在[`www.atlassian.com/git/tutorials/comparing-workflows`](https://www.atlassian.com/git/tutorials/comparing-workflows)上详细描述，并附有示例。

# 基于主干的工作流程

基于主干的工作流程是最简单的策略。其概述如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/dfd60182-ccde-4fba-aec5-e01d4fb677af.png)

有一个中央存储库，所有对项目的更改都有一个单一入口，称为主干或主要。团队的每个成员都克隆中央存储库，以拥有自己的本地副本。更改直接提交到中央存储库。

# 分支工作流

分支工作流，顾名思义，意味着代码被保存在许多不同的分支中。这个想法如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/18d4bcff-09cf-42c4-8e90-b88268349bee.png)

当开发人员开始开发新功能时，他们从主干创建一个专用分支，并在那里提交所有与功能相关的更改。这使得多个开发人员可以轻松地在不破坏主代码库的情况下开发功能。这就是为什么在分支工作流的情况下，保持主干健康是没有问题的。当功能完成时，开发人员会从主干重新设置功能分支，并创建一个包含所有与功能相关代码更改的拉取请求。这会打开代码审查讨论，并留出空间来检查更改是否不会影响主干。当代码被其他开发人员和自动系统检查接受后，它就会合并到主代码库中。然后，在主干上再次运行构建，但几乎不应该失败，因为它在分支上没有失败。

# 分叉工作流

分叉工作流在开源社区中非常受欢迎。其思想如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/83ff827e-d29b-4e4e-8449-cb5d979dc6a2.png)

每个开发人员都有自己的服务器端存储库。它们可能是官方存储库，也可能不是，但从技术上讲，每个存储库都是完全相同的。

分叉字面上意味着从其他存储库创建一个新存储库。开发人员将代码推送到自己的存储库，当他们想要集成代码时，他们会创建一个拉取请求到其他存储库。

分支工作流的主要优势在于集成不一定通过中央存储库。它还有助于所有权，因为它允许接受他人的拉取请求，而不给予他们写入权限。

在面向需求的商业项目中，团队通常只开发一个产品，因此有一个中央存储库，因此这个模型归结为分支工作流，具有良好的所有权分配，例如，只有项目负责人可以将拉取请求合并到中央存储库中。

# 采用持续集成

我们描述了不同的开发工作流程，但它们如何影响持续集成配置呢？

# 分支策略

每种开发工作流程都意味着不同的持续集成方法：

+   **基于主干的工作流程**：意味着不断与破损的管道作斗争。如果每个人都提交到主代码库，那么管道经常会失败。在这种情况下，旧的持续集成规则是：“如果构建失败，开发团队立即停止正在做的事情并立即解决问题”。

+   **分支工作流程**：解决了破损主干的问题，但引入了另一个问题：如果每个人都在自己的分支上开发，那么集成在哪里？一个功能通常需要几周甚至几个月的时间来开发，而在这段时间内，分支没有集成到主代码中，因此不能真正称为“持续”集成；更不用说不断需要合并和解决冲突。

+   **分叉工作流程**：意味着每个存储库所有者管理持续集成过程，这通常不是问题。然而，它与分支工作流程存在相同的问题。

没有银弹，不同的组织选择不同的策略。最接近完美的解决方案是使用分支工作流程的技术和基于主干工作流程的哲学。换句话说，我们可以创建非常小的分支，并经常将它们集成到主分支中。这似乎兼具两者的优点，但要求要么有微小的功能，要么使用功能切换。由于功能切换的概念非常适合持续集成和持续交付，让我们花点时间来探讨一下。

# 功能切换

功能切换是一种替代维护多个源代码分支的技术，以便在功能完成并准备发布之前进行测试。它用于禁用用户的功能，但在测试时为开发人员启用。功能切换本质上是在条件语句中使用的变量。

功能切换的最简单实现是标志和 if 语句。使用功能切换进行开发，而不是使用功能分支开发，看起来如下：

1.  必须实现一个新功能。

1.  创建一个新的标志或配置属性`feature_toggle`（而不是`feature`分支）。

1.  每个与功能相关的代码都添加到`if`语句中（而不是提交到`feature`分支），例如：

```
        if (feature_toggle) {
             // do something
        }
```

1.  在功能开发期间：

+   使用`feature_toggle = true`在主分支上进行编码（而不是在功能分支上进行编码）

+   从主分支进行发布，使用`feature_toggle = false`

1.  当功能开发完成时，所有`if`语句都被移除，并且从配置中移除了`feature_toggle`（而不是将`feature`合并到主分支并删除`feature`分支）。

功能切换的好处在于所有开发都是在“主干”上进行的，这样可以实现真正的持续集成，并减轻合并代码的问题。

# Jenkins 多分支

如果您决定以任何形式使用分支，长期功能分支或推荐的短期分支，那么在将其合并到主分支之前知道代码是否健康是很方便的。这种方法可以确保主代码库始终保持绿色，幸运的是，使用 Jenkins 可以很容易地实现这一点。

为了在我们的计算器项目中使用多分支，让我们按照以下步骤进行：

1.  打开主 Jenkins 页面。

1.  点击“新建项目”。

1.  输入`calculator-branches`作为项目名称，选择多分支管道，然后点击“确定”。

1.  在分支来源部分，点击“添加来源”，然后选择 Git。

1.  将存储库地址输入到项目存储库中。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/612d9172-f32d-4de6-93b8-d050718945ea.png)

1.  如果没有其他运行，则设置 1 分钟为间隔，然后勾选“定期运行”。

1.  点击“保存”。

每分钟，此配置会检查是否有任何分支被添加（或删除），并创建（或删除）由 Jenkinsfile 定义的专用管道。

我们可以创建一个新的分支并看看它是如何工作的。让我们创建一个名为`feature`的新分支并将其`push`到存储库中：

```
$ git checkout -b feature
$ git push origin feature
```

一会儿之后，您应该会看到一个新的分支管道被自动创建并运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/1d029385-1907-49ca-8a47-6869c12edbfd.png)

现在，在将功能分支合并到主分支之前，我们可以检查它是否是绿色的。这种方法不应该破坏主构建。

在 GitHub 的情况下，有一种更好的方法，使用“GitHub 组织文件夹”插件。它会自动为所有项目创建具有分支和拉取请求的管道。

一个非常类似的方法是为每个拉取请求构建一个管道，而不是为每个分支构建一个管道，这会产生相同的结果；主代码库始终保持健康。

# 非技术要求

最后但同样重要的是，持续集成并不全是关于技术。相反，技术排在第二位。詹姆斯·肖尔在他的文章《每日一美元的持续集成》中描述了如何在没有任何额外软件的情况下设置持续集成过程。他所使用的只是一个橡皮鸡和一个铃铛。这个想法是让团队在一个房间里工作，并在一个空椅子上设置一台独立的计算机。把橡皮鸡和铃铛放在那台计算机前。现在，当你计划签入代码时，拿起橡皮鸡，签入代码，去空的计算机，检出最新的代码，在那里运行所有的测试，如果一切顺利，放回橡皮鸡并敲响铃铛，这样每个人都知道有东西被添加到了代码库。

《每日一美元的持续集成》是由詹姆斯·肖尔（James Shore）撰写的，可以在以下网址找到：[`www.jamesshore.com/Blog/Continuous-Integration-on-a-Dollar-a-Day.html`](http://www.jamesshore.com/Blog/Continuous-Integration-on-a-Dollar-a-Day.html)。

这个想法有点过于简化，自动化工具很有用；然而，主要信息是，没有每个团队成员的参与，即使是最好的工具也无济于事。杰兹·汉布尔（Jez Humble）在他的著作《持续交付》中提到了持续集成的先决条件，可以用以下几点重新表述：

+   **定期签入**：引用*迈克·罗伯茨*的话，“连续性比你想象的更频繁”，最少每天一次。

+   **创建全面的单元测试**：不仅仅是高测试覆盖率，可能没有断言但仍保持 100%的覆盖率。

+   **保持流程迅速**：持续集成必须需要很短的时间，最好在 5 分钟以内。10 分钟已经很长了。

+   **监控构建**：这可以是一个共同的责任，或者你可以适应每周轮换的**构建主管**角色。

# 练习

你已经学到了如何配置持续集成过程。由于“熟能生巧”，我们建议进行以下练习：

1.  创建一个 Python 程序，用作命令行参数传递的两个数字相乘。添加单元测试并将项目发布到 GitHub 上：

+   创建两个文件`calculator.py`和`test_calculator.py`

+   你可以在[`docs.python.org/library/unittest.html`](https://docs.python.org/library/unittest.html)使用`unittest`库。

+   运行程序和单元测试

1.  为 Python 计算器项目构建持续集成流水线：

+   使用 Jenkinsfile 指定管道

+   配置触发器，以便在存储库有任何提交时自动运行管道

+   管道不需要“编译”步骤，因为 Python 是一种可解释语言

+   运行管道并观察结果

+   尝试提交破坏管道每个阶段的代码，并观察它在 Jenkins 中的可视化效果

# 总结

在本章中，我们涵盖了持续集成管道的所有方面，这总是持续交付的第一步。本章的关键要点：

+   管道提供了组织任何自动化流程的一般机制；然而，最常见的用例是持续集成和持续交付

+   Jenkins 接受不同的管道定义方式，但推荐的是声明性语法

+   提交管道是最基本的持续集成过程，正如其名称所示，它应该在每次提交到存储库后运行

+   管道定义应存储在存储库中作为 Jenkinsfile

+   提交管道可以通过代码质量阶段进行扩展

+   无论项目构建工具如何，Jenkins 命令应始终与本地开发命令保持一致

+   Jenkins 提供了广泛的触发器和通知

+   团队或组织内部应谨慎选择开发工作流程，因为它会影响持续集成过程，并定义代码开发的方式

在下一章中，我们将专注于持续交付过程的下一个阶段，自动接受测试。它可以被认为是最重要的，而且在许多情况下，是最难实现的步骤。我们将探讨接受测试的概念，并使用 Docker 进行示例实现。


# 第五章：自动验收测试

我们已经配置了持续交付过程的提交阶段，现在是时候解决验收测试阶段了，这通常是最具挑战性的部分。通过逐渐扩展流水线，我们将看到验收测试自动化的不同方面。

本章涵盖以下内容：

+   介绍验收测试过程及其困难

+   解释工件存储库的概念

+   在 Docker Hub 上创建 Docker 注册表

+   安装和保护私有 Docker 注册表

+   在 Jenkins 流水线中实施验收测试

+   介绍和探索 Docker Compose

+   在验收测试过程中使用 Docker Compose

+   与用户一起编写验收测试

# 介绍验收测试

验收测试是为了确定业务需求或合同是否得到满足而进行的测试。它涉及对完整系统进行黑盒测试，从用户的角度来看，其积极的结果应意味着软件交付的验收。有时也称为用户验收测试（UAT）、最终用户测试或测试版测试，这是开发过程中软件满足*真实世界*受众的阶段。

许多项目依赖于由质量保证人员或用户执行的手动步骤来验证功能和非功能要求，但是，以编程可重复操作的方式运行它们要合理得多。

然而，自动验收测试可能被认为是困难的，因为它们具有特定的特点：

+   面向用户：它们需要与用户一起编写，这需要技术和非技术两个世界之间的理解。

+   依赖集成：被测试的应用程序应该与其依赖一起运行，以检查整个系统是否正常工作。

+   环境身份：暂存（测试）和生产环境应该是相同的，以确保在生产环境中运行时，应用程序也能如预期般运行。

+   应用程序身份：应用程序应该只构建一次，并且相同的二进制文件应该被传输到生产环境。这保证了在测试和发布之间没有代码更改，并消除了不同构建环境的风险。

+   相关性和后果：如果验收测试通过，应该清楚地表明应用程序从用户角度来看已经准备好发布。

我们在本章的不同部分解决了所有这些困难。通过仅构建一次 Docker 镜像并使用 Docker 注册表进行存储和版本控制，可以实现应用程序身份。Docker Compose 有助于集成依赖项，提供了一种构建一组容器化应用程序共同工作的方式。在“编写验收测试”部分解释了以用户为中心创建测试的方法，而环境身份则由 Docker 工具本身解决，并且还可以通过下一章描述的其他工具进行改进。关于相关性和后果，唯一的好答案是要记住验收测试必须始终具有高质量。

验收测试可能有多重含义；在本书中，我们将验收测试视为从用户角度进行的完整集成测试，不包括性能、负载和恢复等非功能性测试。

# Docker 注册表

Docker 注册表是用于存储 Docker 镜像的存储库。确切地说，它是一个无状态的服务器应用程序，允许在需要时发布（推送）和检索（拉取）镜像。我们已经在运行官方 Docker 镜像时看到了注册表的示例，比如`jenkins`。我们从 Docker Hub 拉取了这些镜像，这是一个官方的基于云的 Docker 注册表。使用单独的服务器来存储、加载和搜索软件包是一个更一般的概念，称为软件存储库，甚至更一般的是构件存储库。让我们更仔细地看看这个想法。

# 构件存储库

虽然源代码管理存储源代码，但构件存储库专门用于存储软件二进制构件，例如编译后的库或组件，以后用于构建完整的应用程序。为什么我们需要使用单独的工具在单独的服务器上存储二进制文件？

+   文件大小：构件文件可能很大，因此系统需要针对它们的下载和上传进行优化。

+   版本：每个上传的构件都需要有一个版本，这样可以方便浏览和使用。然而，并不是所有的版本都需要永久存储；例如，如果发现了一个 bug，我们可能对相关的构件不感兴趣并将其删除。

+   修订映射：每个构件应该指向源代码的一个确切修订版本，而且二进制创建过程应该是可重复的。

+   **包**：构件以编译和压缩的形式存储，因此这些耗时的步骤不需要重复进行。

+   **访问控制**：用户可以以不同方式限制对源代码和构件二进制文件的访问。

+   **客户端**：构件存储库的用户可以是团队或组织外的开发人员，他们希望通过其公共 API 使用库。

+   **用例**：构件二进制文件用于保证部署到每个环境的确切相同的构建版本，以便在失败情况下简化回滚过程。

最受欢迎的构件存储库是 JFrog Artifactory 和 Sonatype Nexus。

构件存储库在持续交付过程中扮演着特殊的角色，因为它保证了相同的二进制文件在所有流水线步骤中被使用。

让我们看一下下面的图，展示了它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/60334691-bdc8-4953-9758-40f5983827d8.png)

**开发人员**将更改推送到**源代码存储库**，这会触发流水线构建。作为**提交阶段**的最后一步，会创建一个二进制文件并存储在构件存储库中。之后，在交付过程的所有其他阶段中，都会拉取并使用相同的二进制文件。

构建的二进制文件通常被称为**发布候选版本**，将二进制文件移动到下一个阶段的过程称为**提升**。

根据编程语言和技术的不同，二进制格式可能会有所不同。

例如，在 Java 的情况下，通常会存储 JAR 文件，在 Ruby 的情况下会存储 gem 文件。我们使用 Docker，因此我们将 Docker 镜像存储为构件，并且用于存储 Docker 镜像的工具称为 Docker 注册表。

一些团队同时维护两个存储库，一个是用于 JAR 文件的构件存储库，另一个是用于 Docker 镜像的 Docker 注册表。虽然在 Docker 引入的第一阶段可能会有用，但没有理由永远维护两者。

# 安装 Docker 注册表

首先，我们需要安装一个 Docker 注册表。有许多选项可用，但其中两个比其他更常见，一个是基于云的 Docker Hub 注册表，另一个是您自己的私有 Docker 注册表。让我们深入了解一下。

# Docker Hub

Docker Hub 是一个提供 Docker 注册表和其他功能的基于云的服务，例如构建镜像、测试它们以及直接从代码存储库中拉取代码。Docker Hub 是云托管的，因此实际上不需要任何安装过程。你需要做的就是创建一个 Docker Hub 账户：

1.  在浏览器中打开[`hub.docker.com/`](https://hub.docker.com/)。

1.  填写密码、电子邮件地址和 Docker ID。

1.  收到电子邮件并点击激活链接后，帐户已创建。

Docker Hub 绝对是开始使用的最简单选项，并且允许存储私有和公共图像。

# 私有 Docker 注册表

Docker Hub 可能并不总是可接受的。对于企业来说，它并不免费，更重要的是，许多公司有政策不在其自己的网络之外存储其软件。在这种情况下，唯一的选择是安装私有 Docker 注册表。

Docker 注册表安装过程快速简单，但是要使其在公共环境中安全可用，需要设置访问限制和域证书。这就是为什么我们将这一部分分为三个部分：

+   安装 Docker 注册表应用程序

+   添加域证书

+   添加访问限制

# 安装 Docker 注册表应用程序

Docker 注册表可用作 Docker 镜像。要启动它，我们可以运行以下命令：

```
$ docker run -d -p 5000:5000 --restart=always --name registry registry:2
```

默认情况下，注册表数据存储为默认主机文件系统目录中的 docker 卷。要更改它，您可以添加`-v <host_directory>:/var/lib/registry`。另一种选择是使用卷容器。

该命令启动注册表并使其通过端口 5000 可访问。`registry`容器是从注册表镜像（版本 2）启动的。`--restart=always`选项导致容器在关闭时自动重新启动。

考虑设置负载均衡器，并在用户数量较大的情况下启动几个 Docker 注册表容器。

# 添加域证书

如果注册表在本地主机上运行，则一切正常，不需要其他安装步骤。但是，在大多数情况下，我们希望为注册表设置专用服务器，以便图像广泛可用。在这种情况下，Docker 需要使用 SSL/TLS 保护注册表。该过程与公共 Web 服务器配置非常相似，并且强烈建议使用 CA（证书颁发机构）签名证书。如果获取 CA 签名的证书不是一个选项，那么我们可以自签名证书或使用`--insecure-registry`标志。

您可以在[`docs.docker.com/registry/insecure/#using-self-signed-certificates`](https://docs.docker.com/registry/insecure/#using-self-signed-certificates)阅读有关创建和使用自签名证书的信息。

无论证书是由 CA 签名还是自签名，我们都可以将`domain.crt`和`domain.key`移动到`certs`目录并启动注册表。

```
$ docker run -d -p 5000:5000 --restart=always --name registry -v `pwd`/certs:/certs -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key registry:2
```

在使用自签名证书的情况下，客户端必须明确信任该证书。为了做到这一点，他们可以将`domain.crt`文件复制到`/etc/docker/certs.d/<docker_host_domain>:5000/ca.crt`。

不建议使用`--insecure-registry`标志，因为它根本不提供安全性。

# 添加访问限制

除非我们在一个良好安全的私人网络中使用注册表，否则我们应该配置认证。

这样做的最简单方法是使用`registry`镜像中的`htpasswd`工具创建具有密码的用户：

```
$ mkdir auth
$ docker run --entrypoint htpasswd registry:2 -Bbn <username> <password> > auth/passwords
```

该命令运行`htpasswd`工具来创建`auth/passwords`文件（其中包含一个用户）。然后，我们可以使用一个授权访问它的用户来运行注册表：

```
$ docker run -d -p 5000:5000 --restart=always --name registry -v `pwd`/auth:/auth -e "REGISTRY_AUTH=htpasswd" -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/passwords -v `pwd`/certs:/certs -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key registry:2
```

该命令除了设置证书外，还创建了仅限于`auth/passwords`文件中指定的用户的访问限制。

因此，在使用注册表之前，客户端需要指定用户名和密码。

在`--insecure-registry`标志的情况下，访问限制不起作用。

# 其他 Docker 注册表

当涉及基于 Docker 的工件存储库时，Docker Hub 和私有注册表并不是唯一的选择。

其他选项如下：

+   通用存储库：广泛使用的通用存储库，如 JFrog Artifactory 或 Sonatype Nexus，实现了 Docker 注册表 API。它们的优势在于一个服务器可以存储 Docker 镜像和其他工件（例如 JAR 文件）。这些系统也是成熟的，并提供企业集成。

+   基于云的注册表：Docker Hub 并不是唯一的云提供商。大多数面向云的服务都在云中提供 Docker 注册表，例如 Google Cloud 或 AWS。

+   自定义注册表：Docker 注册表 API 是开放的，因此可以实现自定义解决方案。而且，镜像可以导出为文件，因此可以简单地将镜像存储为文件。

# 使用 Docker 注册表

当注册表配置好后，我们可以展示如何通过三个步骤与其一起工作：

+   构建镜像

+   将镜像推送到注册表

+   从注册表中拉取镜像

# 构建镜像

让我们使用第二章中的示例，*介绍 Docker*，并构建一个安装了 Ubuntu 和 Python 解释器的图像。在一个新目录中，我们需要创建一个 Dockerfile：

```
FROM ubuntu:16.04
RUN apt-get update && \
    apt-get install -y python
```

现在，我们可以构建图像：

```
$ docker build -t ubuntu_with_python .
```

# 推送图像

为了推送创建的图像，我们需要根据命名约定对其进行标记：

```
<registry_address>/<image_name>:<tag>
```

"`registry_address`"可以是：

+   在 Docker Hub 的情况下的用户名

+   私有注册表的域名或 IP 地址和端口（例如，`localhost:5000`）

在大多数情况下，`<tag>`的形式是图像/应用程序版本。

让我们标记图像以使用 Docker Hub：

```
$ docker tag ubuntu_with_python leszko/ubuntu_with_python:1
```

我们也可以在`build`命令中标记图像：`"docker`

`build -t leszko/ubuntu_with_python:1 . "`.

如果存储库配置了访问限制，我们需要首先授权它：

```
$ docker login --username <username> --password <password>
```

可以使用`docker login`命令而不带参数，并且 Docker 会交互式地要求用户名和密码。

现在，我们可以使用`push`命令将图像存储在注册表中：

```
$ docker push leszko/ubuntu_with_python:1
```

请注意，无需指定注册表地址，因为 Docker 使用命名约定来解析它。图像已存储，我们可以使用 Docker Hub Web 界面进行检查，该界面可在[`hub.docker.com`](https://hub.docker.com)上找到。

# 拉取图像

为了演示注册表的工作原理，我们可以在本地删除图像并从注册表中检索它：

```
$ docker rmi ubuntu_with_python leszko/ubuntu_with_python:1
```

我们可以使用`docker images`命令看到图像已被删除。然后，让我们从注册表中检索图像：

```
$ docker pull leszko/ubuntu_with_python:1
```

如果您使用免费的 Docker Hub 帐户，您可能需要在拉取之前将`ubuntu_with_python`存储库更改为公共。

我们可以使用`docker images`命令确认图像已经恢复。

当我们配置了注册表并了解了它的工作原理后，我们可以看到如何在持续交付流水线中使用它并构建验收测试阶段。

# 流水线中的验收测试

我们已经理解了验收测试的概念，并知道如何配置 Docker 注册表，因此我们已经准备好在 Jenkins 流水线中进行第一次实现。

让我们看一下呈现我们将使用的过程的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/0a20aa8e-7116-4a9b-97ef-d619265b0725.png)

该过程如下：

1.  开发人员将代码更改推送到 GitHub。

1.  Jenkins 检测到更改，触发构建并检出当前代码。

1.  Jenkins 执行提交阶段并构建 Docker 图像。

1.  Jenkins 将图像推送到 Docker 注册表。

1.  Jenkins 在暂存环境中运行 Docker 容器。

1.  部署 Docker 主机需要从 Docker 注册表中拉取镜像。

1.  Jenkins 对运行在暂存环境中的应用程序运行验收测试套件。

为了简单起见，我们将在本地运行 Docker 容器（而不是在单独的暂存服务器上）。为了远程运行它，我们需要使用`-H`选项或配置`DOCKER_HOST`环境变量。我们将在下一章中介绍这部分内容。

让我们继续上一章开始的流水线，并添加三个更多的阶段：

+   `Docker 构建`

+   `Docker push`

+   `验收测试`

请记住，您需要在 Jenkins 执行器（代理从属节点或主节点，在无从属节点配置的情况下）上安装 Docker 工具，以便它能够构建 Docker 镜像。

如果您使用动态配置的 Docker 从属节点，那么目前还没有提供成熟的 Docker 镜像。您可以自行构建，或者使用`leszko/jenkins-docker-slave`镜像。您还需要在 Docker 代理配置中标记`privileged`选项。然而，这种解决方案有一些缺点，因此在生产环境中使用之前，请阅读[`jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/`](http://jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/)。

# Docker 构建阶段

我们希望将计算器项目作为 Docker 容器运行，因此我们需要创建 Dockerfile，并在 Jenkinsfile 中添加`"Docker 构建"`阶段。

# 添加 Dockerfile

让我们在计算器项目的根目录中创建 Dockerfile：

```
FROM frolvlad/alpine-oraclejdk8:slim
COPY build/libs/calculator-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
```

Gradle 的默认构建目录是`build/libs/`，`calculator-0.0.1-SNAPSHOT.jar`是打包成一个 JAR 文件的完整应用程序。请注意，Gradle 自动使用 Maven 风格的版本`0.0.1-SNAPSHOT`对应用程序进行了版本化。

Dockerfile 使用包含 JDK 8 的基础镜像（`frolvlad/alpine-oraclejdk8:slim`）。它还复制应用程序 JAR（由 Gradle 创建）并运行它。让我们检查应用程序是否构建并运行：

```
$ ./gradlew build
$ docker build -t calculator .
$ docker run -p 8080:8080 --name calculator calculator
```

使用上述命令，我们已经构建了应用程序，构建了 Docker 镜像，并运行了 Docker 容器。过一会儿，我们应该能够打开浏览器，访问`http://localhost:8080/sum?a=1&b=2`，并看到`3`作为结果。

我们可以停止容器，并将 Dockerfile 推送到 GitHub 存储库：

```
$ git add Dockerfile
$ git commit -m "Add Dockerfile"
$ git push
```

# 将 Docker 构建添加到流水线

我们需要的最后一步是在 Jenkinsfile 中添加“Docker 构建”阶段。通常，JAR 打包也被声明为一个单独的`Package`阶段：

```
stage("Package") {
     steps {
          sh "./gradlew build"
     }
}

stage("Docker build") {
     steps {
          sh "docker build -t leszko/calculator ."
     }
}
```

我们没有明确为镜像版本，但每个镜像都有一个唯一的哈希 ID。我们将在下一章中介绍明确的版本控制。

请注意，我们在镜像标签中使用了 Docker 注册表名称。没有必要将镜像标记两次为“calculator”和`leszko/calculator`。

当我们提交并推送 Jenkinsfile 时，流水线构建应该会自动开始，我们应该看到所有的方框都是绿色的。这意味着 Docker 镜像已经成功构建。

还有一个适用于 Docker 的 Gradle 插件，允许在 Gradle 脚本中执行 Docker 操作。您可以在以下链接中看到一个示例：[`spring.io/guides/gs/spring-boot-docker/`](https://spring.io/guides/gs/spring-boot-docker/)。

# Docker push 阶段

当镜像准备好后，我们可以将其存储在注册表中。`Docker push`阶段非常简单。只需在 Jenkinsfile 中添加以下代码即可：

```
stage("Docker push") {
     steps {
          sh "docker push leszko/calculator"
     }
}
```

如果 Docker 注册表受到访问限制，那么首先我们需要使用`docker login`命令登录。不用说，凭据必须得到很好的保护，例如，使用专用凭据存储，如官方 Docker 页面上所述：[`docs.docker.com/engine/reference/commandline/login/#credentials-store`](https://docs.docker.com/engine/reference/commandline/login/#credentials-store)。

和往常一样，将更改推送到 GitHub 存储库会触发 Jenkins 开始构建，过一段时间后，我们应该会看到镜像自动存储在注册表中。

# 验收测试阶段

要执行验收测试，首先需要将应用程序部署到暂存环境，然后针对其运行验收测试套件。

# 向流水线添加一个暂存部署

让我们添加一个阶段来运行`calculator`容器：

```
stage("Deploy to staging") {
     steps {
          sh "docker run -d --rm -p 8765:8080 --name calculator leszko/calculator"
     }
}
```

运行此阶段后，`calculator`容器将作为守护程序运行，将其端口发布为`8765`，并在停止时自动删除。

# 向流水线添加一个验收测试

验收测试通常需要运行一个专门的黑盒测试套件，检查系统的行为。我们将在“编写验收测试”部分进行介绍。目前，为了简单起见，让我们通过使用`curl`工具调用 Web 服务端点并使用`test`命令检查结果来执行验收测试。

在项目的根目录中，让我们创建`acceptance_test.sh`文件：

```
#!/bin/bash
test $(curl localhost:8765/sum?a=1\&b=2) -eq 3
```

我们使用参数`a=1`和`b=2`调用`sum`端点，并期望收到`3`的响应。

然后，`Acceptance test`阶段可以如下所示：

```
stage("Acceptance test") {
     steps {
          sleep 60
          sh "./acceptance_test.sh"
     }
}
```

由于`docker run -d`命令是异步的，我们需要使用`sleep`操作来确保服务已经在运行。

没有好的方法来检查服务是否已经在运行。睡眠的替代方法可能是一个脚本，每秒检查服务是否已经启动。

# 添加一个清理阶段环境

作为验收测试的最后一步，我们可以添加分段环境清理。这样做的最佳位置是在`post`部分，以确保即使失败也会执行：

```
post {
     always {
          sh "docker stop calculator"
     }
}
```

这个声明确保`calculator`容器不再在 Docker 主机上运行。

# Docker Compose

没有依赖关系的生活是轻松的。然而，在现实生活中，几乎每个应用程序都链接到数据库、缓存、消息系统或另一个应用程序。在（微）服务架构的情况下，每个服务都需要一堆其他服务来完成其工作。单片架构并没有消除这个问题，一个应用程序通常至少有一些依赖，至少是数据库。

想象一位新人加入你的开发团队；设置整个开发环境并运行带有所有依赖项的应用程序需要多长时间？

当涉及到自动化验收测试时，依赖问题不再仅仅是便利的问题，而是变成了必要性。虽然在单元测试期间，我们可以模拟依赖关系，但验收测试套件需要一个完整的环境。我们如何快速设置并以可重复的方式进行？幸运的是，Docker Compose 是一个可以帮助的工具。

# 什么是 Docker Compose？

Docker Compose 是一个用于定义、运行和管理多容器 Docker 应用程序的工具。服务在配置文件（YAML 格式）中定义，并可以使用单个命令一起创建和运行。

Docker Compose 使用标准的 Docker 机制来编排容器，并提供了一种方便的方式来指定整个环境。

Docker Compose 具有许多功能，最有趣的是：

+   构建一组服务

+   一起启动一组服务

+   管理单个服务的状态

+   在运行之间保留卷数据

+   扩展服务的规模

+   显示单个服务的日志

+   在运行之间缓存配置和重新创建更改的容器

有关 Docker Compose 及其功能的详细描述，请参阅官方页面：[`docs.docker.com/compose/`](https://docs.docker.com/compose/)。

我们从安装过程开始介绍 Docker Compose 工具，然后介绍 docker-compose.yml 配置文件和`docker-compose`命令，最后介绍构建和扩展功能。

# 安装 Docker Compose

安装 Docker Compose 的最简单方法是使用 pip 软件包管理器：

您可以在[`pip.pypa.io/en/stable/installing/`](https://pip.pypa.io/en/stable/installing/)找到 pip 工具的安装指南，或者在 Ubuntu 上使用`sudo apt-get install python-pip`。

```
$ pip install docker-compose
```

要检查 Docker Compose 是否已安装，我们可以运行：

```
$ docker-compose --version
```

所有操作系统的安装指南都可以在[`docs.docker.com/compose/install/`](https://docs.docker.com/compose/install/)找到。

# 定义 docker-compose.yml

`docker-compose.yml`文件用于定义容器的配置、它们之间的关系和运行时属性。

换句话说，当 Dockerfile 指定如何创建单个 Docker 镜像时，`docker-compose.yml`指定了如何在 Docker 镜像之外设置整个环境。

`docker-compose.yml`文件格式有三个版本。在本书中，我们使用的是最新和推荐的版本 3。更多信息请阅读：[`docs.docker.com/compose/compose-file/compose-versioning/`](https://docs.docker.com/compose/compose-file/compose-versioning/)。

`docker-compose.yml`文件具有许多功能，所有这些功能都可以在官方页面找到：[`docs.docker.com/compose/compose-file/`](https://docs.docker.com/compose/compose-file/)。我们将在持续交付过程的上下文中介绍最重要的功能。

让我们从一个例子开始，假设我们的计算器项目使用 Redis 服务器进行缓存。在这种情况下，我们需要一个包含两个容器`calculator`和`redis`的环境。在一个新目录中，让我们创建`docker-compose.yml`文件。

```
version: "3"
services:
     calculator:
          image: calculator:latest
          ports:
               - 8080
     redis:
          image: redis:latest
```

环境配置如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/dc2fb242-79fe-404e-bce6-e057c0f11a62.png)

让我们来看看这两个容器的定义：

+   **redis**：来自官方 Docker Hub 最新版本的`redis`镜像的容器。

+   **calculator**：来自本地构建的`calculator`镜像的最新版本的容器。它将`8080`端口发布到 Docker 主机（这是`docker`命令的`-p`选项的替代）。该容器链接到`redis`容器，这意味着它们共享相同的网络，`redis` IP 地址在`calculator`容器内部的`redis`主机名下可见。

如果我们希望通过不同的主机名来访问服务（例如，通过 redis-cache 而不是 redis），那么我们可以使用链接关键字创建别名。

# 使用 docker-compose 命令

`docker-compose`命令读取定义文件并创建环境：

```
$ docker-compose up -d
```

该命令在后台启动了两个容器，`calculator`和`redis`（使用`-d`选项）。我们可以检查容器是否在运行：

```
$ docker-compose ps
 Name                   Command            State          Ports 
---------------------------------------------------------------------------
project_calculator_1   java -jar app.jar    Up     0.0.0.0:8080->8080/tcp
project_redis_1        docker-entrypoint.sh redis ... Up 6379/tcp
```

容器名称以项目名称`project`为前缀，该名称取自放置`docker-compose.yml`文件的目录的名称。我们可以使用`-p <project_name>`选项手动指定项目名称。由于 Docker Compose 是在 Docker 之上运行的，我们也可以使用`docker`命令来确认容器是否在运行：

```
$ docker ps
CONTAINER ID  IMAGE             COMMAND                 PORTS
360518e46bd3  calculator:latest "java -jar app.jar"     0.0.0.0:8080->8080/tcp 
2268b9f1e14b  redis:latest      "docker-entrypoint..."  6379/tcp
```

完成后，我们可以拆除环境：

```
$ docker-compose down
```

这个例子非常简单，但这个工具本身非常强大。通过简短的配置和一堆命令，我们可以控制所有服务的编排。在我们将 Docker Compose 用于验收测试之前，让我们看看另外两个 Docker Compose 的特性：构建镜像和扩展容器。

# 构建镜像

在前面的例子中，我们首先使用`docker build`命令构建了`calculator`镜像，然后可以在 docker-compose.yml 中指定它。还有另一种方法让 Docker Compose 构建镜像。在这种情况下，我们需要在配置中指定`build`属性而不是`image`。

让我们把`docker-compose.yml`文件放在计算器项目的目录中。当 Dockerfile 和 Docker Compose 配置在同一个目录中时，前者可以如下所示：

```
version: "3"
services:
     calculator:
          build: .
          ports:
               - 8080
     redis:
          image: redis:latest
```

`docker-compose build`命令构建镜像。我们还可以要求 Docker Compose 在运行容器之前构建镜像，使用`docker-compose --build up`命令。

# 扩展服务

Docker Compose 提供了自动创建多个相同容器实例的功能。我们可以在`docker-compose.yml`中指定`replicas: <number>`参数，也可以使用`docker-compose scale`命令。

例如，让我们再次运行环境并复制`calculator`容器：

```
$ docker-compose up -d
$ docker-compose scale calculator=5
```

我们可以检查正在运行的容器：

```
$ docker-compose ps
 Name                     Command             State Ports 
---------------------------------------------------------------------------
calculator_calculator_1   java -jar app.jar   Up   0.0.0.0:32777->8080/tcp
calculator_calculator_2   java -jar app.jar   Up   0.0.0.0:32778->8080/tcp
calculator_calculator_3   java -jar app.jar   Up   0.0.0.0:32779->8080/tcp
calculator_calculator_4   java -jar app.jar   Up   0.0.0.0:32781->8080/tcp
calculator_calculator_5   java -jar app.jar   Up   0.0.0.0:32780->8080/tcp
calculator_redis_1        docker-entrypoint.sh redis ... Up 6379/tcp
```

五个`calculator`容器完全相同，除了容器 ID、容器名称和发布端口号。

它们都使用相同的 Redis 容器实例。现在我们可以停止并删除所有容器：

```
$ docker-compose down
```

扩展容器是 Docker Compose 最令人印象深刻的功能之一。通过一个命令，我们可以扩展克隆实例的数量。Docker Compose 负责清理不再使用的容器。

我们已经看到了 Docker Compose 工具最有趣的功能。

在接下来的部分，我们将重点介绍如何在自动验收测试的情境中使用它。

# 使用 Docker Compose 进行验收测试

Docker Compose 非常适合验收测试流程，因为它可以通过一个命令设置整个环境。更重要的是，在测试完成后，也可以通过一个命令清理环境。如果我们决定在生产环境中使用 Docker Compose，那么另一个好处是验收测试使用的配置、工具和命令与发布的应用程序完全相同。

要了解如何在 Jenkins 验收测试阶段应用 Docker Compose，让我们继续计算器项目示例，并将基于 Redis 的缓存添加到应用程序中。然后，我们将看到两种不同的方法来运行验收测试：先 Jenkins 方法和先 Docker 方法。

# 使用多容器环境

Docker Compose 提供了容器之间的依赖关系；换句话说，它将一个容器链接到另一个容器。从技术上讲，这意味着容器共享相同的网络，并且一个容器可以从另一个容器中看到。为了继续我们的示例，我们需要在代码中添加这个依赖关系，我们将在几个步骤中完成。

# 向 Gradle 添加 Redis 客户端库

在`build.gradle`文件中，在`dependencies`部分添加以下配置：

```
compile "org.springframework.data:spring-data-redis:1.8.0.RELEASE"
compile "redis.clients:jedis:2.9.0"
```

它添加了负责与 Redis 通信的 Java 库。

# 添加 Redis 缓存配置

添加一个新文件`src/main/java/com/leszko/calculator/CacheConfig.java`：

```
package com.leszko.calculator;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

/** Cache config. */
@Configuration
@EnableCaching
public class CacheConfig extends CachingConfigurerSupport {
    private static final String REDIS_ADDRESS = "redis";

    @Bean
    public JedisConnectionFactory redisConnectionFactory() {
        JedisConnectionFactory redisConnectionFactory = new
          JedisConnectionFactory();
        redisConnectionFactory.setHostName(REDIS_ADDRESS);
        redisConnectionFactory.setPort(6379);
        return redisConnectionFactory;
    }

    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory cf) {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<String, 
          String>();
        redisTemplate.setConnectionFactory(cf);
        return redisTemplate;
    }

    @Bean
    public CacheManager cacheManager(RedisTemplate redisTemplate) {
        return new RedisCacheManager(redisTemplate);
    }
}
```

这是一个标准的 Spring 缓存配置。请注意，对于 Redis 服务器地址，我们使用`redis`主机名，这是由于 Docker Compose 链接机制自动可用。

# 添加 Spring Boot 缓存

当缓存配置好后，我们最终可以将缓存添加到我们的网络服务中。为了做到这一点，我们需要更改`src/main/java/com/leszko/calculator/Calculator.java`文件如下：

```
package com.leszko.calculator;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

/** Calculator logic */
@Service
public class Calculator {
    @Cacheable("sum")
    public int sum(int a, int b) {
        return a + b;
    }
}
```

从现在开始，求和计算将被缓存在 Redis 中，当我们调用`calculator`网络服务的`/sum`端点时，它将首先尝试从缓存中检索结果。

# 检查缓存环境

假设我们的 docker-compose.yml 在计算器项目的目录中，我们现在可以启动容器了：

```
$ ./gradlew clean build
$ docker-compose up --build -d
```

我们可以检查计算器服务发布的端口：

```
$ docker-compose port calculator 8080
0.0.0.0:32783
```

如果我们在`localhost:32783/sum?a=1&b=2`上打开浏览器，计算器服务应该回复`3`，同时访问`redis`服务并将缓存值存储在那里。为了查看缓存值是否真的存储在 Redis 中，我们可以访问`redis`容器并查看 Redis 数据库内部：

```
$ docker-compose exec redis redis-cli

127.0.0.1:6379> keys *
1) "\xac\xed\x00\x05sr\x00/org.springframework.cache.interceptor.SimpleKeyL\nW\x03km\x93\xd8\x02\x00\x02I\x00\bhashCode\x00\x06paramst\x00\x13[Ljava/lang/Object;xp\x00\x00\x03\xe2ur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s)l\x02\x00\x00xp\x00\x00\x00\x02sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01sq\x00~\x00\x05\x00\x00\x00\x02"
2) "sum~keys"
```

`docker-compose exec`命令在`redis`容器内执行了`redis-cli`（Redis 客户端以浏览其数据库内容）命令。然后，我们可以运行`keys *`来打印 Redis 中存储的所有内容。

您可以通过计算器应用程序进行更多操作，并使用不同的值在浏览器中打开，以查看 Redis 服务内容增加。之后，重要的是使用`docker-compose down`命令拆除环境。

在接下来的章节中，我们将看到多容器项目的两种验收测试方法。显然，在 Jenkins 上采取任何行动之前，我们需要提交并推送所有更改的文件（包括`docker-compose.yml`）到 GitHub。

请注意，对于进一步的步骤，Jenkins 执行器上必须安装 Docker Compose。

# 方法 1 - 首先进行 Jenkins 验收测试

第一种方法是以与单容器应用程序相同的方式执行验收测试。唯一的区别是现在我们有两个容器正在运行，如下图所示：

![从用户角度来看，`redis`容器是不可见的，因此单容器和多容器验收测试之间唯一的区别是我们使用`docker-compose up`命令而不是`docker run`。其他 Docker 命令也可以用它们的 Docker Compose 等效命令替换：`docker-compose build` 替换 `docker build`，`docker-compose push` 替换 `docker push`。然而，如果我们只构建一个镜像，那么保留 Docker 命令也是可以的。# 改变暂存部署阶段让我们改变 `部署到暂存` 阶段来使用 Docker Compose：```stage("Deploy to staging") {    steps {        sh "docker-compose up -d"    }}```我们必须以完全相同的方式改变清理：```post {    always {        sh "docker-compose down"    }}```# 改变验收测试阶段为了使用 `docker-compose scale`，我们没有指定我们的 web 服务将发布在哪个端口号下。如果我们这样做了，那么扩展过程将失败，因为所有克隆将尝试在相同的端口号下发布。相反，我们让 Docker 选择端口。因此，我们需要改变 `acceptance_test.sh` 脚本，首先找出端口号是多少，然后使用正确的端口号运行 `curl`。```#!/bin/bashCALCULATOR_PORT=$(docker-compose port calculator 8080 | cut -d: -f2)test $(curl localhost:$CALCULATOR_PORT/sum?a=1\&b=2) -eq 3```让我们找出我们是如何找到端口号的：1.  `docker-compose port calculator 8080` 命令检查 web 服务发布在哪个 IP 和端口地址下（例如返回 `127.0.0.1:57648`）。1.  `cut -d: -f2` 选择只有端口（例如，对于 `127.0.0.1:57648`，它返回 `57648`）。我们可以将更改推送到 GitHub 并观察 Jenkins 的结果。这个想法和单容器应用程序的想法是一样的，设置环境，运行验收测试套件，然后拆除环境。尽管这种验收测试方法很好并且运行良好，让我们看看另一种解决方案。# 方法 2 – 先 Docker 验收测试在 Docker-first 方法中，我们创建了一个额外的 `test` 容器，它从 Docker 主机内部执行测试，如下图所示：![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/78c8fd68-b33a-41f8-9d5a-a8ae5998f5aa.png)

这种方法在检索端口号方面简化了验收测试脚本，并且可以在没有 Jenkins 的情况下轻松运行。它也更符合 Docker 的风格。

缺点是我们需要为测试目的创建一个单独的 Dockerfile 和 Docker Compose 配置。

# 为验收测试创建一个 Dockerfile

我们将首先为验收测试创建一个单独的 Dockerfile。让我们在计算器项目中创建一个新目录 `acceptance` 和一个 Dockerfile。

```
FROM ubuntu:trusty
RUN apt-get update && \
    apt-get install -yq curl
COPY test.sh .
CMD ["bash", "test.sh"]
```

它创建一个运行验收测试的镜像。

# 为验收测试创建一个 docker-compose.yml

在同一个目录下，让我们创建 `docker-compose-acceptance.yml` 来提供测试编排：

```
version: "3"
services:
    test:
        build: ./acceptance
```

它创建一个新的容器，链接到被测试的容器：`calculator`。而且，内部始终是 8080，这就消除了端口查找的麻烦部分。

# 创建验收测试脚本

最后缺失的部分是测试脚本。在同一目录下，让我们创建代表验收测试的`test.sh`文件：

```
#!/bin/bash
sleep 60
test $(curl calculator:8080/sum?a=1\&b=2) -eq 3
```

它与之前的验收测试脚本非常相似，唯一的区别是我们可以通过`calculator`主机名来访问计算器服务，端口号始终是`8080`。此外，在这种情况下，我们在脚本内等待，而不是在 Jenkinsfile 中等待。

# 运行验收测试

我们可以使用根项目目录下的 Docker Compose 命令在本地运行测试：

```
$ docker-compose -f docker-compose.yml -f acceptance/docker-compose-acceptance.yml -p acceptance up -d --build
```

该命令使用两个 Docker Compose 配置来运行`acceptance`项目。其中一个启动的容器应该被称为`acceptance_test_1`，并对其结果感兴趣。我们可以使用以下命令检查其日志：

```
$ docker logs acceptance_test_1
 %   Total %   Received % Xferd Average Speed Time 
 100 1     100 1        0 0     1       0     0:00:01
```

日志显示`curl`命令已成功调用。如果我们想要检查测试是成功还是失败，可以检查容器的退出代码：

```
$ docker wait acceptance_test_1
0
```

`0`退出代码表示测试成功。除了`0`之外的任何代码都意味着测试失败。测试完成后，我们应该像往常一样清理环境：

```
$ docker-compose -f docker-compose.yml -f acceptance/docker-compose-acceptance.yml -p acceptance down
```

# 更改验收测试阶段

最后一步，我们可以将验收测试执行添加到流水线中。让我们用一个新的**验收测试**阶段替换 Jenkinsfile 中的最后三个阶段：

```
stage("Acceptance test") {
    steps {
        sh "docker-compose -f docker-compose.yml 
                   -f acceptance/docker-compose-acceptance.yml build test"
        sh "docker-compose -f docker-compose.yml 
                   -f acceptance/docker-compose-acceptance.yml 
                   -p acceptance up -d"
        sh 'test $(docker wait acceptance_test_1) -eq 0'
    }
}
```

这一次，我们首先构建`test`服务。不需要构建`calculator`镜像；它已经在之前的阶段完成了。最后，我们应该清理环境：

```
post {
    always {
        sh "docker-compose -f docker-compose.yml 
                   -f acceptance/docker-compose-acceptance.yml 
                   -p acceptance down"
    }
}
```

在 Jenkinsfile 中添加了这个之后，我们就完成了第二种方法。我们可以通过将所有更改推送到 GitHub 来测试这一点。

# 比较方法 1 和方法 2

总之，让我们比较两种解决方案。第一种方法是从用户角度进行真正的黑盒测试，Jenkins 扮演用户的角色。优点是它非常接近于在生产中将要做的事情；最后，我们将通过其 Docker 主机访问容器。第二种方法是从另一个容器的内部测试应用程序。这种解决方案在某种程度上更加优雅，可以以简单的方式在本地运行；但是，它需要创建更多的文件，并且不像在生产中将来要做的那样通过其 Docker 主机调用应用程序。

在下一节中，我们将远离 Docker 和 Jenkins，更仔细地研究编写验收测试的过程。

# 编写验收测试

到目前为止，我们使用`curl`命令执行一系列验收测试。这显然是一个相当简化的过程。从技术上讲，如果我们编写一个 REST Web 服务，那么我们可以将所有黑盒测试写成一个大脚本，其中包含多个`curl`调用。然而，这种解决方案非常难以阅读、理解和维护。而且，这个脚本对非技术的业务相关用户来说完全无法理解。如何解决这个问题，创建具有良好结构、可读性强的测试，并满足其基本目标：自动检查系统是否符合预期？我将在本节中回答这个问题。

# 编写面向用户的测试

验收测试是为用户编写的，应该让用户能够理解。这就是为什么编写它们的方法取决于客户是谁。

例如，想象一个纯粹的技术人员。如果你编写了一个优化数据库存储的 Web 服务，而你的系统只被其他系统使用，并且只被其他开发人员读取，那么你的测试可以以与单元测试相同的方式表达。通常情况下，测试是好的，如果开发人员和用户都能理解。

在现实生活中，大多数软件都是为了提供特定的业务价值而编写的，而这个业务价值是由非开发人员定义的。因此，我们需要一种共同的语言来合作。一方面，业务了解需要什么，但不知道如何做；另一方面，开发团队知道如何做，但不知道需要什么。幸运的是，有许多框架可以帮助连接这两个世界，例如 Cucumber、FitNesse、JBehave、Capybara 等等。它们彼此之间有所不同，每一个都可能成为一本单独的书的主题；然而，编写验收测试的一般思想是相同的，并且可以用以下图表来表示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/8b572c5e-b2b1-4f86-90b2-a2d60f6f42fc.png)

**验收标准**由用户（或其代表产品所有者）与开发人员的帮助下编写。它们通常以以下场景的形式编写：

```
Given I have two numbers: 1 and 2
When the calculator sums them
Then I receive 3 as a result
```

开发人员编写称为**fixtures**或**步骤定义**的测试实现，将人性化的 DSL 规范与编程语言集成在一起。因此，我们有了一个可以很好集成到持续交付管道中的自动化测试。

不用说，编写验收测试是一个持续的敏捷过程，而不是瀑布式过程。这需要开发人员和业务方的不断协作，以改进和维护测试规范。

对于具有用户界面的应用程序，直接通过界面执行验收测试可能很诱人（例如，通过记录 Selenium 脚本）；然而，如果没有正确执行，这种方法可能导致测试速度慢且与界面层紧密耦合的问题。

让我们看看实践中编写验收测试的样子，以及如何将它们绑定到持续交付管道中。

# 使用验收测试框架

让我们使用黄瓜框架为计算器项目创建一个验收测试。如前所述，我们将分三步完成这个过程：

+   创建验收标准

+   创建步骤定义

+   运行自动化验收测试

# 创建验收标准

让我们将业务规范放在`src/test/resources/feature/calculator.feature`中：

```
Feature: Calculator
    Scenario: Sum two numbers
        Given I have two numbers: 1 and 2
        When the calculator sums them
        Then I receive 3 as a result
```

这个文件应该由用户在开发人员的帮助下创建。请注意，它是以非技术人员可以理解的方式编写的。

# 创建步骤定义

下一步是创建 Java 绑定，以便特性规范可以被执行。为了做到这一点，我们创建一个新文件`src/test/java/acceptance/StepDefinitions.java`：

```
package acceptance;

import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.assertEquals;

/** Steps definitions for calculator.feature */
public class StepDefinitions {
    private String server = System.getProperty("calculator.url");

    private RestTemplate restTemplate = new RestTemplate();

    private String a;
    private String b;
    private String result;

    @Given("^I have two numbers: (.*) and (.*)$")
    public void i_have_two_numbers(String a, String b) throws Throwable {
        this.a = a;
        this.b = b;
    }

    @When("^the calculator sums them$")
    public void the_calculator_sums_them() throws Throwable {
        String url = String.format("%s/sum?a=%s&b=%s", server, a, b);
        result = restTemplate.getForObject(url, String.class);
    }

    @Then("^I receive (.*) as a result$")
    public void i_receive_as_a_result(String expectedResult) throws Throwable {
        assertEquals(expectedResult, result);
    }
}
```

特性规范文件中的每一行（`Given`，`When`和`Then`）都与 Java 代码中相应的方法匹配。通配符`(.*)`作为参数传递。请注意，服务器地址作为 Java 属性`calculator.url`传递。该方法执行以下操作：

+   `i_have_two_numbers`：将参数保存为字段

+   `the_calculator_sums_them`：调用远程计算器服务并将结果存储在字段中

+   `i_receive_as_a_result`：断言结果是否符合预期

# 运行自动化验收测试

要运行自动化测试，我们需要进行一些配置：

1.  **添加 Java 黄瓜库**：在`build.gradle`文件中，将以下代码添加到`dependencies`部分：

```
        testCompile("info.cukes:cucumber-java:1.2.4")
        testCompile("info.cukes:cucumber-junit:1.2.4")
```

1.  **添加 Gradle 目标**：在同一文件中，添加以下代码：

```
       task acceptanceTest(type: Test) {
            include '**/acceptance/**'
            systemProperties System.getProperties()
       }

       test {
            exclude '**/acceptance/**'
       }
```

这将测试分为单元测试（使用`./gradlew test`运行）和验收测试（使用`./gradlew acceptanceTest`运行）。

1.  **添加 JUnit 运行器**：添加一个新文件`src/test/java/acceptance/AcceptanceTest.java`：

```
        package acceptance;

        import cucumber.api.CucumberOptions;
        import cucumber.api.junit.Cucumber;
        import org.junit.runner.RunWith;

        /** Acceptance Test */
        @RunWith(Cucumber.class)
        @CucumberOptions(features = "classpath:feature")
        public class AcceptanceTest { }
```

这是验收测试套件的入口点。

在进行此配置之后，如果服务器正在本地主机上运行，我们可以通过执行以下代码来测试它：

```
$ ./gradlew acceptanceTest -Dcalculator.url=http://localhost:8080
```

显然，我们可以将此命令添加到我们的`acceptance_test.sh`中，而不是`curl`命令。这将使 Cucumber 验收测试在 Jenkins 流水线中运行。

# 验收测试驱动开发

与持续交付过程的大多数方面一样，验收测试更多地关乎人而不是技术。测试质量当然取决于用户和开发人员的参与，但也取决于测试创建的时间，这可能不太直观。

最后一个问题是，在软件开发生命周期的哪个阶段应准备验收测试？或者换句话说，我们应该在编写代码之前还是之后创建验收测试？

从技术上讲，结果是一样的；代码既有单元测试，也有验收测试覆盖。然而，考虑先编写测试的想法是很诱人的。TDD（测试驱动开发）的理念可以很好地适用于验收测试。如果在编写代码之前编写单元测试，结果代码会更清洁、结构更好。类似地，如果在系统功能之前编写验收测试，结果功能将更符合客户的需求。这个过程，通常称为验收测试驱动开发，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/432d2a13-c759-4399-b9c4-452689af60fe.png)

用户与开发人员以人性化的 DSL 格式编写验收标准规范。开发人员编写固定装置，测试失败。然后，使用 TDD 方法进行内部功能开发。功能完成后，验收测试应该通过，这表明功能已完成。

一个非常好的做法是将 Cucumber 功能规范附加到问题跟踪工具（例如 JIRA）中的请求票据上，以便功能总是与其验收测试一起请求。一些开发团队采取了更激进的方法，拒绝在没有准备验收测试的情况下开始开发过程。毕竟，这是有道理的，*你怎么能开发客户无法测试的东西呢？*

# 练习

在本章中，我们涵盖了很多新材料，为了更好地理解，我们建议做练习，并创建自己的验收测试项目：

1.  创建一个基于 Ruby 的 Web 服务`book-library`来存储书籍：

验收标准以以下 Cucumber 功能的形式交付：

```
Scenario: Store book in the library
Given: Book "The Lord of the Rings" by "J.R.R. Tolkien" with ISBN number  
"0395974682"
When: I store the book in library
Then: I am able to retrieve the book by the ISBN number
```

+   +   为 Cucumber 测试编写步骤定义

+   编写 Web 服务（最简单的方法是使用 Sinatra 框架：[`www.sinatrarb.com/`](http://www.sinatrarb.com/)，但您也可以使用 Ruby on Rails）。

+   书应具有以下属性：名称，作者和 ISBN。

+   Web 服务应具有以下端点：

+   POST`/books/`以添加书籍

+   GET`books/<isbn>`以检索书籍

+   数据可以存储在内存中。

+   最后，检查验收测试是否通过。

1.  将“book-library”添加为 Docker 注册表中的 Docker 图像：

1.  +   在 Docker Hub 上创建一个帐户。

+   为应用程序创建 Dockerfile。

+   构建 Docker 图像并根据命名约定对其进行标记。

+   将图像推送到 Docker Hub。

1.  创建 Jenkins 流水线以构建 Docker 图像，将其推送到 Docker 注册表并执行验收测试：

+   +   创建一个“Docker 构建”阶段。

+   创建“Docker 登录”和“Docker 推送”阶段。

+   创建一个执行验收测试的“测试”容器，并使用 Docker Compose 执行测试。

+   在流水线中添加“验收测试”阶段。

+   运行流水线并观察结果。

# 摘要

在本章中，您学会了如何构建完整和功能齐全的验收测试阶段，这是持续交付过程的重要组成部分。本章的关键要点：

+   接受测试可能很难创建，因为它们结合了技术挑战（应用程序依赖关系，环境设置）和个人挑战（开发人员与业务的合作）。

+   验收测试框架提供了一种以人类友好的语言编写测试的方法，使非技术人员能够理解。

+   Docker 注册表是 Docker 镜像的工件存储库。

+   Docker 注册表与持续交付流程非常匹配，因为它提供了一种在各个阶段和环境中使用完全相同的 Docker 镜像的方式。

+   Docker Compose 编排一组相互交互的 Docker 容器。它还可以构建镜像和扩展容器。

+   Docker Compose 可以帮助在运行一系列验收测试之前设置完整的环境。

+   验收测试可以编写为 Docker 镜像，Docker Compose 可以运行完整的环境以及测试，并提供结果。

在下一章中，我们将介绍完成持续交付流水线所需的缺失阶段。
